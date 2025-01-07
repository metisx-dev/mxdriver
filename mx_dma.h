/* SPDX-License-Identifier: <SPDX License Expression> */

#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/kthread.h>

#include <asm/current.h>
#include <asm/cacheflush.h>

#define MXDMA_NODE_NAME		"mx_dma"

#define MAGIC_COMMAND		0x1234
#define MAGIC_ENGINE	        0xEEEEEEEEUL
#define MAGIC_CHAR		0xCCCCCCCCUL
#define MAGIC_DEVICE		0xDDDDDDDDUL

#define MXDMA_BAR_COUNT		8
#define HMBOX_BAR_INDEX		2

#define HMBOX_RQ_OFFSET		0x1000
#define HIO_HOST_Q_OFFSET	48
#define HMBOX_UPDATE_BITMASK	(1ull << 18)
#define HMBOX_DB_OFFSET		4

#define INVALID_CTX		0xFFFFFFFFFFFFFFFF

#define POWER_OF_2(x)		(BIT(x))

#define SINGLE_DMA_SIZE		(1 << 10) /* 1KB */
#define NUM_OF_DESC_PER_LIST	(SINGLE_DMA_SIZE / sizeof(uint64_t))

#define SQ_POLLING_MSEC		4
#define CQ_POLLING_MSEC		4

enum {
	MXDMA_TYPE_DATA = 0,
	MXDMA_TYPE_CONTEXT,
	MXDMA_TYPE_SQ,
	MXDMA_TYPE_CQ,
	NUM_OF_MXDMA_TYPE,
};

enum {
	MXDMA_OP_DATA_READ = 0,
	MXDMA_OP_DATA_WRITE,
	MXDMA_OP_CONTEXT_READ,
	MXDMA_OP_CONTEXT_WRITE,
	MXDMA_OP_SQ_READ,
	MXDMA_OP_SQ_WRITE,
	MXDMA_OP_CQ_READ,
	MXDMA_OP_CQ_WRITE,
};

enum {
	MXDMA_TRANSFER_START = 0,
	MXDMA_TRANSFER_COMPLETE,
};

enum {
	MXDMA_PAGE_MODE_SINGLE = 0,
	MXDMA_PAGE_MODE_MULTI,
};

static const char * const node_name[] = {
	MXDMA_NODE_NAME "%d_data",
	MXDMA_NODE_NAME "%d_context",
	MXDMA_NODE_NAME "%d_sq",
	MXDMA_NODE_NAME "%d_cq",
};

typedef union {
	struct {
		uint8_t index :7;
		uint8_t phase :1;
	};
	uint8_t full;
} mbox_index_t;

typedef union {
	struct {
		uint64_t mid : 8;
		uint64_t ctx_base : 16;
		uint64_t data_base : 16;
		uint64_t q_size : 4;
		uint64_t data_size : 4;
		uint64_t tail : 8;
		uint64_t head : 8;
	};
	uint64_t u64;
	uint32_t u32[2];
} mbox_context_t;

struct mx_command {
	union {
		struct {
			uint64_t magic : 16;
			uint64_t opcode : 4;
			uint64_t control : 4;
			uint64_t page_mode : 2;
			uint64_t id : 16;
			uint64_t rsvd : 22;
		};
		uint64_t header;
	};
	uint64_t length;
	uint64_t device_addr;
	/*
	 * if page_mode == MXDMA_PAGE_MOODE_SINGLE, host_addr
	 * if page_mode == MXDMA_PAGE_MODE_MULTI, next_desc_list_addr
	 * if db read/write, doorbell_value
	 */
	uint64_t host_addr;
} __packed;

struct mx_transfer {
	void __user *user_addr;
	size_t size;
	uint64_t device_addr;
	enum dma_data_direction dir;

	struct mx_command cmd;
	struct list_head entry;
	struct completion done;

	/* Used for data transfer */
	struct sg_table sgt;
	struct page **pages;
	int pages_nr;
	int desc_list_cnt;
	void **desc_list_va;
	dma_addr_t *desc_list_ba;
};

struct mx_mbox {
	void __iomem *ctx_addr;
	void __iomem *data_addr;
	uint64_t depth;

	struct list_head wait_list;
	struct task_struct *thread;
	spinlock_t lock;
};

struct mx_engine {
	unsigned long magic;
	struct mx_mbox submit;
	struct mx_mbox complete;
};

struct mx_char_dev {
	unsigned long magic;
	struct mx_pci_dev *mx_pdev;
	struct cdev cdev;
	dev_t cdev_no;

	int type;
	bool enabled;
};

struct mx_pci_dev {
	unsigned long magic;
	int id;
	dev_t dev_no;

	struct pci_dev *pdev;
	bool has_regions;
	bool enabled;

	void __iomem *hmbox_bar;
	uint32_t hmbox_size;

	struct mx_engine engine;

	struct mx_char_dev mx_cdev[NUM_OF_MXDMA_TYPE];
};

extern struct file_operations mxdma_fops;

int mxdma_driver_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void mxdma_driver_remove(struct pci_dev *pdev);

int transfer_id_alloc(void *ptr);
void transfer_id_free(unsigned long id);
void *find_transfer_by_id(unsigned long id);

ssize_t read_data_from_device_parallel(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_data_to_device_parallel(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode);

ssize_t read_data_from_device(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_data_to_device(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode);

ssize_t read_ctrl_from_device(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_ctrl_to_device(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode);

int mx_command_submit_handler(void *arg);
int mx_command_complete_handler(void *arg);

#ifdef CONFIG_DEBUG_DMA
#define pr_debug_dma(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define pr_debug_dma(fmt, ...) do { } while (0)
#endif

