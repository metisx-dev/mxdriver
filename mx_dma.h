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
#include <linux/poll.h>

#include <asm/current.h>
#include <asm/cacheflush.h>

#define MXDMA_NODE_NAME		"mx_dma"

#define MAGIC_CHAR		0xCCCCCCCCUL
#define MAGIC_DEVICE		0xDDDDDDDDUL

#define MXDMA_BAR_INDEX	2

#define SINGLE_DMA_SIZE		PAGE_SIZE
#define NUM_OF_DESC_PER_LIST	(SINGLE_DMA_SIZE / sizeof(uint64_t))

enum {
	MX_CDEV_DATA = 0,
	MX_CDEV_CONTEXT,
	MX_CDEV_SQ,
	MX_CDEV_CQ,
	MX_CDEV_DATA_NOWAIT,
	MX_CDEV_CONTEXT_NOWAIT,
	MX_CDEV_SQ_NOWAIT,
	MX_CDEV_CQ_NOWAIT,
	MX_CDEV_EVENT,
	NUM_OF_MX_CDEV,
};

enum {
	IO_OPCODE_DATA_READ = 0,
	IO_OPCODE_DATA_WRITE,
	IO_OPCODE_CONTEXT_READ,
	IO_OPCODE_CONTEXT_WRITE,
	IO_OPCODE_SQ_READ,
	IO_OPCODE_SQ_WRITE,
	IO_OPCODE_CQ_READ,
	IO_OPCODE_CQ_WRITE,
};

enum {
	ADMIN_OPCODE_CREATE_IO_SQ = 0,
	ADMIN_OPCODE_DELETE_IO_SQ,
	ADMIN_OPCODE_CREATE_IO_CQ,
	ADMIN_OPCODE_DELETE_IO_CQ,
};

enum {
	IO_FLAGS_NOWAIT = 0,
	IO_FLAGS_PRP,
};

static const char * const node_name[] = {
	MXDMA_NODE_NAME "%d_data",
	MXDMA_NODE_NAME "%d_context",
	MXDMA_NODE_NAME "%d_sq",
	MXDMA_NODE_NAME "%d_cq",
	MXDMA_NODE_NAME "%d_data_nowait",
	MXDMA_NODE_NAME "%d_context_nowait",
	MXDMA_NODE_NAME "%d_sq_nowait",
	MXDMA_NODE_NAME "%d_cq_nowait",
	MXDMA_NODE_NAME "%d_event",
};

typedef struct
{
	uint16_t depth;
	uint16_t cq_id;
	uint16_t sq_id;
	uint16_t rsvd1;
} io_queue_info_t;

struct mx_command {
	uint8_t opcode;
	uint8_t flags;
	uint16_t command_id;
	uint32_t rsvd1;
	uint64_t rsvd2;
	uint64_t rsvd3;
	union
	{
		uint64_t host_addr;
		uint64_t prp_entry1;
		uint64_t doorbell_value;
	};
	uint64_t prp_entry2;
	union {
		uint64_t device_addr;
		io_queue_info_t io_queue_info;
	};
	uint64_t size;
	uint64_t rsvd4;
};

struct mx_completion
{
	uint64_t result;
	uint16_t sq_head;
	uint16_t sq_id;
	uint16_t command_id;
	uint16_t status;
};

struct mx_transfer {
	void __user *user_addr;
	size_t size;
	uint64_t device_addr;
	enum dma_data_direction dir;
	bool nowait;

	struct mx_command command;
	struct list_head entry;
	struct completion done;
	uint64_t result;

	/* Used for data transfer */
	struct sg_table sgt;
	struct page **pages;
	int pages_nr;
	int desc_list_cnt;
	void **desc_list_va;
	dma_addr_t *desc_list_ba;
};

struct mx_event {
	atomic_t count;
	wait_queue_head_t wq;
};

struct mx_queue {
	uint16_t qid;
	struct mx_command *sqes;
	struct mx_completion *cqes;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;

	uint32_t depth;
	uint16_t last_sq_tail;
	uint16_t sq_tail;
	uint16_t sq_head;
	uint16_t cq_head;
	uint16_t cq_phase;
	void __iomem *db;

	struct list_head sq_list;
	spinlock_t sq_lock;
};

struct mx_char_dev {
	unsigned long magic;
	struct mx_pci_dev *mx_pdev;
	struct cdev cdev;
	dev_t cdev_no;

	bool nowait;
	bool enabled;
};

struct mx_pci_dev {
	unsigned long magic;
	int id;
	dev_t dev_no;

	struct pci_dev *pdev;
	bool enabled;

	void __iomem *bar;
	uint32_t __iomem *dbs;
	uint32_t bar_mapped_size;

	struct mx_event event;
	struct mx_queue admin_queue;
	struct mx_queue io_queue;

	struct task_struct *comm_thread;
	struct task_struct *cmpl_thread;

	int num_of_cdev;
	struct mx_char_dev mx_cdev[NUM_OF_MX_CDEV];

	struct dma_pool *page_pool;
};

extern struct file_operations *mxdma_fops_array[];

int mxdma_driver_probe(struct pci_dev *pdev, const struct pci_device_id *id, int cxl_memdev_id);
void mxdma_driver_remove(struct pci_dev *pdev);

int transfer_id_alloc(void *ptr);
void transfer_id_free(unsigned long id);
void *find_transfer_by_id(unsigned long id);

ssize_t read_data_from_device_parallel(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_data_to_device_parallel(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode, bool nowait);

ssize_t read_data_from_device(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_data_to_device(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode, bool nowait);

ssize_t read_ctrl_from_device(struct mx_pci_dev *mx_pdev, char __user *buf, size_t size, loff_t *fpos, int opcode);
ssize_t write_ctrl_to_device(struct mx_pci_dev *mx_pdev, const char __user *buf, size_t size, loff_t *fpos, int opcode, bool nowait);

void *get_sqe_ptr(struct mx_queue *queue);
void *get_cqe_ptr(struct mx_queue *queue);
void update_sq_doorbell(struct mx_queue *queue);
void update_cq_doorbell(struct mx_queue *queue);
void ring_sq_doorbell(struct mx_queue *queue);
void ring_cq_doorbell(struct mx_queue *queue);

int mx_command_handler(void *arg);
int mx_completion_handler(void *arg);

#ifdef CONFIG_DEBUG_DMA
#define pr_debug_dma(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define pr_debug_dma(fmt, ...) do { } while (0)
#endif

