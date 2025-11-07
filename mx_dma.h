/* SPDX-License-Identifier: <SPDX License Expression> */

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
#include <linux/swait.h>

#include <asm/current.h>
#include <asm/cacheflush.h>

#define MXDMA_NODE_NAME		"mx_dma"
#define XCENA_PCI_VENDOR_ID	0x20A6

#define MAGIC_COMMAND		0x1234
#define MAGIC_CHAR		0xCCCCCCCCUL
#define MAGIC_DEVICE		0xDDDDDDDDUL

#define MXDMA_BAR_INDEX		2

#define MAX_NUM_OF_MBOX		80
#define HMBOX_UPDATE_BITMASK	(1ull << 18)

#define POLLING_INTERVAL_MSEC	4

enum {
	MX_CDEV_DATA = 0,
	MX_CDEV_DATA_NOWAIT,
	MX_CDEV_CONTEXT,
	MX_CDEV_IOCTL,
	MX_CDEV_EVENT,
	MX_CDEV_BDF,
	NUM_OF_MX_CDEV,
};

static const char * const node_name[] = {
	MXDMA_NODE_NAME "%d_data",
	MXDMA_NODE_NAME "%d_data_nowait",
	MXDMA_NODE_NAME "%d_context",
	MXDMA_NODE_NAME "%d_ioctl",
	MXDMA_NODE_NAME "%d_event",
	MXDMA_NODE_NAME "%d_bdf",
};

enum {
	ADMIN_OPCODE_CREATE_IO_CQ = 0,
	ADMIN_OPCODE_DELETE_IO_CQ,
	ADMIN_OPCODE_CREATE_IO_SQ,
	ADMIN_OPCODE_DELETE_IO_SQ,
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

static const char * const mxdma_op_name[] = {
	"R_DATA(0)",
	"W_DATA(1)",
	"R_CTX(2)",
	"W_CTX(3)",
	"R_SQ(4)",
	"W_SQ(5)",
	"R_CQ(6)",
	"W_CQ(7)",
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
} mbox_context_t;

struct mx_mbox {
	uint64_t r_ctx_addr;
	uint64_t w_ctx_addr;
	uint64_t data_addr;
	mbox_context_t ctx;
	uint32_t depth;
	struct mutex lock;
};

struct mx_transfer {
	uint16_t id;
	void __user *user_addr;
	size_t size;
	uint64_t device_addr;
	enum dma_data_direction dir;

	struct mx_pci_dev *mx_pdev;
	struct work_struct work;

	void *command;
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

struct mx_char_dev {
	unsigned long magic;
	struct mx_pci_dev *mx_pdev;
	struct cdev cdev;
	dev_t cdev_no;

	bool nowait;
	bool enabled;
};

struct mx_queue {
	struct list_head sq_list;
	spinlock_t sq_lock;
	atomic_t wait_count;
	struct swait_queue_head sq_wait;
	struct swait_queue_head cq_wait;
};

struct mx_operations {
	int (*init_queue) (struct mx_pci_dev *);
	int (*release_queue) (struct mx_pci_dev *);
	void * (*create_command_sg) (struct mx_pci_dev *, struct mx_transfer *, int);
	void * (*create_command_ctrl) (struct mx_transfer *, int);
} __randomize_layout;

struct mx_pci_dev {
	unsigned long magic;
	int dev_id;
	dev_t dev_no;

	struct pci_dev *pdev;
	bool enabled;

	void __iomem *bar;
	uint32_t bar_mapped_size;

	struct mx_operations ops;

	struct mx_event event;

	struct mx_queue *admin_queue;
	struct mx_queue *io_queue;

	struct mx_mbox *sq_mbox_list[MAX_NUM_OF_MBOX];
	struct mx_mbox *cq_mbox_list[MAX_NUM_OF_MBOX];

	struct task_struct *submit_thread;
	struct task_struct *complete_thread;

	int num_of_cdev;
	struct mx_char_dev mx_cdev[NUM_OF_MX_CDEV];

	size_t page_size;
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

long ioctl_to_device(struct mx_pci_dev *mx_pdev, unsigned int cmd, unsigned long arg);

int desc_list_alloc(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int list_cnt);

void register_mx_ops_v1(struct mx_operations *ops);
void register_mx_ops_v2(struct mx_operations *ops);

bool is_empty(struct mx_mbox *mbox);
bool is_full(struct mx_mbox *mbox);
uint32_t get_free_space(struct mx_mbox *mbox);
uint32_t get_pending_count(struct mx_mbox *mbox);
uint8_t get_next_index(uint8_t _index, uint32_t count, uint32_t depth);
uint32_t get_data_offset(uint8_t _db);
void mx_mbox_init(struct mx_mbox *mbox, uint64_t ctx_addr, uint64_t data_addr, uint64_t ctx);
