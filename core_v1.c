// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/atomic.h>

#include "mx_dma.h"

enum {
	MXDMA_PAGE_MODE_SINGLE = 0,
	MXDMA_PAGE_MODE_MULTI,
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

struct mx_mbox {
	void __iomem *ctx_addr;
	void __iomem *data_addr;
	void __iomem *db_addr;
	mbox_context_t ctx;
	uint32_t depth;
};

struct mx_queue_v1 {
	struct mx_queue common;
	struct mx_mbox sq_mbox;
	struct mx_mbox cq_mbox;
	atomic_t wait_count;
};

struct mx_command {
	union {
		struct {
			uint64_t magic : 16;
			uint64_t opcode : 4;
			uint64_t control : 4;
			uint64_t page_mode : 2;
			uint64_t id : 16;
			uint64_t barrier_index : 6;
			uint64_t rsvd : 14;
			uint64_t nowait : 2;
		};
		uint64_t header;
	};
	uint64_t size;
	uint64_t device_addr;
	union {
		uint64_t host_addr;
		uint64_t prp_entry1;
		uint64_t doorbell_value;
	};
};

/******************************************************************************/
/* Queue helpers                                                              */
/******************************************************************************/
static int get_free_space(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;
	uint32_t depth = mbox->depth;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	return head.index - tail.index + depth * (1 - (head.phase ^ tail.phase));
}

static int get_pending_count(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;
	uint32_t depth = mbox->depth;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	return tail.index - head.index + depth * (head.phase ^ tail.phase);
}

static bool is_pushable(struct mx_queue_v1 *queue)
{
	static uint64_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	struct mx_mbox *mbox = &queue->sq_mbox;

	if (list_empty(&queue->common.sq_list))
		return false;

	mbox->ctx.u64 = readq(mbox->ctx_addr);

	return get_free_space(mbox) >= data_count;
}

static bool is_popable(struct mx_queue_v1 *queue)
{
	static uint64_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	struct mx_mbox *mbox = &queue->cq_mbox;

	if (atomic_read(&queue->wait_count) == 0)
		return false;

	mbox->ctx.u64 = readq(mbox->ctx_addr);

	return get_pending_count(mbox) >= data_count;
}

static uint8_t get_next_index(uint8_t _index, uint32_t count, uint32_t depth)
{
	mbox_index_t last, next;

	last.full = _index;
	next.full = _index;

	next.index = (next.index + count) & (depth - 1);
	if (count && (next.index <= last.index))
		next.phase ^= 1;

	return next.full;
}

static void __iomem *get_data_addr(void __iomem *base, uint8_t _db)
{
	mbox_index_t db;

	db.full = _db;

	return base + (sizeof(uint64_t) * db.index);
}

static void push_mx_command(struct mx_mbox *mbox, struct mx_command *comm)
{
	mbox_context_t ctx;
	void __iomem *data_addr;

	ctx.u64 = readq(mbox->ctx_addr);

	data_addr = get_data_addr(mbox->data_addr, ctx.tail);
	memcpy_toio(data_addr, comm, sizeof(struct mx_command));

	ctx.tail = get_next_index(ctx.tail, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writel(ctx.u32[1], mbox->db_addr);
}

static void pop_mx_command(struct mx_mbox *mbox, struct mx_command *comm)
{
	mbox_context_t ctx;
	void __iomem *data_addr;

	ctx.u64 = readq(mbox->ctx_addr);

	data_addr = get_data_addr(mbox->data_addr, ctx.head);
	memcpy_fromio(comm, data_addr, sizeof(struct mx_command));

	ctx.head = get_next_index(ctx.head, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writel(ctx.u32[1], mbox->db_addr);
}

/******************************************************************************/
/* Functions for handler                                                      */
/******************************************************************************/
static int submit_handler(void *arg)
{
	struct mx_queue_v1 *queue = (struct mx_queue_v1 *)arg;
	struct mx_mbox *sq_mbox = &queue->sq_mbox;
	struct mx_transfer *transfer;
	unsigned long flags;

	while (kthread_should_stop() == false) {
		if (!is_pushable(queue)) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		spin_lock_irqsave(&queue->common.sq_lock, flags);
		transfer = list_first_entry(&queue->common.sq_list, struct mx_transfer, entry);
		list_del(&transfer->entry);
		spin_unlock_irqrestore(&queue->common.sq_lock, flags);

		push_mx_command(sq_mbox, (struct mx_command*)transfer->command);

		if (transfer->nowait) {
			complete(&transfer->done);
		} else {
			atomic_inc(&queue->wait_count);
		}
	}

	return 0;
}

static int complete_handler(void *arg)
{
	struct mx_queue_v1 *queue = (struct mx_queue_v1 *)arg;
	struct mx_mbox *cq_mbox = &queue->cq_mbox;
	struct mx_transfer *transfer;
	struct mx_command comm;

	while (kthread_should_stop() == false) {
		if (!is_popable(queue)) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		pop_mx_command(cq_mbox, &comm);
		atomic_dec(&queue->wait_count);

		transfer = find_transfer_by_id(comm.id);
		if (!transfer)
			continue;

		transfer->result = comm.host_addr;
		complete(&transfer->done);
	}

	return 0;
}

/******************************************************************************/
/* Transfer                                                                   */
/******************************************************************************/
#define SINGLE_DMA_SIZE		(1 << 10)
#define NUM_OF_DESC_PER_LIST	(SINGLE_DMA_SIZE / sizeof(uint64_t))

static uint64_t desc_list_init(struct device *dev, struct mx_transfer *transfer)
{
	struct sg_table *sgt = &transfer->sgt;
	struct scatterlist *sg = sgt->sgl;
	uint64_t *desc;
	int total_desc_cnt;
	int list_cnt, list_idx, desc_idx;
	int i;
	int ret;

	/* Get num of total desc count */
	total_desc_cnt = 0;
	for_each_sgtable_dma_sg(sgt, sg, i) {
		int len = sg_dma_len(sg);
		int desc_cnt = (len + SINGLE_DMA_SIZE - 1) / SINGLE_DMA_SIZE;

		total_desc_cnt += desc_cnt;
	}

	/* Get num of desc list will be desc count of last list */
	list_cnt = 1;
	while (total_desc_cnt > NUM_OF_DESC_PER_LIST) {
		total_desc_cnt -= (NUM_OF_DESC_PER_LIST - 1);
		list_cnt++;
	}

	ret = desc_list_alloc(dev, transfer, list_cnt);
	if (ret) {
		pr_warn("Failed to desc_list_alloc (err=%d)\n", ret);
		return 0;
	}

	list_idx = 0;
	desc_idx = 0;
	desc = (uint64_t *)transfer->desc_list_va[list_idx];

	for_each_sgtable_dma_sg(sgt, sg, i) {
		dma_addr_t dma_addr = sg_dma_address(sg);
		ssize_t dma_size = sg_dma_len(sg);
		ssize_t offset = sg->offset;
		ssize_t len = SINGLE_DMA_SIZE;

		if (offset) {
			ssize_t tmp = (PAGE_SIZE - offset) & (SINGLE_DMA_SIZE - 1);
			if (tmp != 0) {
				len = tmp;
			}
		}

		while (dma_size > 0) {
			if (desc_idx == NUM_OF_DESC_PER_LIST - 1) {
				if (sg_next(sg) || dma_size > SINGLE_DMA_SIZE) {
					desc[desc_idx] = (uint64_t)transfer->desc_list_ba[++list_idx];
					desc = (uint64_t *)transfer->desc_list_va[list_idx];
					desc_idx = 0;
				}
			}

			desc[desc_idx++] = dma_addr;
			dma_addr += len;
			dma_size -= len;
			len = min_t(ssize_t, dma_size, SINGLE_DMA_SIZE);
		}
	}

	return transfer->desc_list_ba[0];
}

static struct mx_command *alloc_mx_command(struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm = kzalloc(sizeof(struct mx_command), GFP_KERNEL);

	if (!comm) {
		pr_warn("Failed to allocate mx_command\n");
		return NULL;
	}

	comm->magic = MAGIC_COMMAND;
	comm->id = transfer->id;
	comm->opcode = opcode;
	comm->nowait = transfer->nowait ? 1 : 0;
	comm->size = transfer->size;
	comm->device_addr = transfer->device_addr;

	return comm;
}

static void *create_mx_command_sg(struct device *dev, struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm;
	struct sg_table *sgt = &transfer->sgt;
	struct scatterlist *sg = sgt->sgl;
	unsigned int size;

	comm = alloc_mx_command(transfer, opcode);
	if (!comm) {
		pr_warn("Failed to allocate mx_command for sg transfer\n");
		return NULL;
	}

	size = (PAGE_SIZE - sg->offset) % SINGLE_DMA_SIZE;
	size = size ? size : SINGLE_DMA_SIZE;

	if (transfer->size <= size) {
		comm->page_mode = MXDMA_PAGE_MODE_SINGLE;
		comm->host_addr = sg_dma_address(sg);
		if (!comm->host_addr) {
			pr_warn("Failed to get sg_dma_address\n");
			kfree(comm);
			return NULL;
		}
	} else {
		comm->page_mode = MXDMA_PAGE_MODE_MULTI;
		comm->prp_entry1 = desc_list_init(dev, transfer);
		if (!comm->prp_entry1) {
			pr_warn("Failed to get desc_list_init\n");
			kfree(comm);
			return NULL;
		}
	}

	return (void*)comm;
}

static void *create_mx_command_ctrl(struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm;

	comm = alloc_mx_command(transfer, opcode);
	if (!comm) {
		pr_warn("Failed to allocate mx_command\n");
		return NULL;
	}

	if (transfer->dir == DMA_TO_DEVICE) {
		uint64_t value = 0;
		int ret = copy_from_user(&value, transfer->user_addr, transfer->size);

		if (ret) {
			pr_warn("Failed to copy_from_user (err=%d)\n", ret);
			return NULL;
		}
		comm->doorbell_value = value;
	}

	return (void*)comm;
}

/******************************************************************************/
/* Init                                                                       */
/******************************************************************************/
#define HMBOX_UPDATE_BITMASK (1ull << 18)
#define HMBOX_DB_OFFSET 4
static int mx_mbox_init(struct mx_mbox *mbox, void __iomem *ctx_addr, void __iomem *data_addr)
{
	mbox->ctx_addr = ctx_addr;
	mbox->ctx.u64 = readq(mbox->ctx_addr);
	if (mbox->ctx.u64 == ULLONG_MAX) {
		pr_err("Failed to read mbox context address\n");
		return -EIO;
	}

	mbox->data_addr = data_addr + sizeof(uint64_t) * mbox->ctx.data_base;
	mbox->db_addr = mbox->ctx_addr + HMBOX_UPDATE_BITMASK + HMBOX_DB_OFFSET;
	mbox->depth = BIT(mbox->ctx.q_size);

	return 0;
}

#define HMBOX_HIO_QID 48
#define HMBOX_RQ_OFFSET 0x1000
static int init_mx_queue(struct mx_pci_dev* mx_pdev)
{
	struct mx_queue_v1 *queue = kzalloc(sizeof(struct mx_queue_v1), GFP_KERNEL);
	void __iomem *host_mbox_base, *hifc_mbox_base;
	uint64_t q_offset = HMBOX_HIO_QID * sizeof(uint64_t);
	int ret;

	if (!queue) {
		pr_err("Failed to allocate memory for mx_queue_v1\n");
		return -ENOMEM;
	}

	mx_pdev->page_size = SINGLE_DMA_SIZE;

	host_mbox_base = mx_pdev->bar;
	hifc_mbox_base = host_mbox_base + (1 << 20);

	ret = mx_mbox_init(&queue->sq_mbox, host_mbox_base + q_offset, hifc_mbox_base);
	if (ret) {
		pr_err("Failed to init sq_mbox (err=%d)\n", ret);
		return ret;
	}

	ret = mx_mbox_init(&queue->cq_mbox, host_mbox_base + q_offset + HMBOX_RQ_OFFSET, host_mbox_base);
	if (ret) {
		pr_err("Failed to init cq_mbox (err=%d)\n", ret);
		return ret;
	}

	spin_lock_init(&queue->common.sq_lock);
	INIT_LIST_HEAD(&queue->common.sq_list);
	atomic_set(&queue->wait_count, 0);

	mx_pdev->submit_thread = kthread_run(submit_handler, queue, "mx_submit_thd%d", mx_pdev->dev_id);
	mx_pdev->complete_thread = kthread_run(complete_handler, queue, "mx_complete_thd%d", mx_pdev->dev_id);

	mx_pdev->io_queue = (struct mx_queue *)queue;

	return 0;
}

static int release_mx_queue(struct mx_pci_dev *mx_pdev)
{
	int ret;

	if (mx_pdev->submit_thread) {
		ret = kthread_stop(mx_pdev->submit_thread);
		if (ret)
			pr_err("submit_thread thread doesn't stop properly (err=%d)\n", ret);
	}

	if (mx_pdev->complete_thread) {
		ret = kthread_stop(mx_pdev->complete_thread);
		if (ret)
			pr_err("complete_thread thread doesn't stop properly (err=%d)\n", ret);
	}

	kfree(mx_pdev->io_queue);

	return ret;
}

void register_mx_ops_v1(struct mx_operations *ops)
{
	ops->init_queue =  init_mx_queue;
	ops->release_queue = release_mx_queue;
	ops->create_command_sg = create_mx_command_sg;
	ops->create_command_ctrl = create_mx_command_ctrl;
}

