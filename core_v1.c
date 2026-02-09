// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/atomic.h>

#include "mx_dma.h"

enum {
	MXDMA_PAGE_MODE_SINGLE = 0,
	MXDMA_PAGE_MODE_MULTI,
};

struct mx_queue_v1 {
	struct mx_queue common;
	struct mx_mbox sq_mbox;
	struct mx_mbox cq_mbox;
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
static bool is_pushable(struct mx_queue_v1 *queue)
{
	static uint32_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	struct mx_mbox *mbox = &queue->sq_mbox;
	uint32_t free_space;

	mbox->ctx.u64 = readq((void *)mbox->r_ctx_addr);
	free_space = get_free_space(mbox);

	return free_space >= data_count;
}

static bool is_popable(struct mx_queue_v1 *queue)
{
	static uint32_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	struct mx_mbox *mbox = &queue->cq_mbox;
	uint32_t pending_count;

	if (atomic_read(&queue->common.wait_count) <= 0)
		return false;

	mbox->ctx.u64 = readq((void *)mbox->r_ctx_addr);
	pending_count = get_pending_count(mbox);

	return pending_count >= data_count;
}

static void push_mx_command(struct mx_queue_v1 *queue, struct mx_command *comm)
{
	struct mx_mbox *mbox = &queue->sq_mbox;
	mbox_context_t *ctx = &mbox->ctx;
	void __iomem *data_addr;

	data_addr = (void *)mbox->data_addr + get_data_offset(ctx->tail);
	memcpy_toio(data_addr, comm, sizeof(struct mx_command));

	dev_dbg(queue->common.dev, "SQ+ tail=0x%02x id=0x%04x op=%u ha=0x%llx da=0x%llx len=%llu\n",
			ctx->tail, comm->id, comm->opcode, comm->host_addr, comm->device_addr, comm->size);

	ctx->tail = get_next_index(ctx->tail, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writeq(ctx->u64, (void *)mbox->w_ctx_addr);
}

static void pop_mx_command(struct mx_queue_v1 *queue, struct mx_command *comm)
{
	struct mx_mbox *mbox = &queue->cq_mbox;
	mbox_context_t *ctx = &mbox->ctx;
	void __iomem *data_addr;

	data_addr = (void *)mbox->data_addr + get_data_offset(ctx->head);
	memcpy_fromio(comm, data_addr, sizeof(struct mx_command));

	dev_dbg(queue->common.dev, "CQ- head=0x%02x id=0x%04x op=%u ha=0x%llx da=0x%llx len=%llu\n",
			ctx->head, comm->id, comm->opcode, comm->host_addr, comm->device_addr, comm->size);

	ctx->head = get_next_index(ctx->head, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writeq(ctx->u64, (void *)mbox->w_ctx_addr);
}

/******************************************************************************/
/* Queue ops adapter for unified handlers                                     */
/******************************************************************************/
static bool v1_is_pushable(struct mx_queue *q)
{
	struct mx_queue_v1 *queue = container_of(q, struct mx_queue_v1, common);

	return is_pushable(queue);
}

static void v1_push_command(struct mx_queue *q, void *command)
{
	struct mx_queue_v1 *queue = container_of(q, struct mx_queue_v1, common);

	push_mx_command(queue, (struct mx_command *)command);
}

static bool v1_is_popable(struct mx_queue *q)
{
	struct mx_queue_v1 *queue = container_of(q, struct mx_queue_v1, common);

	return is_popable(queue);
}

static void v1_pop_completion(struct mx_queue *q, int *out_id, uint64_t *out_result)
{
	struct mx_queue_v1 *queue = container_of(q, struct mx_queue_v1, common);
	struct mx_command comm;

	pop_mx_command(queue, &comm);
	*out_id = comm.id;
	*out_result = comm.host_addr;
}

static const struct mx_queue_ops v1_queue_ops = {
	.is_pushable	= v1_is_pushable,
	.push_command	= v1_push_command,
	.post_submit	= NULL,
	.is_popable	= v1_is_popable,
	.pop_completion	= v1_pop_completion,
	.post_complete	= NULL,
};

/******************************************************************************/
/* Transfer                                                                   */
/******************************************************************************/
#define SINGLE_DMA_SIZE		(1 << 10)
#define NUM_OF_DESC_PER_LIST	(SINGLE_DMA_SIZE / sizeof(uint64_t))


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
	comm->size = transfer->size;
	comm->device_addr = transfer->device_addr;

	return comm;
}

static void *create_mx_command_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int opcode)
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
		comm->prp_entry1 = mx_desc_list_init(mx_pdev, transfer, SINGLE_DMA_SIZE, NUM_OF_DESC_PER_LIST, false);
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

	if (transfer->dir != DMA_TO_DEVICE)
		return (void*)comm;

	if (access_ok(transfer->user_addr, transfer->size)) {
		if (copy_from_user(&comm->doorbell_value, transfer->user_addr, sizeof(uint64_t))) {
			pr_warn("Failed to copy_from_user (%llx <- %llx)\n",
					(uint64_t)&comm->doorbell_value, (uint64_t)transfer->user_addr);
			return NULL;
		}
	} else {
		comm->doorbell_value = *(uint64_t *)transfer->user_addr;
	}

	return (void*)comm;
}

/******************************************************************************/
/* Init                                                                       */
/******************************************************************************/
#define HMBOX_HIO_QID		48
#define HMBOX_RQ_OFFSET		0x1000
#define HIFC_MBOX_BAR_OFFSET	(1ull << 20)

static int init_mx_queue(struct mx_pci_dev* mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v1 *queue;
	void __iomem *host_mbox_base, *hifc_mbox_base;
	void __iomem *ctx_addr, *data_addr;
	uint64_t q_offset;
	uint64_t ctx;

	queue = devm_kzalloc(dev, sizeof(struct mx_queue_v1), GFP_KERNEL);
	if (!queue) {
		pr_err("Failed to allocate memory for mx_queue_v1\n");
		return -ENOMEM;
	}

	mx_pdev->page_size = SINGLE_DMA_SIZE;

	host_mbox_base = mx_pdev->bar;
	hifc_mbox_base = host_mbox_base + HIFC_MBOX_BAR_OFFSET;
	q_offset = HMBOX_HIO_QID * sizeof(uint64_t);

	ctx_addr = host_mbox_base + q_offset;
	data_addr = hifc_mbox_base;
	ctx = readq(ctx_addr);
	if (ctx == ULLONG_MAX) {
		pr_info("Invalid mbox context (ctx_addr = 0x%p)\n", ctx_addr);
		return -EINVAL;
	}
	mx_mbox_init(&queue->sq_mbox, (uint64_t)ctx_addr, (uint64_t)data_addr, ctx);

	ctx_addr += HMBOX_RQ_OFFSET;
	data_addr = host_mbox_base;
	ctx = readq(ctx_addr);
	if (ctx == ULLONG_MAX) {
		pr_info("Invalid mbox context (ctx_addr = 0x%p)\n", ctx_addr);
		return -EINVAL;
	}
	mx_mbox_init(&queue->cq_mbox, (uint64_t)ctx_addr, (uint64_t)data_addr, ctx);

	queue->common.dev = dev;
	queue->common.ops = &v1_queue_ops;
	spin_lock_init(&queue->common.sq_lock);
	INIT_LIST_HEAD(&queue->common.sq_list);
	init_swait_queue_head(&queue->common.sq_wait);
	init_swait_queue_head(&queue->common.cq_wait);
	atomic_set(&queue->common.wait_count, 0);

	mx_pdev->submit_thread = kthread_run(mx_submit_handler, &queue->common, "mx_submit_thd%d", mx_pdev->dev_id);
	if (IS_ERR(mx_pdev->submit_thread)) {
		pr_err("Failed to create submit thread (err=%ld)\n", PTR_ERR(mx_pdev->submit_thread));
		return PTR_ERR(mx_pdev->submit_thread);
	}

	mx_pdev->complete_thread = kthread_run(mx_complete_handler, &queue->common, "mx_complete_thd%d", mx_pdev->dev_id);
	if (IS_ERR(mx_pdev->complete_thread)) {
		pr_err("Failed to create complete thread (err=%ld)\n", PTR_ERR(mx_pdev->complete_thread));
		kthread_stop(mx_pdev->submit_thread);
		return PTR_ERR(mx_pdev->complete_thread);
	}

	mx_pdev->io_queue = (struct mx_queue *)queue;

	return 0;
}

static int release_mx_queue(struct mx_pci_dev *mx_pdev)
{
	mx_stop_queue_threads(mx_pdev);
	return 0;
}

void register_mx_ops_v1(struct mx_operations *ops)
{
	ops->init_queue =  init_mx_queue;
	ops->release_queue = release_mx_queue;
	ops->create_command_sg = create_mx_command_sg;
	ops->create_command_ctrl = create_mx_command_ctrl;
}

