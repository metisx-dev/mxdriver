
// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/nvme.h>

#include "mx_dma.h"

typedef struct
{
	uint16_t depth;
	uint16_t cq_id;
	uint16_t sq_id;
	uint16_t rsvd1;
} io_queue_info_t;

struct mx_queue_v2 {
	struct mx_queue common;

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
};


struct mx_command {
#if 0
	uint8_t opcode;
	uint8_t flags;
	uint16_t command_id;
#else
	union {
		uint32_t header;
		struct {
			uint32_t opcode : 5;
			uint32_t command_id : 16;
			uint32_t barrier_index : 6;
			uint32_t multi_page : 2;
			uint32_t rsvd : 3;
		};
	};
#endif
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
	uint16_t sq_id;
	uint16_t sq_head;
	uint16_t status;
	uint16_t command_id;
};

/******************************************************************************/
/* Queue helpers                                                              */
/******************************************************************************/
static bool is_cqe_pending(struct mx_queue_v2 *queue)
{
	struct mx_completion *cqe = &queue->cqes[queue->cq_head];

	uint16_t status = le16_to_cpu(READ_ONCE(cqe->status));
	uint16_t phase = (status >> 15) & 1;
	return phase == queue->cq_phase;
}

static bool is_sqe_full(struct mx_queue_v2 *queue)
{
	return (queue->sq_tail + 1) % queue->depth == queue->sq_head;
}

static void *get_sqe_ptr(struct mx_queue_v2 *queue)
{
	if (is_sqe_full(queue))
		return NULL;

	return &queue->sqes[queue->sq_tail];
}

static void *get_cqe_ptr(struct mx_queue_v2 *queue)
{
	if (!is_cqe_pending(queue))
		return NULL;

	return &queue->cqes[queue->cq_head];
}

static void update_sq_doorbell(struct mx_queue_v2 *queue)
{
	uint32_t next_tail = queue->sq_tail + 1;

	if (next_tail == queue->depth)
		queue->sq_tail = 0;
	else
		queue->sq_tail = next_tail;
}

static void update_cq_doorbell(struct mx_queue_v2 *queue)
{
	uint32_t next_head = queue->cq_head + 1;
	if (next_head == queue->depth) {
		queue->cq_head = 0;
		queue->cq_phase ^= 1;
	} else {
		queue->cq_head = next_head;
	}
}

static void ring_sq_doorbell(struct mx_queue_v2 *queue)
{
	if (queue->last_sq_tail == queue->sq_tail)
		return;

	writel(queue->sq_tail, queue->db);
	queue->last_sq_tail = queue->sq_tail;
}

static void ring_cq_doorbell(struct mx_queue_v2 *queue)
{
	writel(queue->cq_head, queue->db + sizeof(uint64_t));
}

/******************************************************************************/
/* Functions for handler                                                      */
/******************************************************************************/
static int submit_handler(void *arg)
{
	struct mx_queue_v2 *queue = (struct mx_queue_v2 *)arg;
	struct mx_transfer *transfer, *tmp;
	struct mx_command *comm;
	unsigned long flags;

	while (!kthread_should_stop()) {
		if (list_empty(&queue->common.sq_list)) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		spin_lock_irqsave(&queue->common.sq_lock, flags);
		list_for_each_entry_safe(transfer, tmp, &queue->common.sq_list, entry) {
			comm = (struct mx_command *)get_sqe_ptr(queue);
			if (!comm)
				break;

			memcpy(comm, transfer->command, sizeof(struct mx_command));
			update_sq_doorbell(queue);
			list_del(&transfer->entry);

			if (transfer->nowait)
				complete(&transfer->done);
		}
		spin_unlock_irqrestore(&queue->common.sq_lock, flags);

		ring_sq_doorbell(queue);
	}

	return 0;
}

static int complete_handler(void *arg)
{
	struct mx_queue_v2 *queue = (struct mx_queue_v2 *)arg;
	struct mx_transfer *transfer;
	struct mx_completion *cmpl;

	while (!kthread_should_stop()) {
		cmpl = (struct mx_completion *)get_cqe_ptr(queue);
		if (!cmpl) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		transfer = find_transfer_by_id(READ_ONCE(cmpl->command_id));
		if (transfer && !transfer->nowait) {
			transfer->result = READ_ONCE(cmpl->result);
			complete(&transfer->done);
		}

		queue->sq_head = READ_ONCE(cmpl->sq_head);

		update_cq_doorbell(queue);
		ring_cq_doorbell(queue);
	}

	return 0;
}

/******************************************************************************/
/* Transfer                                                                   */
/******************************************************************************/
#define SINGLE_DMA_SIZE		PAGE_SIZE
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

	/* Get num of desc list will be desc count of last list */
	list_cnt = 1;
	total_desc_cnt = transfer->pages_nr;
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

		if (desc_idx == NUM_OF_DESC_PER_LIST - 1) {
			if (sg_next(sg)) {
				desc[desc_idx] = (uint64_t)transfer->desc_list_ba[++list_idx];
				desc = (uint64_t *)transfer->desc_list_va[list_idx];
				desc_idx = 0;
			}
		}

		desc[desc_idx++] = dma_addr;
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

	comm->opcode = opcode + 4; // FIXME
	comm->command_id = transfer->id;
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
		comm->host_addr = sg_dma_address(sg);
		if (!comm->host_addr) {
			pr_warn("Failed to get sg_dma_address\n");
			kfree(comm);
			return NULL;
		}
	} else {
		comm->multi_page = 1;
		comm->prp_entry1 = desc_list_init(dev, transfer);
		if (!comm->prp_entry1) {
			pr_warn("Failed to desc_list_init\n");
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
static int alloc_queue(struct device *dev, struct mx_queue_v2 *queue, uint32_t q_depth)
{
	queue->depth = q_depth;
	queue->cqes = dma_alloc_coherent(dev, queue->depth * sizeof(struct mx_completion), &queue->cq_dma_addr, GFP_KERNEL);
	if (!queue->cqes)
		return -ENOMEM;

	queue->sqes = dma_alloc_coherent(dev, queue->depth * sizeof(struct mx_command), &queue->sq_dma_addr, GFP_KERNEL);
	if (!queue->sqes)
		dma_free_coherent(dev, queue->depth * sizeof(struct mx_completion), (void *)queue->cqes, queue->cq_dma_addr);

	pr_info("Allocated queue (depth=%u, cq_dma_addr=0x%llx, sq_dma_addr=0x%llx, sqes=0x%llx, cqes=0x%llx)\n",
			queue->depth, queue->cq_dma_addr, queue->sq_dma_addr, (uint64_t)queue->sqes, (uint64_t)queue->cqes);

	return 0;
}

static int release_queue(struct device *dev, struct mx_queue_v2 *queue)
{
	if (!queue->cqes || !queue->sqes)
		return -EINVAL;

	dma_free_coherent(dev, queue->depth * sizeof(struct mx_completion), (void *)queue->cqes, queue->cq_dma_addr);
	dma_free_coherent(dev, queue->depth * sizeof(struct mx_command), (void *)queue->sqes, queue->sq_dma_addr);

	queue->cqes = NULL;
	queue->sqes = NULL;
	queue->cq_dma_addr = 0;
	queue->sq_dma_addr = 0;

	kfree(queue);

	return 0;
}

static void configure_queue(struct mx_pci_dev *mx_pdev, struct mx_queue_v2 *queue, uint16_t qid)
{
	uint64_t __iomem *dbs = mx_pdev->bar + NVME_REG_DBS;

	queue->qid = qid;
	queue->sq_tail = 0;
	queue->sq_head = 0;
	queue->cq_head = 0;
	queue->cq_phase = 1;
	queue->db = &dbs[qid * 2];
	memset((void *)queue->cqes, 0, queue->depth * sizeof(struct mx_completion));
	memset((void *)queue->sqes, 0, queue->depth * sizeof(struct mx_command));
	wmb();
}

static int configure_admin_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v2 *queue = kzalloc(sizeof(struct mx_queue_v2), GFP_KERNEL);
	uint32_t aqa;
	int ret;

	pr_info("Configuring admin queue...\n");

	ret = alloc_queue(dev, queue, NVME_AQ_DEPTH);
	if (ret)
		return ret;

	aqa = queue->depth - 1;
	aqa |= aqa << 16;
	writel(aqa, mx_pdev->bar + 0x0);
	writeq(queue->sq_dma_addr, mx_pdev->bar + 0x8);
	writeq(queue->cq_dma_addr, mx_pdev->bar + 0x10);

	pr_info("Admin queue created (depth=%u)\n", queue->depth);

	configure_queue(mx_pdev, queue, 0);

	mx_pdev->admin_queue = (struct mx_queue *)queue;

	return 0;
}

static int release_admin_queue(struct mx_pci_dev *mx_pdev)
{
	return release_queue(&mx_pdev->pdev->dev, (struct mx_queue_v2 *)mx_pdev->admin_queue);
}

static uint64_t submit_sync_command(struct mx_queue_v2* queue, struct mx_command *c)
{
	struct mx_command *comm;
	struct mx_completion *cmpl;

	comm = (struct mx_command *)get_sqe_ptr(queue);
	if (!comm)
		return -EAGAIN;

	memcpy(comm, c, sizeof(struct mx_command));
	update_sq_doorbell(queue);
	ring_sq_doorbell(queue);

	do {
		cmpl = (struct mx_completion *)get_cqe_ptr(queue);
	} while (!cmpl);

	queue->sq_head = READ_ONCE(cmpl->sq_head);
	update_cq_doorbell(queue);
	ring_cq_doorbell(queue);

	return cmpl->result;
}

static int configure_io_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v2 *admin_queue = (struct mx_queue_v2 *)mx_pdev->admin_queue;
	struct mx_queue_v2 *io_queue = kzalloc(sizeof(struct mx_queue_v2), GFP_KERNEL);
	struct mx_command comm = {};
	uint16_t cq_id, sq_id;
	int ret;

	pr_info("Configuring IO queue...\n");

	ret = alloc_queue(dev, io_queue, 256);
	if (ret)
		return ret;

	comm.opcode = ADMIN_OPCODE_CREATE_IO_CQ;
	comm.host_addr = cpu_to_le64(io_queue->cq_dma_addr);
	comm.io_queue_info.depth = io_queue->depth;
	cq_id = submit_sync_command(admin_queue, &comm);

	comm.opcode = ADMIN_OPCODE_CREATE_IO_SQ;
	comm.host_addr = cpu_to_le64(io_queue->sq_dma_addr);
	comm.io_queue_info.cq_id = cq_id;
	sq_id = submit_sync_command(admin_queue, &comm);

	if (cq_id != sq_id) {
		pr_err("Failed to create IO queue (cq_id=%d, sq_id=%d)\n", cq_id, sq_id);
		return -EINVAL;
	}

	pr_info("IO queue created (depth=%u, sq_id=%u, cq_id=%u)\n", io_queue->depth, sq_id, cq_id);

	configure_queue(mx_pdev, io_queue, cq_id);

	spin_lock_init(&io_queue->common.sq_lock);
	INIT_LIST_HEAD(&io_queue->common.sq_list);

	mx_pdev->submit_thread = kthread_run(submit_handler, io_queue, "mx_submit_thd%d", mx_pdev->dev_id);
	mx_pdev->complete_thread = kthread_run(complete_handler, io_queue, "mx_complete_thd%d", mx_pdev->dev_id);

	mx_pdev->io_queue = (struct mx_queue *)io_queue;

	return 0;
}

static int release_io_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v2 *admin_queue = (struct mx_queue_v2 *)mx_pdev->admin_queue;
	struct mx_queue_v2 *io_queue = (struct mx_queue_v2 *)mx_pdev->io_queue;
	struct mx_command comm = {};
	int ret;

	comm.opcode = ADMIN_OPCODE_DELETE_IO_CQ;
	comm.io_queue_info.cq_id = io_queue->qid;
	submit_sync_command(admin_queue, &comm);

	comm.opcode = ADMIN_OPCODE_DELETE_IO_SQ;
	comm.io_queue_info.sq_id = io_queue->qid;
	submit_sync_command(admin_queue, &comm);

	ret = release_queue(dev, io_queue);
	if (ret)
		pr_err("Failed to release IO queue (err=%d)\n", ret);

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

	return 0;
}

static int init_mx_queue(struct mx_pci_dev *mx_pdev)
{
	int ret;

	mx_pdev->page_size = SINGLE_DMA_SIZE;

	ret = configure_admin_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to configure admin queue (err=%d)\n", ret);
		return ret;
	}

	ret = configure_io_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to configure IO queue (err=%d)\n", ret);
		release_admin_queue(mx_pdev);
		return ret;
	}

	pr_info("MX queue initialized successfully\n");
	return 0;
}

static int release_mx_queue(struct mx_pci_dev *mx_pdev)
{
	int ret;

	ret = release_io_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to release IO queue (err=%d)\n", ret);
		return ret;
	}

	ret = release_admin_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to release admin queue (err=%d)\n", ret);
		return ret;
	}

	pr_info("MX queue released successfully\n");
	return 0;
}

void register_mx_ops_v2(struct mx_operations *ops)
{
	ops->init_queue =  init_mx_queue;
	ops->release_queue = release_mx_queue;
	ops->create_command_sg = create_mx_command_sg;
	ops->create_command_ctrl = create_mx_command_ctrl;
}

