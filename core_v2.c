
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
	uint16_t last_cq_head;
	uint16_t sq_tail;
	uint16_t sq_head;
	uint16_t cq_head;
	uint16_t cq_phase;
	void __iomem *db;
};


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
} __packed;

struct mx_completion
{
	uint64_t result;
	uint16_t sq_head;
	uint16_t sq_id;
	uint16_t command_id;
	uint16_t status;
} __packed;

/******************************************************************************/
/* Queue helpers                                                              */
/******************************************************************************/
static bool is_pushable(struct mx_queue_v2 *queue)
{
       return (queue->sq_tail + 1) % queue->depth != queue->sq_head;
}

static bool is_popable(struct mx_queue_v2 *queue)
{
	struct mx_completion *cqe;
	uint16_t status, phase;

	if (atomic_read(&queue->common.wait_count) <= 0)
		return false;

	cqe = &queue->cqes[queue->cq_head];
	status = le16_to_cpu(READ_ONCE(cqe->status));
	phase = status & 0x1;
	return phase == queue->cq_phase;
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

static void push_mx_command(struct mx_queue_v2 *queue, struct mx_command *comm)
{
	memcpy(&queue->sqes[queue->sq_tail], comm, sizeof(struct mx_command));
	dev_dbg(queue->common.dev, "SQ+ tail=0x%02x id=0x%04x op=%u ha=0x%llx;0x%llx da=0x%llx len=%llu\n",
			queue->sq_tail, comm->command_id, comm->opcode, comm->host_addr, comm->prp_entry2, comm->device_addr, comm->size);
	update_sq_doorbell(queue);
}

static void pop_mx_completion(struct mx_queue_v2 *queue, struct mx_completion *cmpl)
{
	memcpy(cmpl, &queue->cqes[queue->cq_head], sizeof(struct mx_completion));
	dev_dbg(queue->common.dev, "CQ- head=0x%02x id=0x%04x res=0x%llx\n",
			queue->cq_head, cmpl->command_id, cmpl->result);
	queue->sq_head = cmpl->sq_head;
	update_cq_doorbell(queue);
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
	if (queue->last_cq_head == queue->cq_head)
		return;

	writel(queue->cq_head, queue->db + sizeof(uint32_t));
	queue->last_cq_head = queue->cq_head;
}

/******************************************************************************/
/* Queue ops adapter for unified handlers                                     */
/******************************************************************************/
static bool v2_is_pushable(struct mx_queue *q)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);

	return is_pushable(queue);
}

static void v2_push_command(struct mx_queue *q, void *command)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);

	push_mx_command(queue, (struct mx_command *)command);
}

static void v2_post_submit(struct mx_queue *q)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);

	ring_sq_doorbell(queue);
}

static bool v2_is_popable(struct mx_queue *q)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);

	return is_popable(queue);
}

static void v2_pop_completion(struct mx_queue *q, int *out_id, uint64_t *out_result)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);
	struct mx_completion cmpl;

	pop_mx_completion(queue, &cmpl);
	*out_id = cmpl.command_id;
	*out_result = cmpl.result;
}

static void v2_post_complete(struct mx_queue *q)
{
	struct mx_queue_v2 *queue = container_of(q, struct mx_queue_v2, common);

	ring_cq_doorbell(queue);
}

static const struct mx_queue_ops v2_queue_ops = {
	.is_pushable	= v2_is_pushable,
	.push_command	= v2_push_command,
	.post_submit	= v2_post_submit,
	.is_popable	= v2_is_popable,
	.pop_completion	= v2_pop_completion,
	.post_complete	= v2_post_complete,
};

/******************************************************************************/
/* Transfer                                                                   */
/******************************************************************************/
#define SINGLE_DMA_SIZE		PAGE_SIZE
#define NUM_OF_DESC_PER_LIST	(SINGLE_DMA_SIZE / sizeof(uint64_t))


static struct mx_command *alloc_mx_command(struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm = kzalloc(sizeof(struct mx_command), GFP_KERNEL);

	if (!comm) {
		pr_warn("Failed to allocate mx_command\n");
		return NULL;
	}

	comm->opcode = opcode;
	comm->command_id = transfer->id;
	comm->size = transfer->size;
	comm->device_addr = transfer->device_addr;

	return comm;
}

static void *create_mx_command_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm;
	struct sg_table *sgt = &transfer->sgt;
	struct scatterlist *sg = sgt->sgl;

	comm = alloc_mx_command(transfer, opcode);
	if (!comm) {
		pr_warn("Failed to allocate mx_command for sg transfer\n");
		return NULL;
	}

	comm->prp_entry1 = sg_dma_address(sg);
	if (!comm->prp_entry1) {
		pr_warn("Failed to get sg_dma_address\n");
		kfree(comm);
		return NULL;
	}

	if (transfer->pages_nr == 1) {
		comm->prp_entry2 = 0;
	} else if (transfer->pages_nr == 2) {
		if (sg_dma_len(sg) + sg->offset > SINGLE_DMA_SIZE)
			comm->prp_entry2 = (comm->prp_entry1 + SINGLE_DMA_SIZE) - sg->offset;
		else
			comm->prp_entry2 = sg_dma_address(sg_next(sg));
		if (!comm->prp_entry2) {
			pr_warn("Failed to get sg_dma_address\n");
			kfree(comm);
			return NULL;
		}
	} else {
		comm->prp_entry2 = mx_desc_list_init(mx_pdev, transfer, SINGLE_DMA_SIZE, NUM_OF_DESC_PER_LIST, true);
		if (!comm->prp_entry2) {
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
static int alloc_queue(struct device *dev, struct mx_queue_v2 *queue, uint32_t q_depth)
{
	queue->depth = q_depth;
	queue->cqes = dmam_alloc_coherent(dev, queue->depth * sizeof(struct mx_completion), &queue->cq_dma_addr, GFP_KERNEL);
	if (!queue->cqes)
		return -ENOMEM;

	queue->sqes = dmam_alloc_coherent(dev, queue->depth * sizeof(struct mx_command), &queue->sq_dma_addr, GFP_KERNEL);
	if (!queue->sqes)
		return -ENOMEM;

	pr_info("Allocated queue (depth=%u, sq_dma_addr=0x%llx, cq_dma_addr=0x%llx, sqes=0x%llx, cqes=0x%llx)\n",
			queue->depth, queue->sq_dma_addr, queue->cq_dma_addr, (uint64_t)queue->sqes, (uint64_t)queue->cqes);

	return 0;
}

static void configure_queue(struct mx_pci_dev *mx_pdev, struct mx_queue_v2 *queue, uint16_t qid)
{
	uint64_t __iomem *dbs = mx_pdev->bar + NVME_REG_DBS;

	queue->common.dev = &mx_pdev->pdev->dev;
	queue->qid = qid;
	queue->sq_tail = 0;
	queue->sq_head = 0;
	queue->cq_head = 0;
	queue->cq_phase = 1;
	queue->db = &dbs[qid];
	memset((void *)queue->cqes, 0, queue->depth * sizeof(struct mx_completion));
	memset((void *)queue->sqes, 0, queue->depth * sizeof(struct mx_command));
	wmb();
}

static int configure_admin_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v2 *queue = devm_kzalloc(dev, sizeof(struct mx_queue_v2), GFP_KERNEL);
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

static int submit_sync_command(struct mx_queue_v2* queue, struct mx_command *c, uint64_t *result)
{
	struct mx_completion cmpl;
	int timeout = 500;
	int count = 0;

	for (count = 0; count < timeout; count++) {
		if (is_pushable(queue))
			break;
		msleep(1);
	}
	if (count >= timeout) {
		pr_err("Timeout waiting for pushable admin queue\n");
		return false;
	}

	push_mx_command(queue, c);
	ring_sq_doorbell(queue);
	atomic_inc(&queue->common.wait_count);

	for (count = 0; count < timeout; count++) {
		if (is_popable(queue))
			break;
		msleep(1);
	}
	if (count >= timeout) {
		pr_err("Timeout waiting for popable admin queue\n");
		return false;
	}

	pop_mx_completion(queue, &cmpl);
	ring_cq_doorbell(queue);

	if (result)
		*result = cmpl.result;

	return true;
}

static int configure_io_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue_v2 *admin_queue = (struct mx_queue_v2 *)mx_pdev->admin_queue;
	struct mx_queue_v2 *io_queue = devm_kzalloc(dev, sizeof(struct mx_queue_v2), GFP_KERNEL);
	struct mx_command comm = {};
	uint64_t result;
	uint16_t cq_id, sq_id;
	bool ret;

	pr_info("Configuring IO queue...\n");

	ret = alloc_queue(dev, io_queue, 256);
	if (ret)
		return ret;

	comm.opcode = ADMIN_OPCODE_CREATE_IO_CQ;
	comm.host_addr = cpu_to_le64(io_queue->cq_dma_addr);
	comm.io_queue_info.depth = io_queue->depth;
	ret = submit_sync_command(admin_queue, &comm, &result);
	if (!ret) {
		pr_err("Failed to create IO completion queue\n");
		return -EIO;
	}
	cq_id = le16_to_cpu(result);

	comm.opcode = ADMIN_OPCODE_CREATE_IO_SQ;
	comm.host_addr = cpu_to_le64(io_queue->sq_dma_addr);
	comm.io_queue_info.cq_id = cq_id;
	ret = submit_sync_command(admin_queue, &comm, &result);
	if (!ret) {
		pr_err("Failed to create IO submission queue\n");
		return -EIO;
	}
	sq_id = le16_to_cpu(result);

	if (cq_id != sq_id) {
		pr_err("Failed to create IO queue (cq_id=%d, sq_id=%d)\n", cq_id, sq_id);
		return -EINVAL;
	}

	pr_info("IO queue created (depth=%u, sq_id=%u, cq_id=%u)\n", io_queue->depth, sq_id, cq_id);

	configure_queue(mx_pdev, io_queue, cq_id);

	io_queue->common.ops = &v2_queue_ops;
	spin_lock_init(&io_queue->common.sq_lock);
	INIT_LIST_HEAD(&io_queue->common.sq_list);
	init_swait_queue_head(&io_queue->common.sq_wait);
	init_swait_queue_head(&io_queue->common.cq_wait);
	atomic_set(&io_queue->common.wait_count, 0);

	mx_pdev->submit_thread = kthread_run(mx_submit_handler, &io_queue->common, "mx_submit_thd%d", mx_pdev->dev_id);
	if (IS_ERR(mx_pdev->submit_thread)) {
		pr_err("Failed to create submit thread (err=%ld)\n", PTR_ERR(mx_pdev->submit_thread));
		return PTR_ERR(mx_pdev->submit_thread);
	}
	mx_pdev->complete_thread = kthread_run(mx_complete_handler, &io_queue->common, "mx_complete_thd%d", mx_pdev->dev_id);
	if (IS_ERR(mx_pdev->complete_thread)) {
		pr_err("Failed to create complete thread (err=%ld)\n", PTR_ERR(mx_pdev->complete_thread));
		kthread_stop(mx_pdev->submit_thread);
		return PTR_ERR(mx_pdev->complete_thread);
	}

	mx_pdev->io_queue = (struct mx_queue *)io_queue;

	return 0;
}

static int release_io_queue(struct mx_pci_dev *mx_pdev)
{
	struct mx_queue_v2 *admin_queue = (struct mx_queue_v2 *)mx_pdev->admin_queue;
	struct mx_queue_v2 *io_queue = (struct mx_queue_v2 *)mx_pdev->io_queue;
	struct mx_command comm = {};
	int ret;

	if (!admin_queue || !io_queue)
		return 0;

	comm.opcode = ADMIN_OPCODE_DELETE_IO_CQ;
	comm.io_queue_info.cq_id = io_queue->qid;
	do {
		ret = submit_sync_command(admin_queue, &comm, NULL);
	} while (ret == -EAGAIN);
	if (ret) {
		pr_err("Failed to delete IO completion queue (err=%d)\n", ret);
		return ret;
	}

	comm.opcode = ADMIN_OPCODE_DELETE_IO_SQ;
	comm.io_queue_info.sq_id = io_queue->qid;
	do {
		ret = submit_sync_command(admin_queue, &comm, NULL);
	} while (ret == -EAGAIN);
	if (ret) {
		pr_err("Failed to delete IO submission queue (err=%d)\n", ret);
		return ret;
	}

	mx_stop_queue_threads(mx_pdev);

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

