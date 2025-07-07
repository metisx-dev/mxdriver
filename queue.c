// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/atomic.h>

#include "mx_dma.h"

static bool is_cqe_pending(struct mx_queue *queue)
{
	struct mx_completion *cqe = &queue->cqes[queue->cq_head];

	return (le16_to_cpu(READ_ONCE(cqe->status)) & 1) == queue->cq_phase;
}

static bool is_sqe_full(struct mx_queue *queue)
{
	return (queue->sq_tail + 1) % queue->depth == queue->sq_head;
}

void *get_sqe_ptr(struct mx_queue *queue)
{
	if (is_sqe_full(queue))
		return NULL;

	return &queue->sqes[queue->sq_tail];
}

void *get_cqe_ptr(struct mx_queue *queue)
{
	if (!is_cqe_pending(queue))
		return NULL;

	return &queue->cqes[queue->cq_head];
}

void update_sq_doorbell(struct mx_queue *queue)
{
	uint32_t next_tail = queue->sq_tail + 1;

	if (next_tail == queue->depth)
		queue->sq_tail = 0;
	else
		queue->sq_tail = next_tail;
}

void update_cq_doorbell(struct mx_queue *queue)
{
	uint32_t next_head = queue->cq_head + 1;

	if (next_head == queue->depth) {
		queue->cq_head = 0;
		queue->cq_phase ^= 1;
	} else {
		queue->cq_head = next_head;
	}
}

void ring_sq_doorbell(struct mx_queue *queue)
{
	if (queue->last_sq_tail == queue->sq_tail)
		return;

	writel(queue->sq_tail, queue->db);
	queue->last_sq_tail = queue->sq_tail;
}

void ring_cq_doorbell(struct mx_queue *queue)
{
	writel(queue->cq_head, queue->db + sizeof(uint32_t));
}

