// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

/******************************************************************************/
/* Descriptor list utilities                                                  */
/******************************************************************************/
int mx_get_list_count(int total_desc_cnt, int descs_per_list)
{
	int list_cnt = 1;

	while (total_desc_cnt > descs_per_list) {
		total_desc_cnt -= (descs_per_list - 1);
		list_cnt++;
	}

	return list_cnt;
}

int mx_get_total_desc_count(struct sg_table *sgt, size_t dma_size,
			    bool skip_first)
{
	struct scatterlist *sg = sgt->sgl;
	int total_desc_cnt = 0;
	int i;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		int len = sg_dma_len(sg);
		int desc_cnt = (len + dma_size - 1) / dma_size;

		total_desc_cnt += desc_cnt;
	}

	if (skip_first)
		total_desc_cnt--;

	return total_desc_cnt;
}

uint64_t mx_desc_list_init(struct mx_pci_dev *mx_pdev,
			   struct mx_transfer *transfer, size_t dma_size,
			   int descs_per_list, bool skip_first_entry)
{
	struct sg_table *sgt = &transfer->sgt;
	struct scatterlist *sg = sgt->sgl;
	uint64_t *desc;
	int total_desc_cnt, list_cnt, list_idx, desc_idx;
	int ret;
	int i;

	total_desc_cnt = mx_get_total_desc_count(sgt, dma_size, skip_first_entry);
	list_cnt = mx_get_list_count(total_desc_cnt, descs_per_list);
	ret = desc_list_alloc(mx_pdev, transfer, list_cnt);
	if (ret) {
		pr_warn("Failed to desc_list_alloc (err=%d)\n", ret);
		return 0;
	}

	list_idx = 0;
	desc_idx = 0;
	desc = (uint64_t *)transfer->desc_list_va[list_idx];

	for_each_sgtable_dma_sg(sgt, sg, i) {
		dma_addr_t dma_addr = sg_dma_address(sg);
		ssize_t dma_len = sg_dma_len(sg);
		ssize_t offset = sg->offset;
		ssize_t len = dma_size;

		if (offset) {
			ssize_t tmp = (PAGE_SIZE - offset) & (dma_size - 1);
			if (tmp != 0)
				len = tmp;
		}

		if (skip_first_entry && i == 0) {
			dma_addr += len;
			dma_len -= len;
			len = min_t(ssize_t, dma_len, dma_size);
		}

		while (dma_len > 0) {
			if (desc_idx == descs_per_list - 1 && total_desc_cnt > 1) {
				desc[desc_idx] = (uint64_t)transfer->desc_list_ba[++list_idx];
				desc = (uint64_t *)transfer->desc_list_va[list_idx];
				desc_idx = 0;
			}

			desc[desc_idx++] = dma_addr;
			dma_addr += len;
			dma_len -= len;
			len = min_t(ssize_t, dma_len, dma_size);
			total_desc_cnt--;
		}
	}

	return transfer->desc_list_ba[0];
}

/******************************************************************************/
/* Thread helpers                                                             */
/******************************************************************************/
void mx_stop_queue_threads(struct mx_pci_dev *mx_pdev)
{
	int ret;

	if (!IS_ERR_OR_NULL(mx_pdev->submit_thread)) {
		ret = kthread_stop(mx_pdev->submit_thread);
		if (ret)
			pr_err("submit_thread thread doesn't stop properly (err=%d)\n", ret);
	}

	if (!IS_ERR_OR_NULL(mx_pdev->complete_thread)) {
		ret = kthread_stop(mx_pdev->complete_thread);
		if (ret)
			pr_err("complete_thread thread doesn't stop properly (err=%d)\n", ret);
	}
}

/******************************************************************************/
/* Unified submit/complete handlers                                           */
/******************************************************************************/
int mx_submit_handler(void *arg)
{
	struct mx_queue *q = (struct mx_queue *)arg;
	const struct mx_queue_ops *ops = q->ops;
	struct mx_transfer *transfer, *tmp;
	unsigned long flags;

	while (!kthread_should_stop()) {
		__swait_event_interruptible_timeout(q->sq_wait,
				!list_empty(&q->sq_list),
				POLLING_INTERVAL_MSEC);

		spin_lock_irqsave(&q->sq_lock, flags);
		list_for_each_entry_safe(transfer, tmp, &q->sq_list, entry) {
			if (!ops->is_pushable(q))
				break;

			ops->push_command(q, transfer->command);
			list_del_init(&transfer->entry);

			atomic_inc(&q->wait_count);
			swake_up_one(&q->cq_wait);
		}
		spin_unlock_irqrestore(&q->sq_lock, flags);

		if (ops->post_submit)
			ops->post_submit(q);
	}

	return 0;
}

int mx_complete_handler(void *arg)
{
	struct mx_queue *q = (struct mx_queue *)arg;
	const struct mx_queue_ops *ops = q->ops;
	struct mx_transfer *transfer;
	int id;
	uint64_t result;

	while (!kthread_should_stop()) {
		__swait_event_interruptible_timeout(q->cq_wait,
				atomic_read(&q->wait_count) > 0,
				POLLING_INTERVAL_MSEC);

		while (ops->is_popable(q)) {
			ops->pop_completion(q, &id, &result);

			transfer = find_transfer_by_id(id);
			if (!transfer)
				continue;

			atomic_dec(&q->wait_count);
			transfer->result = result;
			complete(&transfer->done);
		}

		if (ops->post_complete)
			ops->post_complete(q);
	}

	return 0;
}
