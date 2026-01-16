// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

unsigned int timeout_ms = 60000; /* 60 seconds */
module_param(timeout_ms, int, 0644);
unsigned int parallel_count = 6;
module_param(parallel_count, int, 0644);

/******************************************************************************/
/* Functions for DMA                                                          */
/******************************************************************************/
static void unmap_user_addr_to_sg(struct device *dev, struct mx_transfer *transfer)
{
	struct sg_table *sgt = &transfer->sgt;
	int i;

	if (sgt->nents)
		dma_unmap_sg(dev, sgt->sgl, sgt->nents, transfer->dir);

	if (transfer->dir == DMA_FROM_DEVICE) {
		for (i = 0; i < transfer->pages_nr; i++) {
			struct page *page = transfer->pages[i];
			if (!page)
				break;
			set_page_dirty_lock(page);
		}
	}

	if (transfer->pages_nr > 0)
		unpin_user_pages(transfer->pages, transfer->pages_nr);

	sg_free_table(&transfer->sgt);

	if (transfer->pages) {
		kfree(transfer->pages);
		transfer->pages = NULL;
	}
}

static int map_user_addr_to_sg(struct device *dev, struct mx_transfer *transfer)
{
	struct sg_table *sgt = &transfer->sgt;
	void __user *user_addr = transfer->user_addr;
	size_t size = transfer->size;
	unsigned int pages_nr;
	unsigned int offset;
	unsigned int gup_flags = 0;
	long pinned;
	int ret;

	offset = offset_in_page((unsigned long)user_addr);
	pages_nr = DIV_ROUND_UP(offset + size, PAGE_SIZE);
	if (!pages_nr)
		return 0;

	transfer->pages = kcalloc(pages_nr, sizeof(struct page *), GFP_KERNEL);
	if (!transfer->pages) {
		pr_warn("Failed to alloc pages\n");
		return -ENOMEM;
	}

	/* Pin user_addr to pages */
	if (transfer->dir == DMA_FROM_DEVICE || transfer->dir == DMA_BIDIRECTIONAL)
		gup_flags |= FOLL_WRITE;

	pinned = pin_user_pages_fast((unsigned long)user_addr, pages_nr, gup_flags, transfer->pages);
	if (pinned < 0) {
		pr_warn("pin_user_pages_fast failed (err=%ld)\n", pinned);
		kfree(transfer->pages);
		transfer->pages = NULL;
		return (int)pinned;
	}
	if (pinned != pages_nr) {
		pr_warn("pin_user_pages_fast partial (req=%u, got=%ld)\n", pages_nr, pinned);
		if (pinned > 0)
			unpin_user_pages(transfer->pages, pinned);
		kfree(transfer->pages);
		transfer->pages = NULL;
		return -EFAULT;
	}
	transfer->pages_nr = pages_nr;

	/* Alloc sg_table as pages_nr */
	ret = sg_alloc_table_from_pages(sgt, transfer->pages, pages_nr, offset, size, GFP_KERNEL);
	if (ret) {
		pr_warn("sg_alloc_table_from_pages failed (err=%d)\n", ret);
		unpin_user_pages(transfer->pages, transfer->pages_nr);
		transfer->pages_nr = 0;
		return ret;
	}

	/* Map the given buffer for DMA */
	sgt->nents = dma_map_sg(dev, sgt->sgl, sgt->orig_nents, transfer->dir);
	if (!sgt->nents) {
		sg_free_table(sgt);
		unpin_user_pages(transfer->pages, transfer->pages_nr);
		pr_warn("Failed to dma_map_sg\n");
		return -EIO;
	}

	return 0;
}

/******************************************************************************/
/* MX Transfer                                                                */
/******************************************************************************/
static void desc_list_free(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer)
{
	int i;

	if (transfer->desc_list_va) {
		for (i = 0; i < transfer->desc_list_cnt; i++) {
			if (transfer->desc_list_va[i])
				dma_pool_free(mx_pdev->page_pool, transfer->desc_list_va[i], transfer->desc_list_ba[i]);
		}
		kfree(transfer->desc_list_va);
		transfer->desc_list_va = NULL;
	}

	if (transfer->desc_list_ba) {
		kfree(transfer->desc_list_ba);
		transfer->desc_list_ba = NULL;
	}
}

int desc_list_alloc(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int list_cnt)
{
	int i;

	transfer->desc_list_cnt = list_cnt;
	transfer->desc_list_va = kcalloc(list_cnt, sizeof(void *), GFP_KERNEL);
	if (!transfer->desc_list_va) {
		pr_warn("Failed to allocate desc_list_va\n");
		return -ENOMEM;
	}

	transfer->desc_list_ba = kcalloc(list_cnt, sizeof(dma_addr_t), GFP_KERNEL);
	if (!transfer->desc_list_ba) {
		pr_warn("Failed to allocate desc_list_ba\n");
		kfree(transfer->desc_list_va);
		transfer->desc_list_va = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < list_cnt; i++) {
		void *cpu_addr;
		dma_addr_t bus_addr;

		cpu_addr = dma_pool_alloc(mx_pdev->page_pool, GFP_ATOMIC, &bus_addr);
		if (!cpu_addr)
			goto fail;

		transfer->desc_list_va[i] = cpu_addr;
		transfer->desc_list_ba[i] = bus_addr;
	}

	return 0;

fail:
	desc_list_free(mx_pdev, transfer);
	pr_warn("Failed to dma_pool_alloc\n");

	return -ENOMEM;
}

static void release_mx_transfer(struct mx_transfer *transfer)
{
	transfer_id_free(transfer->id);
	kfree(transfer->command);
	kfree(transfer);
}

static struct mx_transfer *alloc_mx_transfer(char __user *user_addr, size_t size, uint64_t device_addr,
		enum dma_data_direction dir)
{
	struct mx_transfer *transfer;

	transfer = kzalloc(sizeof(struct mx_transfer), GFP_KERNEL);
	if (!transfer) {
		return NULL;
	}

	INIT_LIST_HEAD(&transfer->entry);
	INIT_LIST_HEAD(&transfer->zombie_entry);

	transfer->id = transfer_id_alloc(transfer);
	if (transfer->id < 0) {
		pr_warn("Failed to alloc transfer_id\n");
		kfree(transfer);
		return NULL;
	}

	transfer->user_addr = user_addr;
	transfer->size = size;
	transfer->device_addr = device_addr;
	transfer->dir = dir;

	return transfer;
}

static struct mx_transfer **alloc_mx_transfers(void __user *user_addr, size_t total_size,
		uint64_t device_addr, enum dma_data_direction dir, int pages_nr, int count)
{
	struct mx_transfer **transfer;
	int q, r;
	int i;

	transfer = kcalloc(count, sizeof(struct mx_transfer *), GFP_KERNEL);
	if (!transfer) {
		pr_warn("Failed to alloc parallel mx_transfer\n");
		return NULL;
	}

	q = pages_nr / count;
	r = pages_nr % count;

	for (i = 0; i < count; i++) {
		int num = (r-- > 0) ? q + 1 : q;
		uint64_t end_addr = ((uint64_t)user_addr + num * PAGE_SIZE) & PAGE_MASK;
		size_t size = min_t(size_t, end_addr - (uint64_t)user_addr, total_size);

		transfer[i] = alloc_mx_transfer(user_addr, size, device_addr, dir);
		if (!transfer[i]) {
			pr_warn("Failed to alloc mx_transfer[%d]\n", i);
			goto fail;
		}
		user_addr = (void __user *)((uint64_t)user_addr + size);
		total_size -= size;
		device_addr += size;
	}

	return transfer;

fail:
	for (i = 0; i < count; i++) {
		if (transfer[i])
			release_mx_transfer(transfer[i]);
	}
	kfree(transfer);
	return NULL;
}

static void mx_transfer_queue(struct mx_queue *queue, struct mx_transfer *transfer)
{
	unsigned long flags;

	init_completion(&transfer->done);

	spin_lock_irqsave(&queue->sq_lock, flags);
	list_add_tail(&transfer->entry, &queue->sq_list);
	spin_unlock_irqrestore(&queue->sq_lock, flags);
	swake_up_one(&queue->sq_wait);
}

static void mx_transfer_queue_parallel(struct mx_queue *queue, struct mx_transfer **transfers, int count)
{
	unsigned long flags;
	int i;

	for (i = 0; i < count; i++)
		init_completion(&transfers[i]->done);

	spin_lock_irqsave(&queue->sq_lock, flags);
	for (i = 0; i < count; i++)
		list_add_tail(&transfers[i]->entry, &queue->sq_list);
	spin_unlock_irqrestore(&queue->sq_lock, flags);
	swake_up_one(&queue->sq_wait);
}

static bool mx_transfer_remove_from_sq(struct mx_queue *queue, struct mx_transfer *transfer)
{
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&queue->sq_lock, flags);
	if (!list_empty(&transfer->entry)) {
		list_del_init(&transfer->entry);
		found = true;
	}
	spin_unlock_irqrestore(&queue->sq_lock, flags);

	return found;
}

static void mx_transfer_destroy_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer);
static int mx_transfer_destroy_ctrl(struct mx_transfer *transfer);
static ssize_t mx_transfer_wait(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer)
{
	unsigned long left_time;

	left_time = wait_for_completion_interruptible_timeout(&transfer->done, msecs_to_jiffies(timeout_ms));
	if ((long)left_time <= 0) {
		unsigned long flags;

		if (left_time == 0)
			pr_warn("wait_for_completion is timeout (id=%u, size=%#llx, dir=%u, timeout=%u ms)\n",
					transfer->id, (uint64_t)transfer->size, transfer->dir, timeout_ms);
		else
			pr_warn("wait_for_completion is interrupted (id=%u, size=%#llx, dir=%u)\n",
					transfer->id, (uint64_t)transfer->size, transfer->dir);

		if (mx_transfer_remove_from_sq(mx_pdev->io_queue, transfer))
			return 0;

		/* Mark as zombie - device might still be accessing memory */
		transfer->zombie_timestamp = jiffies;

		spin_lock_irqsave(&mx_pdev->zombie_lock, flags);
		list_add_tail(&transfer->zombie_entry, &mx_pdev->zombie_list);
		spin_unlock_irqrestore(&mx_pdev->zombie_lock, flags);

		return 0;
	}

	if (transfer->is_sg)
		mx_transfer_destroy_sg(mx_pdev, transfer);
	else
		mx_transfer_destroy_ctrl(transfer);

	return transfer->size;
}

static void mx_transfer_wait_work(struct work_struct *work)
{
	struct mx_transfer *transfer = container_of(work, struct mx_transfer, work);
	struct mx_pci_dev *mx_pdev = transfer->mx_pdev;

	mx_transfer_wait(mx_pdev, transfer);
}

static int mx_transfer_init_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int opcode)
{
	struct device *dev = &mx_pdev->pdev->dev;
	int ret;

	ret = map_user_addr_to_sg(dev, transfer);
	if (ret)
		return ret;

	transfer->command = mx_pdev->ops.create_command_sg(mx_pdev, transfer, opcode);
	if (!transfer->command) {
		pr_warn("Failed to create_command_sg (id=%u)\n", transfer->id);
		unmap_user_addr_to_sg(dev, transfer);
		return -ENOMEM;
	}

	transfer->mx_pdev = mx_pdev;
	transfer->is_sg = true;
	INIT_WORK(&transfer->work, mx_transfer_wait_work);

	return 0;
}

static void mx_transfer_destroy_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer)
{
	struct device *dev = &mx_pdev->pdev->dev;

	unmap_user_addr_to_sg(dev, transfer);
	desc_list_free(mx_pdev, transfer);
	release_mx_transfer(transfer);
}

static ssize_t mx_transfer_submit_sg(struct mx_pci_dev *mx_pdev,
		struct mx_transfer *transfer, int opcode, bool nowait)
{
	size_t size = transfer->size;
	ssize_t ret;

	ret = mx_transfer_init_sg(mx_pdev, transfer, opcode);
	if (ret < 0) {
		release_mx_transfer(transfer);
		return ret;
	}

	mx_transfer_queue(mx_pdev->io_queue, transfer);
	if (nowait) {
		schedule_work(&transfer->work);
		return size;
	}

	return mx_transfer_wait(mx_pdev, transfer);
}

static ssize_t mx_transfer_submit_sg_parallel(struct mx_pci_dev *mx_pdev,
		struct mx_transfer **transfers, int opcode, int count, bool nowait)
{
	int initialized_count = 0;
	ssize_t transferred = 0;
	size_t total_size = 0;
	int ret = 0;
	int i;

	for (i = 0; i < count; i++) {
		ret = mx_transfer_init_sg(mx_pdev, transfers[i], opcode);
		if (ret < 0)
			break;
		total_size += transfers[i]->size;
		initialized_count++;
	}

	if (ret < 0) {
		for (i = 0; i < initialized_count; i++)
			mx_transfer_destroy_sg(mx_pdev, transfers[i]);

		for (i = initialized_count; i < count; i++)
			release_mx_transfer(transfers[i]);

		kfree(transfers);
		return ret;
	}

	mx_transfer_queue_parallel(mx_pdev->io_queue, transfers, count);

	if (nowait) {
		for (i = 0; i < count; i++)
			schedule_work(&transfers[i]->work);
		kfree(transfers);
		return total_size;
	}

	for (i = 0; i < count; i++)
		transferred += mx_transfer_wait(mx_pdev, transfers[i]);

	kfree(transfers);
	return transferred;
}

static int mx_transfer_init_ctrl(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int opcode)
{
	transfer->command = mx_pdev->ops.create_command_ctrl(transfer, opcode);
	if (!transfer->command)
		return -ENOMEM;

	transfer->mx_pdev = mx_pdev;
	transfer->is_sg = false;
	INIT_WORK(&transfer->work, mx_transfer_wait_work);

	return 0;
}

static int mx_transfer_destroy_ctrl(struct mx_transfer *transfer)
{
	int ret = 0;

	if (transfer->dir == DMA_FROM_DEVICE) {
		if (access_ok(transfer->user_addr, transfer->size)) {
			ret = copy_to_user(transfer->user_addr, &transfer->result, sizeof(uint64_t));
			if (ret)
				pr_warn("Failed to copy_to_user (id=%u, %llx -> %llx, err=%d)\n",
						transfer->id, (uint64_t)&transfer->result, (uint64_t)transfer->user_addr, ret);
		} else {
			*(uint64_t *)transfer->user_addr = transfer->result;
		}
	}

	release_mx_transfer(transfer);

	return ret;
}

static ssize_t mx_transfer_submit_ctrl(struct mx_pci_dev *mx_pdev,
		struct mx_transfer *transfer, int opcode, bool nowait)
{
	size_t size = transfer->size;
	ssize_t ret;

	ret = mx_transfer_init_ctrl(mx_pdev, transfer, opcode);
	if (ret < 0) {
		release_mx_transfer(transfer);
		return ret;
	}

	mx_transfer_queue(mx_pdev->io_queue, transfer);
	if (nowait) {
		schedule_work(&transfer->work);
		return size;
	}

	return mx_transfer_wait(mx_pdev, transfer);
}

/******************************************************************************/
/* Functions for fops                                                         */
/******************************************************************************/
ssize_t read_data_from_device(struct mx_pci_dev *mx_pdev,
		char __user *user_addr, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer *transfer;

	transfer = alloc_mx_transfer(user_addr, size, *fpos, DMA_FROM_DEVICE);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer for read\n");
		return -ENOMEM;
	}

	return mx_transfer_submit_sg(mx_pdev, transfer, opcode, false);
}

ssize_t write_data_to_device(struct mx_pci_dev *mx_pdev,
		const char __user *user_addr, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer *transfer;

	transfer = alloc_mx_transfer((char __user *)user_addr, size, *fpos, DMA_TO_DEVICE);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer for write\n");
		return -ENOMEM;
	}

	return mx_transfer_submit_sg(mx_pdev, transfer, opcode, nowait);
}

ssize_t read_data_from_device_parallel(struct mx_pci_dev *mx_pdev,
		char __user *buf, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer **transfers;
	uint64_t first_page_index, last_page_index;
	int nr_pages, count;

	first_page_index = (uint64_t)buf >> PAGE_SHIFT;
	last_page_index = ((uint64_t)buf + size - 1) >> PAGE_SHIFT;
	nr_pages = last_page_index - first_page_index + 1;
	count = min_t(int, nr_pages, parallel_count);

	if (count == 1)
		return read_data_from_device(mx_pdev, buf, size, fpos, opcode);

	transfers = alloc_mx_transfers(buf, size, *fpos, DMA_FROM_DEVICE, nr_pages, count);
	if (!transfers) {
		pr_warn("Failed to alloc parallel mx_transfers for read (count=%d)\n", count);
		return -ENOMEM;
	}

	return mx_transfer_submit_sg_parallel(mx_pdev, transfers, opcode, count, false);
}

ssize_t write_data_to_device_parallel(struct mx_pci_dev *mx_pdev,
		const char __user *buf, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer **transfers;
	uint64_t first_page_index, last_page_index;
	int nr_pages, count;

	first_page_index = (uint64_t)buf >> PAGE_SHIFT;
	last_page_index = ((uint64_t)buf + size - 1) >> PAGE_SHIFT;
	nr_pages = last_page_index - first_page_index + 1;
	count = min_t(int, nr_pages, parallel_count);

	if (count == 1)
		return write_data_to_device(mx_pdev, buf, size, fpos, opcode, nowait);

	transfers = alloc_mx_transfers((char __user *)buf, size, *fpos, DMA_TO_DEVICE, nr_pages, count);
	if (!transfers) {
		pr_warn("Failed to alloc parallel mx_transfers for write (count=%d)\n", count);
		return -ENOMEM;
	}

	return mx_transfer_submit_sg_parallel(mx_pdev, transfers, opcode, count, nowait);
}

ssize_t read_ctrl_from_device(struct mx_pci_dev *mx_pdev,
		char __user *user_addr, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer *transfer;

	transfer = alloc_mx_transfer(user_addr, size, *fpos, DMA_FROM_DEVICE);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer for read_ctrl\n");
		return -ENOMEM;
	}

	return mx_transfer_submit_ctrl(mx_pdev, transfer, opcode, false);
}

ssize_t write_ctrl_to_device(struct mx_pci_dev *mx_pdev,
		const char __user *user_addr, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer *transfer;

	transfer = alloc_mx_transfer((char __user *)user_addr, size, *fpos, DMA_TO_DEVICE);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer for write_ctrl\n");
		return -ENOMEM;
	}

	return mx_transfer_submit_ctrl(mx_pdev, transfer, opcode, nowait);
}

/******************************************************************************/
/* Zombie Transfer Cleanup                                                   */
/******************************************************************************/
int zombie_cleanup_handler(void *data)
{
	struct mx_pci_dev *mx_pdev = data;
	struct mx_transfer *transfer, *tmp;
	unsigned long grace_period = msecs_to_jiffies(300000); /* 5 minutes */
	unsigned long flags;
	LIST_HEAD(to_cleanup);

	while (!kthread_should_stop()) {
		/* Wait for zombie addition or periodic check */
		wait_event_interruptible_timeout(mx_pdev->zombie_wq,
				kthread_should_stop() || !list_empty(&mx_pdev->zombie_list),
				msecs_to_jiffies(1000)); /* 1 second */

		if (kthread_should_stop())
			break;

		/* Check and collect zombies that exceeded grace period */
		spin_lock_irqsave(&mx_pdev->zombie_lock, flags);
		list_for_each_entry_safe(transfer, tmp, &mx_pdev->zombie_list, zombie_entry) {
			if (completion_done(&transfer->done)) {
				pr_info("Zombie transfer completed (id=%u)\n", transfer->id);
				list_del(&transfer->zombie_entry);
				list_add_tail(&transfer->zombie_entry, &to_cleanup);
			} else if (time_after(jiffies, transfer->zombie_timestamp + grace_period)) {
				pr_err("Zombie transfer timeout (id=%u) - device not responding\n", transfer->id);
				list_del(&transfer->zombie_entry);
				list_add_tail(&transfer->zombie_entry, &to_cleanup);
			}
		}
		spin_unlock_irqrestore(&mx_pdev->zombie_lock, flags);

		list_for_each_entry_safe(transfer, tmp, &to_cleanup, zombie_entry) {
			list_del(&transfer->zombie_entry);

			/* Ensure any pending work is canceled to avoid UAF */
			cancel_work_sync(&transfer->work);

			if (transfer->is_sg) {
				unmap_user_addr_to_sg(&mx_pdev->pdev->dev, transfer);
				desc_list_free(mx_pdev, transfer);
			}

			release_mx_transfer(transfer);
		}
	}

	return 0;
}
