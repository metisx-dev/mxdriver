// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

unsigned int timeout_ms = 60 * 1000;
module_param(timeout_ms, int, 0644);
unsigned int parallel_count = 2;
module_param(parallel_count, int, 0644);

#define POLLING_INTERVAL_MSEC	4

/******************************************************************************/
/* Functions for DMA                                                          */
/******************************************************************************/
static void desc_list_free(struct device *dev, struct mx_transfer *transfer)
{
	struct mx_pci_dev *mx_pdev = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < transfer->desc_list_cnt; i++) {
		if (transfer->desc_list_va[i])
			dma_pool_free(mx_pdev->page_pool, transfer->desc_list_va[i], transfer->desc_list_ba[i]);
	}

	if (transfer->desc_list_va)
		devm_kfree(dev, transfer->desc_list_va);
	if (transfer->desc_list_ba)
		devm_kfree(dev, transfer->desc_list_ba);
}

static int desc_list_alloc(struct device *dev, struct mx_transfer *transfer, int list_cnt)
{
	struct mx_pci_dev *mx_pdev = dev_get_drvdata(dev);
	int i;

	transfer->desc_list_cnt = list_cnt;
	transfer->desc_list_va = devm_kcalloc(dev, list_cnt, sizeof(void *), GFP_KERNEL);
	transfer->desc_list_ba = devm_kcalloc(dev, list_cnt, sizeof(dma_addr_t), GFP_KERNEL);

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
	desc_list_free(dev, transfer);
	pr_warn("Failed to dma_alloc_coherent\n");

	return -ENOMEM;
}

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
				if (sg_next(sg) != NULL || dma_size > SINGLE_DMA_SIZE) {
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

static ssize_t sg_set_pages(struct scatterlist *sg, struct page **pages, int pages_nr,
		ssize_t size, void __user *user_addr)
{
	struct page *page;
	unsigned int offset, nbytes;
	int i;

	for (i = 0; i < pages_nr; i++) {
		page = pages[i];
		offset = offset_in_page(user_addr);
		nbytes = min_t(unsigned int, PAGE_SIZE - offset, size);

		flush_dcache_page(page);
		sg_set_page(sg, page, nbytes, offset);

		user_addr += nbytes;
		size -= nbytes;
		sg = sg_next(sg);
	}

	return size;
}

static void unmap_user_addr_to_sg(struct device *dev, struct mx_transfer *transfer)
{
	struct sg_table *sgt = &transfer->sgt;
	struct page *page;
	int i;

	if (sgt->nents)
		dma_unmap_sg(dev, sgt->sgl, sgt->orig_nents, transfer->dir);

	for (i = 0; i < transfer->pages_nr; i++) {
		page = transfer->pages[i];
		if (!page)
			break;

		if (transfer->dir == DMA_FROM_DEVICE)
			set_page_dirty_lock(page);

		put_page(page);
	}

	sg_free_table(&transfer->sgt);

	if (transfer->pages) {
		devm_kfree(dev, transfer->pages);
		transfer->pages = NULL;
	}
}

static int map_user_addr_to_sg(struct device *dev, struct mx_transfer *transfer)
{
	struct sg_table *sgt = &transfer->sgt;
	void __user *user_addr = transfer->user_addr;
	size_t size = transfer->size;
	int pages_nr;
	int ret;

	/* Calculate pages_nr and alloc pages as pages_nr*/
	pages_nr = (offset_in_page(user_addr) + size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (!pages_nr)
		return 0;

	transfer->pages = devm_kcalloc(dev, pages_nr, sizeof(struct page *), GFP_KERNEL);
	if (!transfer->pages) {
		pr_warn("Failed to alloc pages\n");
		return -ENOMEM;
	}

	/* Pin user_addr to pages */
	transfer->pages_nr = get_user_pages_fast((unsigned long)user_addr, pages_nr,
			FOLL_WRITE, transfer->pages);
	if (transfer->pages_nr < pages_nr) {
		pr_warn("Failed to get_user_pages_fast (request=%d, success=%d)\n",
				pages_nr, transfer->pages_nr);
		return -EFAULT;
	}

	/* Alloc sg_table as pages_nr */
	ret = sg_alloc_table(sgt, pages_nr, GFP_KERNEL);
	if (ret) {
		pr_warn("Failed to sg_alloc_table (err=%d)\n", ret);
		return ret;
	}

	/* Set pinned page to SG entried */
	size = sg_set_pages(sgt->sgl, transfer->pages, pages_nr, size, user_addr);
	if (size) {
		pr_warn("Failed to sg_set_pages\n");
		return -EINVAL;
	}

	/* Map the given buffer for DMA */
	sgt->nents = dma_map_sg(dev, sgt->sgl, sgt->orig_nents, transfer->dir);
	if (!sgt->nents) {
		pr_warn("Failed to dma_map_sg\n");
		return -EIO;
	}

	return 0;
}

/******************************************************************************/
/* MX Transfer                                                                */
/******************************************************************************/
static int mx_command_init_common(struct mx_transfer *transfer, int opcode)
{
	struct mx_command *comm = &transfer->command;
	int id;

	id = transfer_id_alloc(transfer);
	if (id < 0) {
		pr_warn("Failed to trasfer_id_alloc (err=%d)\n", id);
		return -ENOMEM;
	}

	comm->opcode = opcode;
	comm->command_id = id;
	comm->flags = 0;
	comm->size = transfer->size;
	comm->device_addr = transfer->device_addr;

	if (transfer->nowait)
		comm->flags |= (1 << IO_FLAGS_NOWAIT);

	return 0;
}

static int mx_command_init_sg(struct device *dev, struct mx_transfer *transfer)
{
	struct mx_command *comm = &transfer->command;
	struct sg_table *sgt = &transfer->sgt;
	struct scatterlist *sg = sgt->sgl;
	unsigned int size = (PAGE_SIZE - sg->offset) % SINGLE_DMA_SIZE;

	size = size ? size : SINGLE_DMA_SIZE;

	if (transfer->size <= size) {
		comm->host_addr = sg_dma_address(sg);
		if (!comm->host_addr) {
			pr_warn("Failed to get sg_dma_address\n");
			return -ENOMEM;
		}
	} else {
		comm->flags = (1 << IO_FLAGS_PRP);
		comm->prp_entry1 = desc_list_init(dev, transfer);
		if (!comm->prp_entry1) {
			pr_warn("Failed to desc_list_init\n");
			return -ENOMEM;
		}
	}

	return 0;
}

static int mx_transfer_init_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer, int opcode)
{
	struct device *dev = &mx_pdev->pdev->dev;
	int ret;

	ret = map_user_addr_to_sg(dev, transfer);
	if (ret) {
		pr_warn("Failed to map_user_addr_to_sg (err=%d)\n", ret);
		return ret;
	}

	ret = mx_command_init_common(transfer, opcode);
	if (ret) {
		pr_warn("Failed to init mx_command for common (err=%d)\n", ret);
		return ret;
	}

	ret = mx_command_init_sg(dev, transfer);
	if (ret) {
		pr_warn("Failed to init mx_command for sg (err=%d)\n", ret);
		return ret;
	}

	return 0;
}

static void mx_transfer_destroy_sg(struct mx_pci_dev *mx_pdev, struct mx_transfer *transfer)
{
	struct device *dev = &mx_pdev->pdev->dev;

	transfer_id_free(transfer->command.command_id);
	desc_list_free(dev, transfer);
	unmap_user_addr_to_sg(dev, transfer);
}

static int mx_transfer_init_ctrl(struct mx_transfer *transfer, int opcode)
{
	uint64_t value = 0;
	int ret;

	ret = mx_command_init_common(transfer, opcode);
	if (ret) {
		pr_warn("Failed to init mx_command for common (err=%d)\n", ret);
		return ret;
	}

	if (transfer->dir != DMA_TO_DEVICE)
		return 0;

	ret = copy_from_user(&value, transfer->user_addr, transfer->size);
	if (ret) {
		pr_warn("Failed to copy_from_user (err=%d)\n", ret);
		return ret;
	}
	transfer->command.doorbell_value = value;

	return 0;
}

static int mx_transfer_destroy_ctrl(struct mx_transfer *transfer)
{
	uint64_t value;
	int ret;

	transfer_id_free(transfer->command.command_id);

	if (transfer->dir != DMA_FROM_DEVICE)
		return 0;

	value = transfer->result;
	ret = copy_to_user(transfer->user_addr, &value, transfer->size);
	if (ret)
		pr_warn("Failed to copy_to_user (err=%d)\n", ret);

	return ret;
}

static void mx_transfer_queue(struct mx_queue *queue, struct mx_transfer *transfer)
{
	unsigned long flags;

	init_completion(&transfer->done);

	spin_lock_irqsave(&queue->sq_lock, flags);
	list_add_tail(&transfer->entry, &queue->sq_list);
	spin_unlock_irqrestore(&queue->sq_lock, flags);
}

static ssize_t mx_transfer_wait(struct mx_transfer *transfer)
{
	unsigned long left_time;

	left_time = wait_for_completion_timeout(&transfer->done, msecs_to_jiffies(timeout_ms));
	if (left_time == 0) {
		pr_warn("wait_for_completion is timeout\n");
		return -ETIMEDOUT;
	}

	return transfer->size;
}

static ssize_t mx_transfer_submit_sg(struct mx_pci_dev *mx_pdev,
		struct mx_transfer *transfer, int opcode)
{
	ssize_t ret;

	ret = mx_transfer_init_sg(mx_pdev, transfer, opcode);
	if (ret < 0) {
		pr_warn("Failed to init mx_transfer (err=%ld)\n", ret);
		goto out;
	}

	mx_transfer_queue(&mx_pdev->io_queue, transfer);
	ret = mx_transfer_wait(transfer);
	if (ret < 0)
		pr_warn("Failed to wait mx_transfer (err=%ld)\n", ret);

out:
	mx_transfer_destroy_sg(mx_pdev, transfer);

	return ret;
}

static ssize_t mx_transfer_submit_sg_parallel(struct mx_pci_dev *mx_pdev,
		struct mx_transfer **transfer, int opcode, int count)
{
	ssize_t res = 0;
	int i;

	for (i = 0; i < count; i++) {
		int ret = mx_transfer_init_sg(mx_pdev, transfer[i], opcode);
		if (ret < 0) {
			pr_warn("Failed to init mx_transfer (err=%d)\n", ret);
			goto out;
		}

		mx_transfer_queue(&mx_pdev->io_queue, transfer[i]);
	}

	for (i = 0; i < count; i++) {
		int ret = mx_transfer_wait(transfer[i]);
		if (ret < 0)
			pr_warn("Failed to wait mx_transfer (err=%d)\n", ret);
		res += ret;
	}

out:
	for (i = 0; i < count; i++)
		mx_transfer_destroy_sg(mx_pdev, transfer[i]);

	return res;
}

static ssize_t mx_transfer_submit_ctrl(struct mx_pci_dev *mx_pdev,
		struct mx_transfer *transfer, int opcode)
{
	ssize_t ret;

	ret = mx_transfer_init_ctrl(transfer, opcode);
	if (ret < 0) {
		pr_warn("Failed to init mx_transfer (err=%ld)\n", ret);
		return ret;
	}

	mx_transfer_queue(&mx_pdev->io_queue, transfer);
	ret = mx_transfer_wait(transfer);
	if (ret < 0) {
		pr_warn("Failed to wait mx_transfer (err=%ld)\n", ret);
		return ret;
	}

	ret = mx_transfer_destroy_ctrl(transfer);
	if (ret) {
		pr_warn("Failed to destroy mx_transfer (err=%ld)\n", ret);
		return ret;
	}

	return transfer->size;
}

/******************************************************************************/
/* Functions for fops                                                         */
/******************************************************************************/
static struct mx_transfer *alloc_mx_transfer(char __user *user_addr, size_t size, uint64_t device_addr,
		enum dma_data_direction dir, bool nowait)
{
	struct mx_transfer *transfer;

	transfer = kzalloc(sizeof(struct mx_transfer), GFP_KERNEL);
	if (!transfer) {
		return NULL;
	}

	transfer->user_addr = user_addr;
	transfer->size = size;
	transfer->device_addr = device_addr;
	transfer->dir = dir;
	transfer->nowait = nowait;

	return transfer;
}

ssize_t read_data_from_device(struct mx_pci_dev *mx_pdev,
		char __user *user_addr, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer *transfer;
	ssize_t ret;

	transfer = alloc_mx_transfer(user_addr, size, *fpos, DMA_FROM_DEVICE, false);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer\n");
		return -ENOMEM;
	}

	ret = mx_transfer_submit_sg(mx_pdev, transfer, opcode);

	kfree(transfer);

	return ret;
}

ssize_t write_data_to_device(struct mx_pci_dev *mx_pdev,
		const char __user *user_addr, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer *transfer;
	ssize_t ret;

	transfer = alloc_mx_transfer((char __user *)user_addr, size, *fpos, DMA_TO_DEVICE, nowait);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer\n");
		return -ENOMEM;
	}

	ret = mx_transfer_submit_sg(mx_pdev, transfer, opcode);

	kfree(transfer);

	return ret;
}

ssize_t read_ctrl_from_device(struct mx_pci_dev *mx_pdev,
		char __user *user_addr, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer *transfer;
	ssize_t ret;

	transfer = alloc_mx_transfer(user_addr, size, *fpos, DMA_FROM_DEVICE, false);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer\n");
		return -ENOMEM;
	}

	ret = mx_transfer_submit_ctrl(mx_pdev, transfer, opcode);

	kfree(transfer);

	return ret;
}

ssize_t write_ctrl_to_device(struct mx_pci_dev *mx_pdev,
		const char __user *user_addr, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer *transfer;
	ssize_t ret;

	transfer = alloc_mx_transfer((char __user *)user_addr, size, *fpos, DMA_TO_DEVICE, nowait);
	if (!transfer) {
		pr_warn("Failed to alloc mx_transfer\n");
		return -ENOMEM;
	}

	ret = mx_transfer_submit_ctrl(mx_pdev, transfer, opcode);

	kfree(transfer);

	return ret;
}

/******************************************************************************/
/* Functions for parallel fops                                                */
/******************************************************************************/
static struct mx_transfer **alloc_mx_transfer_parallel(void __user *user_addr, size_t total_size,
		uint64_t device_addr, enum dma_data_direction dir, int pages_nr, int count, bool nowait)
{
	struct mx_transfer **transfer;
	int q, r;
	int i;

	transfer = kcalloc(count, sizeof(struct mx_transfer *), GFP_KERNEL);
	if (!transfer) {
		pr_warn("Failed to alloc parallel mx_transfer\n");
		return NULL;
	}

	pr_debug_dma("user_addr=%#llx, device_addr=%#llx, size=%#lx, pages_nr=%d, count=%d\n",
			(uint64_t)user_addr, device_addr, total_size, pages_nr, count);

	q = pages_nr / count;
	r = pages_nr % count;

	for (i = 0; i < count; i++) {
		int num = (r-- > 0) ? q + 1 : q;
		uint64_t end_addr = ((uint64_t)user_addr + num * PAGE_SIZE) & PAGE_MASK;
		size_t size = min_t(size_t, end_addr - (uint64_t)user_addr, total_size);

		transfer[i] = alloc_mx_transfer(user_addr, size, device_addr, dir, nowait);
		user_addr = (void __user *)((uint64_t)user_addr + size);
		total_size -= size;
		device_addr += size;

		pr_debug_dma("transfer[%d]: user_addr=%#llx device_addr=%#llx, size=%#lx\n",
				i, (uint64_t)transfer[i]->user_addr, transfer[i]->device_addr, transfer[i]->size);
	}

	return transfer;
}

static void free_mx_transfer_parallel(struct mx_transfer **transfer, int count)
{
	int i;

	for (i = 0; i < count; i++)
		kfree(transfer[i]);

	kfree(transfer);
}

ssize_t read_data_from_device_parallel(struct mx_pci_dev *mx_pdev,
		char __user *buf, size_t size, loff_t *fpos, int opcode)
{
	struct mx_transfer **transfer;
	uint64_t first_page_index, last_page_index;
	int nr_pages, count;
	ssize_t res;

	first_page_index = (uint64_t)buf >> PAGE_SHIFT;
	last_page_index = ((uint64_t)buf + size - 1) >> PAGE_SHIFT;
	nr_pages = last_page_index - first_page_index + 1;
	count = min_t(int, nr_pages, parallel_count);

	if (count == 1)
		return read_data_from_device(mx_pdev, buf, size, fpos, opcode);

	transfer = alloc_mx_transfer_parallel(buf, size, *fpos, DMA_FROM_DEVICE, nr_pages, count, false);
	if (!transfer)
		return -ENOMEM;

	res = mx_transfer_submit_sg_parallel(mx_pdev, transfer, opcode, count);
	free_mx_transfer_parallel(transfer, count);

	return res;
}

ssize_t write_data_to_device_parallel(struct mx_pci_dev *mx_pdev,
		const char __user *buf, size_t size, loff_t *fpos, int opcode, bool nowait)
{
	struct mx_transfer **transfer;
	uint64_t first_page_index, last_page_index;
	int nr_pages, count;
	ssize_t res;

	first_page_index = (uint64_t)buf >> PAGE_SHIFT;
	last_page_index = ((uint64_t)buf + size - 1) >> PAGE_SHIFT;
	nr_pages = last_page_index - first_page_index + 1;
	count = min_t(int, nr_pages, parallel_count);

	if (count == 1)
		return write_data_to_device(mx_pdev, buf, size, fpos, opcode, nowait);

	transfer = alloc_mx_transfer_parallel((char __user *)buf, size, *fpos, DMA_TO_DEVICE, nr_pages, count, nowait);
	if (!transfer)
		return -ENOMEM;

	res = mx_transfer_submit_sg_parallel(mx_pdev, transfer, opcode, count);
	free_mx_transfer_parallel(transfer, count);

	return res;
}

/******************************************************************************/
/* Functions for handler                                                      */
/******************************************************************************/
int mx_command_handler(void *arg)
{
	struct mx_queue *queue = (struct mx_queue *)arg;
	struct mx_transfer *transfer, *tmp;
	struct mx_command *comm;
	unsigned long flags;

	while (!kthread_should_stop()) {
		if (list_empty(&queue->sq_list)) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		spin_lock_irqsave(&queue->sq_lock, flags);
		list_for_each_entry_safe(transfer, tmp, &queue->sq_list, entry) {
			comm = (struct mx_command *)get_sqe_ptr(queue);
			if (!comm)
				break;

			memcpy(comm, &transfer->command, sizeof(struct mx_command));
			update_sq_doorbell(queue);

			if (transfer->nowait)
				complete(&transfer->done);

			list_del_init(&queue->sq_list);
		}
		spin_unlock_irqrestore(&queue->sq_lock, flags);

		ring_sq_doorbell(queue);
	}

	return 0;
}

int mx_completion_handler(void *arg)
{
	struct mx_queue *queue = (struct mx_queue *)arg;
	struct mx_transfer *transfer;
	struct mx_completion *cmpl;

	while (!kthread_should_stop()) {
		cmpl = (struct mx_completion *)get_cqe_ptr(queue);
		if (!cmpl) {
			msleep(POLLING_INTERVAL_MSEC);
			continue;
		}

		transfer = find_transfer_by_id(READ_ONCE(cmpl->command_id));
		if (transfer) {
			transfer->result = READ_ONCE(cmpl->result);
			complete(&transfer->done);
		}

		queue->sq_head = READ_ONCE(cmpl->sq_head);

		update_cq_doorbell(queue);
		ring_cq_doorbell(queue);
	}

	return 0;
}

