// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/nvme.h>

#include "mx_dma.h"

/******************************************************************************/
/* Initialization                                                             */
/******************************************************************************/
static struct class *mxdma_class;

static void mx_event_init(struct mx_pci_dev *mx_pdev)
{
	struct mx_event *mx_event = &mx_pdev->event;

	init_waitqueue_head(&mx_event->wq);
	atomic_set(&mx_event->count, 0);
}

static irqreturn_t msi_irq_handler(int irq, void *data)
{
	struct mx_pci_dev *mx_pdev;
	struct mx_event *mx_event;

	mx_pdev = (struct mx_pci_dev *)data;
	if (mx_pdev == NULL) {
		pr_err("Invalid data\n");
		goto out;
	}

	mx_event = &(mx_pdev->event);
	if (mx_event == NULL) {
		pr_err("Invalid event\n");
		goto out;
	}

	atomic_inc(&mx_event->count);
	wake_up_interruptible(&mx_event->wq);

out:
	return IRQ_HANDLED;
}

static int alloc_mx_queue(struct device *dev, struct mx_queue *queue, uint32_t q_depth)
{
	queue->depth = q_depth;
	queue->cqes = dma_alloc_coherent(dev, queue->depth * sizeof(struct mx_completion), &queue->cq_dma_addr, GFP_KERNEL);
	if (!queue->cqes)
		return -ENOMEM;

	queue->sqes = dma_alloc_coherent(dev, queue->depth * sizeof(struct mx_command), &queue->sq_dma_addr, GFP_KERNEL);
	if (!queue->sqes)
		dma_free_coherent(dev, queue->depth * sizeof(struct mx_completion), (void *)queue->cqes, queue->cq_dma_addr);

	return 0;
}

static int release_mx_queue(struct device *dev, struct mx_queue *queue)
{
	if (!queue->cqes || !queue->sqes)
		return -EINVAL;

	dma_free_coherent(dev, queue->depth * sizeof(struct mx_completion), (void *)queue->cqes, queue->cq_dma_addr);
	dma_free_coherent(dev, queue->depth * sizeof(struct mx_command), (void *)queue->sqes, queue->sq_dma_addr);

	queue->cqes = NULL;
	queue->sqes = NULL;
	queue->cq_dma_addr = 0;
	queue->sq_dma_addr = 0;

	return 0;
}

static void init_mx_queue(struct mx_pci_dev *mx_pdev, struct mx_queue *queue, uint16_t qid)
{
	queue->qid = qid;
	queue->sq_tail = 0;
	queue->sq_head = 0;
	queue->cq_head = 0;
	queue->cq_phase = 1;
	queue->db = &mx_pdev->dbs[qid * 2 * sizeof(uint32_t)];
	memset((void *)queue->cqes, 0, queue->depth * sizeof(struct mx_completion));
	memset((void *)queue->sqes, 0, queue->depth * sizeof(struct mx_command));
	wmb();
}

static int configure_admin_queue(struct mx_pci_dev *mx_pdev)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue *admin_queue = &mx_pdev->admin_queue;
	uint32_t aqa;
	int ret;

	ret = alloc_mx_queue(dev, admin_queue, NVME_AQ_DEPTH);
	if (ret)
		return ret;

	aqa = admin_queue->depth - 1;
	aqa |= aqa << 16;
	writel(aqa, mx_pdev->bar + NVME_REG_AQA);
	writeq(admin_queue->sq_dma_addr, mx_pdev->bar + NVME_REG_ASQ);
	writeq(admin_queue->cq_dma_addr, mx_pdev->bar + NVME_REG_ACQ);

	init_mx_queue(mx_pdev, admin_queue, 0);

	return 0;
}

static int release_admin_queue(struct mx_pci_dev *mx_pdev)
{
	return release_mx_queue(&mx_pdev->pdev->dev, &mx_pdev->admin_queue);
}

static uint64_t submit_sync_command(struct mx_queue* queue, struct mx_command *c)
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
	struct mx_queue *admin_queue = &mx_pdev->admin_queue;
	struct mx_queue *io_queue = &mx_pdev->io_queue;
	struct mx_command comm = {};
	uint16_t cq_id, sq_id;
	int ret;

	ret = alloc_mx_queue(dev, io_queue, 256);
	if (ret)
		return ret;

	comm.opcode = ADMIN_OPCODE_CREATE_IO_CQ;
	comm.io_queue_info.depth = io_queue->depth;
	cq_id = submit_sync_command(admin_queue, &comm);

	comm.opcode = ADMIN_OPCODE_CREATE_IO_SQ;
	comm.io_queue_info.cq_id = cq_id;
	sq_id = submit_sync_command(admin_queue, &comm);

	if (cq_id != sq_id) {
		pr_err("Failed to create IO queue (cq_id=%d, sq_id=%d)\n", cq_id, sq_id);
		return -EINVAL;
	}

	init_mx_queue(mx_pdev, io_queue, cq_id);

	spin_lock_init(&io_queue->sq_lock);
	INIT_LIST_HEAD(&io_queue->sq_list);
	mx_pdev->comm_thread = kthread_run(mx_command_handler, io_queue, "mx_command_thd%d", mx_pdev->id);
	mx_pdev->cmpl_thread = kthread_run(mx_completion_handler, io_queue, "mx_complete_thd%d", mx_pdev->id);

	return 0;
}

static int release_io_queue(struct mx_pci_dev *mx_pdev)
{

	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_queue *admin_queue = &mx_pdev->admin_queue;
	struct mx_queue *io_queue = &mx_pdev->io_queue;
	struct mx_command comm = {};
	int ret;

	comm.opcode = ADMIN_OPCODE_DELETE_IO_CQ;
	comm.io_queue_info.cq_id = io_queue->qid;
	submit_sync_command(admin_queue, &comm);

	comm.opcode = ADMIN_OPCODE_DELETE_IO_SQ;
	comm.io_queue_info.cq_id = io_queue->qid;
	submit_sync_command(admin_queue, &comm);

	ret = release_mx_queue(dev, io_queue);
	if (ret)
		pr_err("Failed to release IO queue (err=%d)\n", ret);

	if (mx_pdev->comm_thread) {
		ret = kthread_stop(mx_pdev->comm_thread);
		if (ret)
			pr_err("%s doesn't stop properly (err=%d)\n", mx_pdev->comm_thread->comm, ret);
	}

	if (mx_pdev->cmpl_thread) {
		ret = kthread_stop(mx_pdev->cmpl_thread);
		if (ret)
			pr_err("%s doesn't stop properly (err=%d)\n", mx_pdev->cmpl_thread->comm, ret);
	}

	return 0;
}

static void pci_device_exit(struct mx_pci_dev *mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;
	int irq = pci_irq_vector(pdev, 0);

	free_irq(irq, NULL);
}

static int pci_device_init(struct mx_pci_dev *mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;
	int ret;

	if (pci_is_enabled(pdev) == false) {
		ret = pcim_enable_device(pdev);
		if (ret) {
			pr_err("Failed to pci_enable_device (err=%d)\n", ret);
			return ret;
		}
	}

	ret = pcie_set_readrq(pdev, PAGE_SIZE);
	if (ret) {
		pr_err("Failed to pcie_set_readrq (err=%d)\n", ret);
		return ret;
	}

	if (!pdev->is_busmaster)
		pci_set_master(pdev);

	ret = pci_enable_msi(pdev);
	if (ret) {
		pr_err("Failed to pci_enable_msi (err=%d)\n", ret);
	} else {
		int irq = pci_irq_vector(pdev, 0);
		pr_info("MSI enabled, irq=%d\n", irq);

		mx_event_init(mx_pdev);

		ret = request_threaded_irq(irq, msi_irq_handler, NULL, 0, MXDMA_NODE_NAME, mx_pdev);
		if (ret) {
			pr_err("Failed to request_threaded_irq (err=%d)\n", ret);
			pci_disable_msi(pdev);
		}
	}

	return 0;
}

static void dev_unmap(struct mx_pci_dev *mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;

	if (mx_pdev->bar)
		pci_iounmap(pdev, mx_pdev->bar);

	pci_release_region(pdev, MXDMA_BAR_INDEX);
}

static int remap_bar(struct mx_pci_dev *mx_pdev, uint32_t size)
{
	struct pci_dev *pdev = mx_pdev->pdev;

	if (size <= mx_pdev->bar_mapped_size)
		return 0;

	if (size > pci_resource_len(pdev, MXDMA_BAR_INDEX))
		return -ENOMEM;

	if (mx_pdev->bar)
		pci_iounmap(pdev, mx_pdev->bar);

	mx_pdev->bar = pci_iomap(pdev, MXDMA_BAR_INDEX, size);
	if (!mx_pdev->bar) {
		mx_pdev->bar_mapped_size = 0;
		return -ENOMEM;
	}

	mx_pdev->bar_mapped_size = size;
	mx_pdev->dbs = mx_pdev->bar + NVME_REG_DBS;

	return 0;
}

static int dev_map(struct mx_pci_dev *mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;
	int ret;

	ret = pci_request_region(pdev, MXDMA_BAR_INDEX, MXDMA_NODE_NAME);
	if (ret)
		return ret;

	ret = remap_bar(mx_pdev, NVME_REG_DBS + 4096);
	if (ret)
	{
		pci_release_region(pdev, MXDMA_BAR_INDEX);
		return ret;
	}

	return 0;
}

static int set_dma_addressing(struct pci_dev *pdev)
{
	/* 64-bit addressing capability for MXDMA? */
	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		/* use 64-bit DMA */
		pr_info("use 64-bit DMA\n");
		dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	} else if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))) {
		/* use 32-bit DMA */
		pr_info("use 32-bit DMA\n");
		dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
	} else {
		return -EINVAL;
	}

	return 0;
}

static bool is_nowait_type(int type)
{
	if (type >= MX_CDEV_DATA_NOWAIT && type <= MX_CDEV_CQ_NOWAIT)
		return true;
	return false;
}

static int create_mx_cdev(struct mx_pci_dev *mx_pdev, int type)
{
	struct mx_char_dev *mx_cdev = &mx_pdev->mx_cdev[type];
	struct device *dev;
	int ret;

	mx_cdev->magic = MAGIC_CHAR;
	mx_cdev->cdev_no = MKDEV(MAJOR(mx_pdev->dev_no), type);
	mx_cdev->nowait = is_nowait_type(type);

	cdev_init(&mx_cdev->cdev, mxdma_fops_array[type]);
	kobject_set_name(&mx_cdev->cdev.kobj, node_name[type], mx_pdev->id);

	ret = cdev_add(&mx_cdev->cdev, mx_cdev->cdev_no, 1);
	if (ret) {
		pr_err("Failed to cdev_add (err=%d)\n", ret);
		return ret;
	}

	dev = device_create(mxdma_class, NULL, mx_cdev->cdev_no, NULL, mx_cdev->cdev.kobj.name);
	if (IS_ERR(dev)) {
		pr_err("Failed to device_created (err=%ld)\n", PTR_ERR(dev));
		return PTR_ERR(dev);
	}

	mx_cdev->mx_pdev = mx_pdev;
	mx_cdev->enabled = true;

	pr_info("%s (%d:%d) is created\n", mx_cdev->cdev.kobj.name,
			MAJOR(mx_cdev->cdev_no), MINOR(mx_cdev->cdev_no));

	return 0;
}

static void destroy_mx_cdev(struct mx_char_dev *mx_cdev)
{
	if (!mx_cdev->enabled)
		return;
	mx_cdev->enabled = false;

	pr_info("%s (%d:%d) is destroyed\n", mx_cdev->cdev.kobj.name,
			MAJOR(mx_cdev->cdev_no), MINOR(mx_cdev->cdev_no));

	device_destroy(mxdma_class, mx_cdev->cdev_no);
	cdev_del(&mx_cdev->cdev);
}

static void mxdma_device_online(struct pci_dev *pdev)
{
	struct mx_pci_dev *mx_pdev;

	mx_pdev = dev_get_drvdata(&pdev->dev);
	if (!mx_pdev)
		return;

	mx_pdev->enabled = true;
}

static void mxdma_device_offline(struct pci_dev *pdev)
{
	struct mx_pci_dev *mx_pdev;

	mx_pdev = dev_get_drvdata(&pdev->dev);
	if (!mx_pdev)
		return;

	mx_pdev->enabled = false;
}

static void destroy_mx_pdev(struct pci_dev *pdev)
{
	struct mx_pci_dev *mx_pdev;
	int type;

	mxdma_device_offline(pdev);

	mx_pdev = dev_get_drvdata(&pdev->dev);
	if (!mx_pdev)
		return;

	dma_pool_destroy(mx_pdev->page_pool);

	release_admin_queue(mx_pdev);
	release_io_queue(mx_pdev);

	for (type = 0; type < NUM_OF_MX_CDEV; type++)
		destroy_mx_cdev(&mx_pdev->mx_cdev[type]);

	pci_device_exit(mx_pdev);
	dev_unmap(mx_pdev);
	unregister_chrdev_region(mx_pdev->dev_no, NUM_OF_MX_CDEV);
	devm_kfree(&pdev->dev, mx_pdev);
	dev_set_drvdata(&pdev->dev, NULL);
}

static int create_mx_pdev(struct pci_dev *pdev, int cxl_memdev_id)
{
	struct mx_pci_dev *mx_pdev;
	int type;
	int ret;

	mx_pdev = devm_kzalloc(&pdev->dev, sizeof(struct mx_pci_dev), GFP_KERNEL);
	if (!mx_pdev) {
		pr_err("Failed to alloc mx_pci_dev\n");
		return -ENOMEM;
	}

	dev_set_drvdata(&pdev->dev, mx_pdev);

	mx_pdev->magic = MAGIC_DEVICE;
	mx_pdev->pdev = pdev;
	mx_pdev->id = cxl_memdev_id;

	ret = alloc_chrdev_region(&mx_pdev->dev_no, 0, NUM_OF_MX_CDEV, MXDMA_NODE_NAME);
	if (ret) {
		pr_err("Failed to alloc_chrdev_region (err=%d)\n", ret);
		goto out_fail;
	}

	ret = dev_map(mx_pdev);
	if (ret) {
		pr_err("Failed to dev_map (err=%d)\n", ret);
		goto out_fail;
	}

	ret = pci_device_init(mx_pdev);
	if (ret) {
		pr_err("Failed to init_pdev (err=%d)\n", ret);
		goto out_fail;
	}

	ret = set_dma_addressing(pdev);
	if (ret) {
		pr_err("Failed to set_dma_addressing (err=%d)\n", ret);
		goto out_fail;
	}

	ret = configure_admin_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to configure_admin_queue (err=%d)\n", ret);
		return ret;
	}

	ret = configure_io_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to configure_io_queue (err=%d)\n", ret);
		return ret;
	}

	mx_event_init(mx_pdev);

	for (type = 0; type < NUM_OF_MX_CDEV; type++) {
		ret = create_mx_cdev(mx_pdev, type);
		if (ret) {
			pr_err("Failed to create mx_cdev (%s) (err=%d)\n", node_name[type], ret);
			goto out_fail;
		}
	}

	mx_pdev->page_pool = dma_pool_create("mxdma_page_pool", &pdev->dev, SINGLE_DMA_SIZE, SINGLE_DMA_SIZE, 0);

	mxdma_device_online(pdev);

	return 0;

out_fail:
	destroy_mx_pdev(pdev);

	return ret;
}

int mxdma_driver_probe(struct pci_dev *pdev, const struct pci_device_id *id, int cxl_memdev_id)
{
	int ret;

	ret = create_mx_pdev(pdev, cxl_memdev_id);
	if (ret) {
		pr_err("Failed to create_mx_pdev\n");
		return ret;
	}

	pr_info("pci device is probed (vendor=%#x device=%#x bdf=%s cxl=mem%d)\n",
			pdev->vendor, pdev->device, dev_name(&pdev->dev), cxl_memdev_id);

	return 0;
}
EXPORT_SYMBOL(mxdma_driver_probe);

void mxdma_driver_remove(struct pci_dev *pdev)
{
	destroy_mx_pdev(pdev);

	pr_info("pci device is removed (vendor=%#x) device=%#x)\n", pdev->vendor, pdev->device);
}
EXPORT_SYMBOL(mxdma_driver_remove);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 6)
static char *mxdma_devnode(struct device *dev, umode_t *mode)
#else
static char *mxdma_devnode(const struct device *dev, umode_t *mode)
#endif
{
	if (mode)
		*mode = 0666;
	return kasprintf(GFP_KERNEL, "%s/%s", MXDMA_NODE_NAME, dev_name(dev));
}

static int mxdma_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 3)
	mxdma_class = class_create(THIS_MODULE, MXDMA_NODE_NAME);
#else
	mxdma_class = class_create(MXDMA_NODE_NAME);
#endif
	if (IS_ERR(mxdma_class)) {
		pr_err("Failed to class_create (err=%ld)\n", PTR_ERR(mxdma_class));
		return PTR_ERR(mxdma_class);
	}

	mxdma_class->devnode = mxdma_devnode;

	pr_info("MXDMA driver is loaded\n");

	return 0;
}

static void mxdma_exit(void)
{
	if (mxdma_class)
		class_destroy(mxdma_class);

	pr_info("MXDMA driver is unloaded\n");
}

module_init(mxdma_init);
module_exit(mxdma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XCENA Inc.");
MODULE_DESCRIPTION("XCENA MX-DMA Driver");

