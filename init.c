// SPDX-License-Identifier: <SPDX License Expression>

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

static void pci_device_exit(struct mx_pci_dev *mx_pdev, struct pci_dev *pdev)
{
	int irq = pci_irq_vector(pdev, 0);

	free_irq(irq, NULL);

	if (mx_pdev->has_regions)
		pci_release_region(pdev, HMBOX_BAR_INDEX);
}

static int pci_device_init(struct mx_pci_dev *mx_pdev, struct pci_dev *pdev)
{
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

	ret = pci_request_region(pdev, HMBOX_BAR_INDEX, MXDMA_NODE_NAME);
	if (!ret)
		mx_pdev->has_regions = true;

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

static void unmap_bars(struct mx_pci_dev *mx_pdev, struct pci_dev *pdev)
{
	if (!mx_pdev->hmbox_bar)
		return;

	pci_iounmap(pdev, mx_pdev->hmbox_bar);
}

static int map_bars(struct mx_pci_dev *mx_pdev, struct pci_dev *pdev)
{
	resource_size_t start = pci_resource_start(pdev, HMBOX_BAR_INDEX);
	resource_size_t len = pci_resource_len(pdev, HMBOX_BAR_INDEX);
	void __iomem *bar;

	if (len == 0) {
		pr_err("HMBOX BAR is not available\n");
		return -ENODEV;
	}

	if (len > INT_MAX) {
		pr_info("Limit HMBOX BAR mapping from %llu to %d bytes\n", (uint64_t)len, INT_MAX);
		len = (resource_size_t)INT_MAX;
	}

	bar = pci_iomap(pdev, HMBOX_BAR_INDEX, len);
	if (!bar) {
		pr_err("Failed to pci_iomap(%d)\n", HMBOX_BAR_INDEX);
		return -ENODEV;
	}

	mx_pdev->hmbox_bar = bar;
	mx_pdev->hmbox_size = (uint32_t)len;

	pr_info("HMBOX BAR at %#llx is mapped at %#llx, length=%u\n",
			(uint64_t)start, (uint64_t)mx_pdev->hmbox_bar, mx_pdev->hmbox_size);

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

static void mx_engine_exit(struct mx_engine *engine)
{
	int ret;

	if (engine->submit.thread) {
		ret = kthread_stop(engine->submit.thread);
		if (ret)
			pr_err("submit_thread thread doesn't stop properly (err=%d)\n", ret);
	}

	if (engine->complete.thread) {
		ret = kthread_stop(engine->complete.thread);
		if (ret)
			pr_err("complete_thread thread doesn't stop properly (err=%d)\n", ret);
	}
}

static int mx_engine_init(struct mx_engine *engine, void __iomem *bar, int dev_id)
{
	void __iomem *host_mbox_base = bar;
	void __iomem *hifc_mbox_base = bar + (1 << 20); /* 1MB */
	mbox_context_t ctx;

	engine->magic = MAGIC_ENGINE;

	/* Set up mailbox for submit */
	engine->submit.ctx_addr = host_mbox_base + HIO_HOST_Q_OFFSET * sizeof(uint64_t);
	ctx.u64 = readq(engine->submit.ctx_addr);
	if (ctx.u64 == INVALID_CTX) {
		pr_err("Invalid SQ context: %llx\n", ctx.u64);
		return -ENXIO;
	}

	engine->submit.data_addr = hifc_mbox_base + sizeof(uint64_t) * ctx.data_base;
	engine->submit.depth = POWER_OF_2(ctx.q_size);
	pr_info("submit: ctx_addr=%#llx, data_addr=%#llx, ctx=%#llx\n",
			(uint64_t)engine->submit.ctx_addr, (uint64_t)engine->submit.data_addr, ctx.u64);

	spin_lock_init(&engine->submit.lock);
	INIT_LIST_HEAD(&engine->submit.wait_list);
	engine->submit.thread = kthread_run(mx_command_submit_handler, engine, "mx_submit_thread%d", dev_id);

	/* Set up mailbox for complete */
	engine->complete.ctx_addr = host_mbox_base + HIO_HOST_Q_OFFSET * sizeof(uint64_t) + HMBOX_RQ_OFFSET;
	ctx.u64 = readq(engine->complete.ctx_addr);
	if (ctx.u64 == INVALID_CTX) {
		pr_err("Invalid CQ context: %llx\n", ctx.u64);
		return -ENXIO;
	}

	engine->complete.data_addr = host_mbox_base + sizeof(uint64_t) * ctx.data_base;
	engine->complete.depth = POWER_OF_2(ctx.q_size);
	pr_info("complete: ctx_addr=%#llx, data_addr=%#llx, ctx=%#llx\n",
			(uint64_t)engine->complete.ctx_addr, (uint64_t)engine->complete.data_addr, ctx.u64);

	spin_lock_init(&engine->complete.lock);
	INIT_LIST_HEAD(&engine->complete.wait_list);
	engine->complete.thread = kthread_run(mx_command_complete_handler, engine, "mx_complete_thread%d", dev_id);

	return 0;
}

static bool is_nowait_type(int type)
{
	if (type >= MXDMA_TYPE_DATA_NOWAIT && type <= MXDMA_TYPE_CQ_NOWAIT)
		return true;
	return false;
}

static int create_mx_cdev(struct mx_pci_dev *mx_pdev, int type)
{
	struct mx_char_dev *mx_cdev = &mx_pdev->mx_cdev[type];
	struct device *dev;
	int ret;

	mx_cdev->magic = MAGIC_CHAR;
	mx_cdev->cdev_no = MKDEV(MAJOR(mx_pdev->dev_no), mx_pdev->num_of_cdev++);
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

	mx_engine_exit(&mx_pdev->engine);

	for (type = 0; type < NUM_OF_MXDMA_TYPE; type++)
		destroy_mx_cdev(&mx_pdev->mx_cdev[type]);

	pci_device_exit(mx_pdev, pdev);
	unmap_bars(mx_pdev, pdev);
	unregister_chrdev_region(mx_pdev->dev_no, NUM_OF_MXDMA_TYPE);
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

	ret = alloc_chrdev_region(&mx_pdev->dev_no, 0, NUM_OF_MXDMA_TYPE, MXDMA_NODE_NAME);
	if (ret) {
		pr_err("Failed to alloc_chrdev_region (err=%d)\n", ret);
		goto out_fail;
	}

	ret = map_bars(mx_pdev, pdev);
	if (ret) {
		pr_err("Failed to map_bars (err=%d)\n", ret);
		goto out_fail;
	}

	ret = pci_device_init(mx_pdev, pdev);
	if (ret) {
		pr_err("Failed to init_pdev (err=%d)\n", ret);
		goto out_fail;
	}

	ret = set_dma_addressing(pdev);
	if (ret) {
		pr_err("Failed to set_dma_addressing (err=%d)\n", ret);
		goto out_fail;
	}

	mx_event_init(mx_pdev);

	for (type = 0; type < NUM_OF_MXDMA_TYPE; type++) {
		ret = create_mx_cdev(mx_pdev, type);
		if (ret) {
			pr_err("Failed to create mx_cdev (%s) (err=%d)\n", node_name[type], ret);
			goto out_fail;
		}
	}

	ret = mx_engine_init(&mx_pdev->engine, mx_pdev->hmbox_bar, mx_pdev->id);
	if (ret) {
		pr_err("Failed to mx_engine_init (err=%d)\n", ret);
		goto out_fail;
	}

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

