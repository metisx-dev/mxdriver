// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

/******************************************************************************/
/* Initialization                                                             */
/******************************************************************************/
static struct class *mxdma_class;

#ifndef CONFIG_WO_CXL
static LIST_HEAD(mx_device_list_head);
static DEFINE_MUTEX(mx_device_list_lock);
#endif

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
	if (!mx_pdev) {
		pr_err("Invalid data\n");
		goto out;
	}

	mx_event = &(mx_pdev->event);
	if (!mx_event) {
		pr_err("Invalid event\n");
		goto out;
	}

	atomic_inc(&mx_event->count);
	wake_up_interruptible(&mx_event->wq);

out:
	return IRQ_HANDLED;
}

static void pci_device_exit(struct mx_pci_dev* mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;
	int irq = pci_irq_vector(pdev, 0);

	free_irq(irq, mx_pdev);
#ifdef CONFIG_WO_CXL
	pci_disable_msi(pdev);
#endif
}

static int pci_device_init(struct mx_pci_dev* mx_pdev)
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

	if (pci_dev_msi_enabled(pdev) == false) {
		ret = pci_enable_msi(pdev);
		if (ret) {
			pr_err("Failed to pci_enable_msi (err=%d)\n", ret);
			return ret;
		}
	}

	int irq = pci_irq_vector(pdev, 0);
	if (irq < 0) {
		pr_err("Failed to get msi irq vector (err=%d)\n", irq);
		return -ENODEV;
	}

	ret = request_threaded_irq(irq, msi_irq_handler, NULL, 0, MXDMA_NODE_NAME, mx_pdev);
	if (ret) {
		pr_err("Failed to request_threaded_irq (err=%d)\n", ret);
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

static int dev_map(struct mx_pci_dev *mx_pdev)
{
	struct pci_dev *pdev = mx_pdev->pdev;
	uint32_t size;
	int ret;

	ret = pci_request_region(pdev, MXDMA_BAR_INDEX, MXDMA_NODE_NAME);
	if (ret) {
		pr_err("Failed to pci_request_region (err=%d)\n", ret);
		return ret;
	}

	size = pci_resource_len(pdev, MXDMA_BAR_INDEX);
	mx_pdev->bar = pci_iomap(pdev, MXDMA_BAR_INDEX, size);
	if (!mx_pdev->bar) {
		pr_err("Failed to pci_iomap (size=%u)\n", size);
		pci_release_region(pdev, MXDMA_BAR_INDEX);
		return -ENOMEM;
	}

	mx_pdev->bar_mapped_size = size;

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

static int create_mx_cdev(struct mx_pci_dev *mx_pdev, int type)
{
	struct mx_char_dev *mx_cdev = &mx_pdev->mx_cdev[type];
	struct device *dev;
	int ret;

	mx_cdev->magic = MAGIC_CHAR;
	mx_cdev->cdev_no = MKDEV(MAJOR(mx_pdev->dev_no), mx_pdev->num_of_cdev++);
	mx_cdev->nowait = type == MX_CDEV_DATA_NOWAIT;

	cdev_init(&mx_cdev->cdev, mxdma_fops_array[type]);
	kobject_set_name(&mx_cdev->cdev.kobj, node_name[type], mx_pdev->dev_id);

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

	mx_pdev->ops.release_queue(mx_pdev);

	for (type = 0; type < NUM_OF_MX_CDEV; type++)
		destroy_mx_cdev(&mx_pdev->mx_cdev[type]);

	dev_unmap(mx_pdev);
	unregister_chrdev_region(mx_pdev->dev_no, NUM_OF_MX_CDEV);
	pci_device_exit(mx_pdev);
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
	mx_pdev->dev_id = cxl_memdev_id;

	if (pdev->revision == 0x1) {
		register_mx_ops_v1(&mx_pdev->ops);
		pr_info("PCI device revision 1 detected\n");
	} else if (pdev->revision == 0x2) {
		register_mx_ops_v2(&mx_pdev->ops);
		pr_info("PCI device revision 2 detected\n");
	} else {
		pr_err("Unknown PCI device revision %d\n", pdev->revision);
		return -EINVAL;
	}

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

	ret = mx_pdev->ops.init_queue(mx_pdev);
	if (ret) {
		pr_err("Failed to mx_queue_init (err=%d)\n", ret);
		goto out_fail;
	}

	mx_event_init(mx_pdev);

	for (type = 0; type < NUM_OF_MX_CDEV; type++) {
		ret = create_mx_cdev(mx_pdev, type);
		if (ret) {
			pr_err("Failed to create mx_cdev (%s) (err=%d)\n", node_name[type], ret);
			goto out_fail;
		}
	}

	mx_pdev->page_pool = dma_pool_create("mxdma_page_pool", &pdev->dev,
			mx_pdev->page_size, mx_pdev->page_size, 0);

	mxdma_device_online(pdev);

	return 0;

out_fail:
	destroy_mx_pdev(pdev);

	return ret;
}

/******************************************************************************/
/* PCI Device Driver Support                                                  */
/******************************************************************************/
static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(XCENA_PCI_VENDOR_ID, PCI_ANY_ID), },
	{ 0,}
};
MODULE_DEVICE_TABLE(pci, pci_ids);

#ifndef CONFIG_WO_CXL
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static int match_mem_prefix(struct device *dev, void *data)
#else
static int match_mem_prefix(struct device *dev, const void *data)
#endif
{
	const char *name;

	name = dev_name(dev);
	return name && !strncmp(name, MXDMA_MEM_NAME, MEM_NAME_LEN);
}
#endif

static int get_cxl_memdev_id(struct pci_dev *pdev)
{
#ifdef CONFIG_WO_CXL
	static int standalone_id = -1;
	return ++standalone_id;
#else
	int mem_id;
	struct device *child;

	child = device_find_child(&pdev->dev, NULL, match_mem_prefix);
	if (!child)
	{
		pr_err("No matching CXL memory device found for PCI device %s.\n", dev_name(&pdev->dev));
		return -ENODEV;
	}

	if (sscanf(dev_name(child), MXDMA_MEM_NAME "%d", &mem_id) != 1 || mem_id < 0)
	{
		pr_err("Failed to parse CXL memory device ID from device name %s.\n", dev_name(child));
		mem_id = -ENODEV;
	}

	put_device(child);
	return mem_id;
#endif
}

#ifndef CONFIG_WO_CXL
static int add_device_into_global_list(struct pci_dev *pdev)
{
	struct mx_device_node *mx_node;

	mx_node = devm_kzalloc(&pdev->dev, sizeof(*mx_node), GFP_KERNEL);
	if (!mx_node)
		return -ENOMEM;
	mx_node->dev = &pdev->dev;

	mutex_lock(&mx_device_list_lock);
	list_add_tail(&mx_node->node, &mx_device_list_head);
	mutex_unlock(&mx_device_list_lock);

	return 0;
}
#endif

static int __mxdma_driver_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	int cxl_memdev_id;

	cxl_memdev_id = get_cxl_memdev_id(pdev);
	if (cxl_memdev_id < 0)
	{
		pr_err("Failed to get cxl_memdev_id from PCI device %s\n", dev_name(&pdev->dev));
		return -ENODEV;
	}

	ret = create_mx_pdev(pdev, cxl_memdev_id);
	if (ret) {
		pr_err("Failed to create_mx_pdev\n");
		return ret;
	}

#ifndef CONFIG_WO_CXL
	ret = add_device_into_global_list(pdev);
	if (ret < 0)
	{
		destroy_mx_pdev(pdev);
		return ret;
	}
#endif

	pr_info("pci device is probed (vendor=%#x device=%#x bdf=%s cxl=mem%d)\n",
			pdev->vendor, pdev->device, dev_name(&pdev->dev), cxl_memdev_id);

	return 0;
}

static void __mxdma_driver_remove(struct pci_dev *pdev)
{
	destroy_mx_pdev(pdev);

	pr_info("pci device is removed (vendor=%#x, device=%#x, bdf=%s)\n",
			pdev->vendor, pdev->device, dev_name(&pdev->dev));
}

#ifdef CONFIG_WO_CXL
static struct pci_driver pci_driver = {
	.name		= MXDMA_NODE_NAME,
	.id_table	= pci_ids,
	.probe		= __mxdma_driver_probe,
	.remove		= __mxdma_driver_remove,
};
#endif

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

#ifndef CONFIG_WO_CXL
static void remove_device_from_global_list(struct device *dev)
{
	struct mx_device_node *mx_node, *tmp;

	mutex_lock(&mx_device_list_lock);
	list_for_each_entry_safe(mx_node, tmp, &mx_device_list_head, node) {
		if (mx_node->dev == dev) {
			list_del(&mx_node->node);
			break;
		}
	}
	mutex_unlock(&mx_device_list_lock);
}

static int mxdma_pci_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	struct pci_dev *pdev;

	pdev = to_pci_dev(data);
	if (pdev->vendor != XCENA_PCI_VENDOR_ID)
		return NOTIFY_OK;

	switch (action) {
	case BUS_NOTIFY_BOUND_DRIVER:
		__mxdma_driver_probe(pdev, NULL);
		break;
	case BUS_NOTIFY_UNBIND_DRIVER:
		__mxdma_driver_remove(pdev);
		remove_device_from_global_list(&pdev->dev);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block mxdma_pci_notifier = {
	.notifier_call = mxdma_pci_notify,
};
#endif

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

#ifdef CONFIG_WO_CXL
	return pci_register_driver(&pci_driver);
#else
	bus_register_notifier(&pci_bus_type, &mxdma_pci_notifier);
	return 0;
#endif
}

#ifndef CONFIG_WO_CXL
static void destroy_device_list(void)
{
	struct mx_device_node *mx_node, *tmp;

	mutex_lock(&mx_device_list_lock);
	list_for_each_entry_safe(mx_node, tmp, &mx_device_list_head, node) {
		struct pci_dev *pdev;

		if (!mx_node->dev)
			continue;

		pdev = to_pci_dev(mx_node->dev);
		__mxdma_driver_remove(pdev);
		list_del(&mx_node->node);
	}
	mutex_unlock(&mx_device_list_lock);
}
#endif

static void mxdma_exit(void)
{
#ifdef CONFIG_WO_CXL
	pci_unregister_driver(&pci_driver);
#else
	bus_unregister_notifier(&pci_bus_type, &mxdma_pci_notifier);
	destroy_device_list();
#endif

	if (mxdma_class)
		class_destroy(mxdma_class);

	pr_info("MXDMA driver is unloaded\n");
}

module_init(mxdma_init);
module_exit(mxdma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XCENA Inc.");
MODULE_DESCRIPTION("XCENA MX-DMA Driver");
MODULE_SOFTDEP("post: cxl_pci");
