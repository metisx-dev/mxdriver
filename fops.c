// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

/******************************************************************************/
/* Functions for file_operations                                              */
/******************************************************************************/
static int mxdma_device_open(struct inode *inode, struct file *file)
{
	struct mx_char_dev *mx_cdev;

	mx_cdev = container_of(inode->i_cdev, struct mx_char_dev, cdev);
	if (mx_cdev->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mxcdev(0x%p) inode(%#lx)\n", mx_cdev, inode->i_ino);
		return -EINVAL;
	}

	file->private_data = mx_cdev;

	return 0;
}

static int mxdma_device_release(struct inode *inode, struct file *file)
{
	struct mx_char_dev *mx_cdev;

	mx_cdev = (struct mx_char_dev *)file->private_data;
	if (!mx_cdev) {
		pr_warn("mx_cdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if (mx_cdev->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mxcdev(0x%p) file(0x%p)\n", mx_cdev, file);
		return -EINVAL;
	}

	file->private_data = 0;

	return 0;
}

static int mxdma_device_prepare(struct file *file, struct mx_char_dev **mx_cdev, struct mx_pci_dev **mx_pdev)
{
	*mx_cdev = (struct mx_char_dev *)file->private_data;
	if (!*mx_cdev) {
		pr_warn("mx_cdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if ((*mx_cdev)->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mxcdev(0x%p) file(0x%p)\n", *mx_cdev, file);
		return -EINVAL;
	}

	*mx_pdev = (*mx_cdev)->mx_pdev;
	if (!*mx_pdev) {
		pr_warn("mx_pdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if ((*mx_pdev)->magic != MAGIC_DEVICE) {
		pr_warn("magic is mismatch. mx_pdev(0x%p) file(0x%p)\n", *mx_pdev, file);
		return -EINVAL;
	}

	if (!(*mx_pdev)->enabled) {
		pr_warn("pci device isn't enabled. dev_no=%d", (*mx_pdev)->dev_no);
		return -ENODEV;
	}

	return 0;
}

static ssize_t mxdma_device_read_data(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (!count) {
		pr_warn("size of data to read is zero\n");
		return -EINVAL;
	}

	if (pos == NULL || *pos == 0) {
		pr_warn("Invalid position to read\n");
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	if (mx_cdev->nowait)
		return -EINVAL;

	return read_data_from_device_parallel(mx_pdev, buf, count, pos, IO_OPCODE_DATA_READ);
}

static ssize_t mxdma_device_read_context(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (!count) {
		pr_warn("size of data to read is zero\n");
		return -EINVAL;
	}

	if (pos == NULL || *pos == 0) {
		pr_warn("Invalid position to read\n");
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	if (mx_cdev->nowait)
		return -EINVAL;

	return read_data_from_device(mx_pdev, buf, count, pos, IO_OPCODE_CONTEXT_READ);
}

static ssize_t mxdma_device_write_data(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (!count) {
		pr_warn("size of data to write is zero\n");
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	return write_data_to_device_parallel(mx_pdev, buf, count, pos, IO_OPCODE_DATA_WRITE, mx_cdev->nowait);
}

static ssize_t mxdma_device_write_context(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (!count) {
		pr_warn("size of data to write is zero\n");
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	return write_data_to_device(mx_pdev, buf, count, pos, IO_OPCODE_CONTEXT_WRITE, mx_cdev->nowait);
}

static long mxdma_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	return ioctl_to_device(mx_pdev, cmd, arg);
}

static unsigned int mxdma_device_poll(struct file *file, poll_table *wait)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	struct mx_event *mx_event;
	int ret;

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return POLLERR;

	mx_event = &mx_pdev->event;
	poll_wait(file, &mx_event->wq, wait);

	ret = atomic_read(&mx_event->count);
	if (ret > 0) {
		atomic_dec(&mx_event->count);
		return POLLIN | POLLRDNORM;
	}

	return 0;
}

static ssize_t mxdma_bdf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct mx_char_dev *mx_cdev = file->private_data;
	struct mx_pci_dev *mx_pdev;
	struct pci_dev *pdev;
	char bdf_str[32];
	int len;

	if (!mx_cdev || !mx_cdev->mx_pdev)
		return -ENODEV;

	mx_pdev = mx_cdev->mx_pdev;
	pdev = mx_pdev->pdev;

	len = scnprintf(bdf_str, sizeof(bdf_str), "%s\n", dev_name(&pdev->dev));

	return simple_read_from_buffer(buf, count, ppos, bdf_str, len);
}

static int mxdma_bdf_open(struct inode *inode, struct file *file)
{
	struct mx_char_dev *mx_cdev;
	mx_cdev = container_of(inode->i_cdev, struct mx_char_dev, cdev);
	file->private_data = mx_cdev;
	return 0;
}

struct file_operations mxdma_fops_data = {
	.owner = THIS_MODULE,
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_data,
	.write = mxdma_device_write_data,
};

struct file_operations mxdma_fops_context = {
	.owner = THIS_MODULE,
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_context,
	.write = mxdma_device_write_context,
};

struct file_operations mxdma_fops_ioctl = {
	.owner = THIS_MODULE,
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.unlocked_ioctl = mxdma_device_ioctl,
};

struct file_operations mxdma_fops_event = {
	.owner = THIS_MODULE,
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.poll = mxdma_device_poll,
};

struct file_operations mxdma_fops_bdf = {
	.owner = THIS_MODULE,
	.open = mxdma_bdf_open,
	.read = mxdma_bdf_read,
};

struct file_operations *mxdma_fops_array[] = {
	[MX_CDEV_DATA] = &mxdma_fops_data,
	[MX_CDEV_DATA_NOWAIT] = &mxdma_fops_data,
	[MX_CDEV_CONTEXT] = &mxdma_fops_context,
	[MX_CDEV_IOCTL] = &mxdma_fops_ioctl,
	[MX_CDEV_EVENT] = &mxdma_fops_event,
	[MX_CDEV_BDF] = &mxdma_fops_bdf,
};
