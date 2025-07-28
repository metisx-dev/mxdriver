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

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	if (mx_cdev->nowait)
		return -EINVAL;

	return read_data_from_device(mx_pdev, buf, count, pos, IO_OPCODE_CONTEXT_READ);
}

static ssize_t mxdma_device_read_sq(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (count != sizeof(uint64_t)) {
		pr_warn("size of data to read is not supported: %zu\n", count);
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	if (mx_cdev->nowait)
		return -EINVAL;

	return read_ctrl_from_device(mx_pdev, buf, count, pos, IO_OPCODE_SQ_READ);
}

static ssize_t mxdma_device_read_cq(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (count != sizeof(uint64_t)) {
		pr_warn("size of data to read is not supported: %zu\n", count);
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	if (mx_cdev->nowait)
		return -EINVAL;

	return read_ctrl_from_device(mx_pdev, buf, count, pos, IO_OPCODE_CQ_READ);
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

static ssize_t mxdma_device_write_sq(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (count != sizeof(uint32_t)) {
		pr_warn("size of data to write is not supported: %zu\n", count);
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	return write_ctrl_to_device(mx_pdev, buf, count, pos, IO_OPCODE_SQ_WRITE, mx_cdev->nowait);
}

static ssize_t mxdma_device_write_cq(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	int ret;

	if (count != sizeof(uint32_t)) {
		pr_warn("size of data to write is not supported: %zu\n", count);
		return -EINVAL;
	}

	ret = mxdma_device_prepare(file, &mx_cdev, &mx_pdev);
	if (ret)
		return ret;

	return write_ctrl_to_device(mx_pdev, buf, count, pos, IO_OPCODE_CQ_WRITE, mx_cdev->nowait);
}

static unsigned int mxdma_device_poll(struct file *file, poll_table *wait)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;
	struct mx_event *mx_event;
	unsigned int mask = 0;
	int count;

	mx_cdev = (struct mx_char_dev *)file->private_data;
	if (!mx_cdev) {
		pr_warn("mx_cdev is NULL of file(0x%p)\n", file);
		return POLLERR;
	}

	if (mx_cdev->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mx_cdev(0x%p) file(0x%p)\n", mx_cdev, file);
		return POLLERR;
	}

	mx_pdev = mx_cdev->mx_pdev;
	if (!mx_pdev) {
		pr_warn("mx_pdev is NULL of file(0x%p)\n", file);
		return POLLERR;
	}

	if (mx_pdev->magic != MAGIC_DEVICE) {
		pr_warn("magic is mismatch. mx_pdev(0x%p) file(0x%p)\n", mx_pdev, file);
		return POLLERR;
	}

	if (!mx_pdev->enabled) {
		pr_warn("pci device isn't enabled. dev_no=%d", mx_pdev->dev_no);
		return POLLERR;
	}

	mx_event = &mx_pdev->event;
	poll_wait(file, &mx_event->wq, wait);
	count = atomic_read(&mx_event->count);
	if (count > 0) {
		atomic_dec(&mx_event->count);
		mask = POLLIN | POLLRDNORM;
	}

	return mask;
}

struct file_operations mxdma_fops_data = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_data,
	.write = mxdma_device_write_data,
};

struct file_operations mxdma_fops_context = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_context,
	.write = mxdma_device_write_context,
};

struct file_operations mxdma_fops_sq = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_sq,
	.write = mxdma_device_write_sq,
};

struct file_operations mxdma_fops_cq = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read_cq,
	.write = mxdma_device_write_cq,
};

struct file_operations mxdma_fops_event = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.poll = mxdma_device_poll,
};

struct file_operations *mxdma_fops_array[] = {
	[MX_CDEV_DATA] = &mxdma_fops_data,
	[MX_CDEV_CONTEXT] = &mxdma_fops_context,
	[MX_CDEV_SQ] = &mxdma_fops_sq,
	[MX_CDEV_CQ] = &mxdma_fops_cq,
	[MX_CDEV_DATA_NOWAIT] = &mxdma_fops_data,
	[MX_CDEV_CONTEXT_NOWAIT] = &mxdma_fops_context,
	[MX_CDEV_SQ_NOWAIT] = &mxdma_fops_sq,
	[MX_CDEV_CQ_NOWAIT] = &mxdma_fops_cq,
	[MX_CDEV_EVENT] = &mxdma_fops_event,
};

