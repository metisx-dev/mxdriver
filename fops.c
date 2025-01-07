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

static ssize_t mxdma_device_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;

	if (!count) {
		pr_warn("size of data to read is zero\n");
		return -EINVAL;
	}

	mx_cdev = (struct mx_char_dev *)file->private_data;
	if (!mx_cdev) {
		pr_warn("mx_cdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if (mx_cdev->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mxcdev(0x%p) file(0x%p)\n", mx_cdev, file);
		return -EINVAL;
	}

	mx_pdev = mx_cdev->mx_pdev;
	if (!mx_pdev) {
		pr_warn("mx_pdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if (mx_pdev->magic != MAGIC_DEVICE) {
		pr_warn("magic is mismatch. mx_pdev(0x%p) file(0x%p)\n", mx_pdev, file);
		return -EINVAL;
	}

	if (!mx_pdev->enabled) {
		pr_warn("pci device isn't enabled. dev_no=%d", mx_pdev->dev_no);
		return -ENODEV;
	}

	switch (mx_cdev->type) {
	case MXDMA_TYPE_DATA:
		count = read_data_from_device_parallel(mx_pdev, buf, count, pos, MXDMA_OP_DATA_READ);
		break;
	case MXDMA_TYPE_CONTEXT:
		if (count >= sizeof(uint64_t))
			count = read_data_from_device(mx_pdev, buf, count, pos, MXDMA_OP_CONTEXT_READ);
		else
			count = read_ctrl_from_device(mx_pdev, buf, count, pos, MXDMA_OP_CONTEXT_READ);
		break;
	case MXDMA_TYPE_SQ:
		if (count <= sizeof(uint64_t))
			count = read_ctrl_from_device(mx_pdev, buf, count, pos, MXDMA_OP_SQ_READ);
		else
			return -EINVAL;
		break;
	case MXDMA_TYPE_CQ:
		if (count <= sizeof(uint64_t))
			count = read_ctrl_from_device(mx_pdev, buf, count, pos, MXDMA_OP_CQ_READ);
		else
			return -EINVAL;
		break;
	default:
		break;
	}

	return count;
}

static ssize_t mxdma_device_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct mx_char_dev *mx_cdev;
	struct mx_pci_dev *mx_pdev;

	if (!count) {
		pr_warn("size of data to write is zero\n");
		return -EINVAL;
	}

	mx_cdev = (struct mx_char_dev *)file->private_data;
	if (!mx_cdev) {
		pr_warn("mx_cdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if (mx_cdev->magic != MAGIC_CHAR) {
		pr_warn("magic is mismatch. mx_cdev(0x%p) file(0x%p)\n", mx_cdev, file);
		return -EINVAL;
	}

	mx_pdev = mx_cdev->mx_pdev;
	if (!mx_pdev) {
		pr_warn("mx_pdev is NULL of file(0x%p)\n", file);
		return -EINVAL;
	}

	if (mx_pdev->magic != MAGIC_DEVICE) {
		pr_warn("magic is mismatch. mx_pdev(0x%p) file(0x%p)\n", mx_pdev, file);
		return -EINVAL;
	}

	if (!mx_pdev->enabled) {
		pr_warn("pci device isn't enabled. dev_no=%d", mx_pdev->dev_no);
		return -ENODEV;
	}

	switch (mx_cdev->type) {
	case MXDMA_TYPE_DATA:
		count = write_data_to_device_parallel(mx_pdev, buf, count, pos, MXDMA_OP_DATA_WRITE);
		break;
	case MXDMA_TYPE_CONTEXT:
		if (count >= sizeof(uint64_t))
			count = write_data_to_device(mx_pdev, buf, count, pos, MXDMA_OP_CONTEXT_WRITE);
		else
			count = write_ctrl_to_device(mx_pdev, buf, count, pos, MXDMA_OP_CONTEXT_WRITE);
		break;
	case MXDMA_TYPE_SQ:
		if (count <= sizeof(uint64_t))
			count = write_ctrl_to_device(mx_pdev, buf, count, pos, MXDMA_OP_SQ_WRITE);
		else
			return -EINVAL;
		break;
	case MXDMA_TYPE_CQ:
		if (count <= sizeof(uint64_t))
			count = write_ctrl_to_device(mx_pdev, buf, count, pos, MXDMA_OP_CQ_WRITE);
		else
			return -EINVAL;
		break;
	default:
		break;
	}

	return count;
}

struct file_operations mxdma_fops = {
	.open = mxdma_device_open,
	.release = mxdma_device_release,
	.read = mxdma_device_read,
	.write = mxdma_device_write,
};

