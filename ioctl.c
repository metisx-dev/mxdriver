// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

struct mx_ioctl_mbox_info
{
	uint32_t qid;
	uint64_t sq_ctx_addr;
	uint64_t sq_data_addr;
	uint64_t cq_ctx_addr;
	uint64_t cq_data_addr;
};

struct mx_ioctl_cmd_with_data
{
	uint32_t qid;
	uint64_t *cmd;
	void *user_addr;
	uint64_t device_addr;
	size_t size;
};

struct mx_ioctl_cmds
{
	uint32_t qid;
	uint32_t nr_cmds;
	uint64_t *cmds;
};

struct mx_ioctl_data
{
	void *user_addr;
	uint64_t device_addr;
	size_t size;
	bool no_wait;
};

#define MX_IOCTL_MAGIC			'X'
#define MX_IOCTL_REGISTER_MBOX		_IOW(MX_IOCTL_MAGIC, 1, struct mx_ioctl_mbox_info)
#define MX_IOCTL_INIT_MBOX		_IOW(MX_IOCTL_MAGIC, 2, uint32_t)
#define MX_IOCTL_SEND_CMD_WITH_DATA	_IOW(MX_IOCTL_MAGIC, 3, struct mx_ioctl_cmd_with_data)
#define MX_IOCTL_RECV_CMDS		_IOWR(MX_IOCTL_MAGIC, 4, struct mx_ioctl_cmds)
#define MX_IOCTL_SEND_CMDS		_IOWR(MX_IOCTL_MAGIC, 5, struct mx_ioctl_cmds)
#define MX_IOCTL_READ_DATA		_IOW(MX_IOCTL_MAGIC, 6, struct mx_ioctl_data)
#define MX_IOCTL_WRITE_DATA		_IOW(MX_IOCTL_MAGIC, 7, struct mx_ioctl_data)

static uint32_t get_pushable_count(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	if (head.phase == tail.phase)
		return mbox->depth - tail.index;
	else
		return head.index - tail.index;
}

static uint32_t get_popable_count(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	if (head.phase == tail.phase)
		return tail.index - head.index;
	else
		return mbox->depth - head.index;
}

static struct mx_mbox *create_mx_mbox(struct mx_pci_dev *mx_pdev, uint64_t ctx_addr, uint64_t data_addr)
{
	struct device *dev = &mx_pdev->pdev->dev;
	struct mx_mbox *mbox;
	uint64_t ctx;

	read_ctrl_from_device(mx_pdev, (char __user *)&ctx, sizeof(uint64_t), (loff_t *)&ctx_addr, IO_OPCODE_SQ_READ);
	if (ctx == ULLONG_MAX) {
		pr_info("Invalid mbox context (ctx_addr = 0x%llx)\n", ctx_addr);
		return NULL;
	}

	mbox = devm_kzalloc(dev, sizeof(struct mx_mbox), GFP_KERNEL);
	if (!mbox)
		return NULL;

	mx_mbox_init(mbox, ctx_addr, data_addr, ctx);

	return mbox;
}

static void reset_mx_mbox(struct mx_pci_dev *mx_pdev, struct mx_mbox *mbox)
{
	uint64_t ctx;

	read_ctrl_from_device(mx_pdev, (char __user *)&ctx, sizeof(uint64_t), (loff_t *)&mbox->r_ctx_addr, IO_OPCODE_SQ_READ);
	mbox->ctx.u64 = ctx;
}

static long ioctl_register_mbox(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_mbox_info mbox_info;
	struct mx_mbox *sq_mbox, *cq_mbox;

	if (copy_from_user(&mbox_info, (void __user *)arg, sizeof(mbox_info)))
		return -EFAULT;

	if (mbox_info.qid >= MAX_NUM_OF_MBOX)
		return -EINVAL;

	if (mx_pdev->sq_mbox_list[mbox_info.qid])
		return 0;

	sq_mbox = create_mx_mbox(mx_pdev, mbox_info.sq_ctx_addr, mbox_info.sq_data_addr);
	if (!sq_mbox)
		return -ENOMEM;

	cq_mbox = create_mx_mbox(mx_pdev, mbox_info.cq_ctx_addr, mbox_info.cq_data_addr);
	if (!cq_mbox) {
		return -ENOMEM;
	}

	mx_pdev->sq_mbox_list[mbox_info.qid] = sq_mbox;
	mx_pdev->cq_mbox_list[mbox_info.qid] = cq_mbox;

	return 0;
}

static long ioctl_init_mbox(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	uint32_t qid;

	if (copy_from_user(&qid, (void __user *)arg, sizeof(qid)))
		return -EFAULT;

	if (qid >= MAX_NUM_OF_MBOX || !mx_pdev->sq_mbox_list[qid] || !mx_pdev->cq_mbox_list[qid])
		return -EINVAL;

	reset_mx_mbox(mx_pdev, mx_pdev->sq_mbox_list[qid]);
	reset_mx_mbox(mx_pdev, mx_pdev->cq_mbox_list[qid]);

	return 0;
}

static long ioctl_send_cmd_with_data(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_cmd_with_data send_cmd;
	struct mx_mbox *sq_mbox;
	uint64_t data_addr;

	if (copy_from_user(&send_cmd, (void __user *)arg, sizeof(send_cmd)))
		return -EFAULT;

	if (send_cmd.qid >= MAX_NUM_OF_MBOX || !mx_pdev->sq_mbox_list[send_cmd.qid])
		return -EINVAL;

	if (send_cmd.user_addr && send_cmd.size > 0)
		write_data_to_device(mx_pdev, send_cmd.user_addr, send_cmd.size, &send_cmd.device_addr, IO_OPCODE_DATA_WRITE, true);

	sq_mbox = mx_pdev->sq_mbox_list[send_cmd.qid];

	mutex_lock(&sq_mbox->lock);
	while (is_full(sq_mbox)) {
		mbox_context_t ctx;

		read_ctrl_from_device(mx_pdev, (char __user *)&ctx.u64, sizeof(uint64_t), (loff_t *)&sq_mbox->r_ctx_addr, IO_OPCODE_SQ_READ);
		sq_mbox->ctx.head = ctx.head;
	}

	data_addr = sq_mbox->data_addr + get_data_offset(sq_mbox->ctx.tail);
	sq_mbox->ctx.tail = get_next_index(sq_mbox->ctx.tail, 1, sq_mbox->depth);

	write_data_to_device(mx_pdev, (const char __user *)send_cmd.cmd, sizeof(uint64_t), (loff_t *)&data_addr, IO_OPCODE_CONTEXT_WRITE, true);
	write_ctrl_to_device(mx_pdev, (const char __user *)&sq_mbox->ctx.u64, sizeof(uint64_t), (loff_t *)&sq_mbox->w_ctx_addr, IO_OPCODE_SQ_WRITE, true);
	mutex_unlock(&sq_mbox->lock);

	return 0;
}

static long ioctl_send_cmds(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_cmds send_cmd;
	struct mx_mbox *sq_mbox;
	mbox_context_t ctx;
	uint64_t data_addr;
	uint32_t count = 0;

	if (copy_from_user(&send_cmd, (void __user *)arg, sizeof(send_cmd)))
		return -EFAULT;

	if (send_cmd.qid >= MAX_NUM_OF_MBOX || !mx_pdev->sq_mbox_list[send_cmd.qid])
		return -EINVAL;

	sq_mbox = mx_pdev->sq_mbox_list[send_cmd.qid];

	mutex_lock(&sq_mbox->lock);
	read_ctrl_from_device(mx_pdev, (char __user *)&ctx.u64, sizeof(uint64_t), (loff_t *)&sq_mbox->r_ctx_addr, IO_OPCODE_SQ_READ);
	sq_mbox->ctx.head = ctx.head;

	count = get_pushable_count(sq_mbox);
	if (count == 0)
		goto out;

	if (count > send_cmd.nr_cmds)
		count = send_cmd.nr_cmds;

	data_addr = sq_mbox->data_addr + get_data_offset(sq_mbox->ctx.tail);
	sq_mbox->ctx.tail = get_next_index(sq_mbox->ctx.tail, count, sq_mbox->depth);

	write_data_to_device(mx_pdev, (const char __user *)send_cmd.cmds, sizeof(uint64_t) * count, (loff_t *)&data_addr, IO_OPCODE_CONTEXT_WRITE, true);
	write_ctrl_to_device(mx_pdev, (const char __user *)&sq_mbox->ctx.u64, sizeof(uint64_t), (loff_t *)&sq_mbox->w_ctx_addr, IO_OPCODE_SQ_WRITE, true);

out:
	mutex_unlock(&sq_mbox->lock);

	send_cmd.nr_cmds = count;
	if (copy_to_user((void __user *)arg, &send_cmd, sizeof(send_cmd)))
		return -EFAULT;

	return 0;
}

static long ioctl_recv_cmds(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_cmds recv_cmd;
	struct mx_mbox *cq_mbox;
	mbox_context_t ctx;
	uint64_t data_addr;
	uint32_t count = 0;

	if (copy_from_user(&recv_cmd, (void __user *)arg, sizeof(recv_cmd)))
		return -EFAULT;

	if (recv_cmd.qid >= MAX_NUM_OF_MBOX || !mx_pdev->cq_mbox_list[recv_cmd.qid])
		return -EINVAL;

	if (recv_cmd.nr_cmds == 0 || !recv_cmd.cmds)
		return -EINVAL;

	cq_mbox = mx_pdev->cq_mbox_list[recv_cmd.qid];

	read_ctrl_from_device(mx_pdev, (char __user *)&ctx.u64, sizeof(uint64_t), (loff_t *)&cq_mbox->r_ctx_addr, IO_OPCODE_CQ_READ);
	cq_mbox->ctx.tail = ctx.tail;

	mutex_lock(&cq_mbox->lock);
	if (is_empty(cq_mbox))
		goto out;

	count = get_popable_count(cq_mbox);
	if (count > recv_cmd.nr_cmds)
		count = recv_cmd.nr_cmds;

	data_addr = cq_mbox->data_addr + get_data_offset(cq_mbox->ctx.head);
	cq_mbox->ctx.head = get_next_index(cq_mbox->ctx.head, count, cq_mbox->depth);

	read_data_from_device(mx_pdev, (char __user *)recv_cmd.cmds, count * sizeof(uint64_t), (loff_t *)&data_addr, IO_OPCODE_CONTEXT_READ);
	write_ctrl_to_device(mx_pdev, (const char __user *)&cq_mbox->ctx.u64, sizeof(uint64_t), (loff_t *)&cq_mbox->w_ctx_addr, IO_OPCODE_CQ_WRITE, true);

out:
	mutex_unlock(&cq_mbox->lock);

	recv_cmd.nr_cmds = count;
	if (copy_to_user((void __user *)arg, &recv_cmd, sizeof(recv_cmd)))
		return -EFAULT;

	return 0;
}

static long ioctl_read_data(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_data read_data;
	ssize_t ret;

	if (copy_from_user(&read_data, (void __user *)arg, sizeof(read_data)))
		return -EFAULT;

	if (read_data.size == 0 || !read_data.user_addr)
		return -EINVAL;

	ret = read_data_from_device_parallel(mx_pdev, (char __user *)read_data.user_addr, read_data.size,
			(loff_t *)&read_data.device_addr, IO_OPCODE_DATA_READ);
	if (ret < 0)
		return ret;

	return 0;
}

static long ioctl_write_data(struct mx_pci_dev *mx_pdev, unsigned long arg)
{
	struct mx_ioctl_data write_data;
	ssize_t ret;

	if (copy_from_user(&write_data, (void __user *)arg, sizeof(write_data)))
		return -EFAULT;

	if (write_data.size == 0 || !write_data.user_addr)
		return -EINVAL;

	ret = write_data_to_device_parallel(mx_pdev, (const char __user *)write_data.user_addr, write_data.size,
			(loff_t *)&write_data.device_addr, IO_OPCODE_DATA_WRITE, write_data.no_wait);
	if (ret < 0)
		return ret;

	return 0;
}

long ioctl_to_device(struct mx_pci_dev *mx_pdev, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case MX_IOCTL_REGISTER_MBOX:
			return ioctl_register_mbox(mx_pdev, arg);
		case MX_IOCTL_INIT_MBOX:
			return ioctl_init_mbox(mx_pdev, arg);
		case MX_IOCTL_SEND_CMD_WITH_DATA:
			return ioctl_send_cmd_with_data(mx_pdev, arg);
		case MX_IOCTL_RECV_CMDS:
			return ioctl_recv_cmds(mx_pdev, arg);
		case MX_IOCTL_SEND_CMDS:
			return ioctl_send_cmds(mx_pdev, arg);
		case MX_IOCTL_READ_DATA:
			return ioctl_read_data(mx_pdev, arg);
		case MX_IOCTL_WRITE_DATA:
			return ioctl_write_data(mx_pdev, arg);
		default:
			pr_warn("unknown ioctl cmd(%u)\n", cmd);
			return -EINVAL;
	}
}
