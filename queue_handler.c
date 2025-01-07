// SPDX-License-Identifier: <SPDX License Expression>

#include <linux/atomic.h>

#include "mx_dma.h"

atomic_t wait_count = ATOMIC_INIT(0);

static int set_wait_count(const char *val, const struct kernel_param *kp)
{
	atomic_set(&wait_count, 0);
	return 0;
}

static int get_wait_count(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%d\n", atomic_read(&wait_count));
}

const struct kernel_param_ops wait_count_ops = {
	.set = &set_wait_count,
	.get = &get_wait_count,
};

module_param_cb(wait_count, &wait_count_ops, &wait_count, 0664);

/******************************************************************************/
/* Helpers                                                                    */
/******************************************************************************/
static inline int get_free_space(uint8_t _head, uint8_t _tail, uint32_t depth)
{
	mbox_index_t head, tail;

	head.full = _head;
	tail.full = _tail;

	return head.index - tail.index + depth * (1 - (head.phase ^ tail.phase));
}

static inline int get_pending_count(uint8_t _head, uint8_t _tail, uint32_t depth)
{
	mbox_index_t head, tail;

	head.full = _head;
	tail.full = _tail;

	return tail.index - head.index + depth * (head.phase ^ tail.phase);
}

static inline bool is_pushable(struct mx_mbox *mbox)
{
	uint64_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	mbox_context_t ctx;

	ctx.u64 = readq(mbox->ctx_addr);

	return get_free_space(ctx.head, ctx.tail, mbox->depth) >= data_count;
}

static inline bool is_popable(struct mx_mbox *mbox)
{
	uint64_t data_count = sizeof(struct mx_command) / sizeof(uint64_t);
	mbox_context_t ctx;

	ctx.u64 = readq(mbox->ctx_addr);

	return get_pending_count(ctx.head, ctx.tail, mbox->depth) >= data_count;
}

static inline uint8_t get_next_index(uint8_t _index, uint32_t count, uint32_t depth)
{
	mbox_index_t last, next;

	last.full = _index;
	next.full = _index;

	next.index = (next.index + count) & (depth - 1);
	if (count && (next.index <= last.index))
		next.phase ^= 1;

	return next.full;
}

static inline void __iomem *get_data_addr(void __iomem *base, uint8_t _db)
{
	mbox_index_t db;

	db.full = _db;

	return base + (sizeof(uint64_t) * db.index);
}

static void push_mx_command(struct mx_mbox *mbox, struct mx_command *comm)
{
	mbox_context_t ctx;
	void __iomem *data_addr;
	void __iomem *db_addr;

	ctx.u64 = readq(mbox->ctx_addr);

	data_addr = get_data_addr(mbox->data_addr, ctx.tail);
	writeq(comm->header, data_addr);
	writeq(comm->length, data_addr + 0x8);
	writeq(comm->device_addr, data_addr + 0x10);
	writeq(comm->host_addr, data_addr + 0x18);

	db_addr = mbox->ctx_addr + HMBOX_UPDATE_BITMASK + HMBOX_DB_OFFSET;
	ctx.tail = get_next_index(ctx.tail, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writel(ctx.u32[1], db_addr);

	pr_debug_dma("[SQ] id=%u opcode=%u ep_addr=%#llx host_addr=%#llx size=%#llx",
			comm->id, comm->opcode, comm->device_addr, comm->host_addr, comm->length);
}

static void pop_mx_command(struct mx_mbox *mbox, struct mx_command *comm)
{
	mbox_context_t ctx;
	void __iomem *data_addr;
	void __iomem *db_addr;

	ctx.u64 = readq(mbox->ctx_addr);

	data_addr = get_data_addr(mbox->data_addr, ctx.head);
	comm->header = readq(data_addr);
	comm->length = readq(data_addr + 0x8);
	comm->device_addr = readq(data_addr + 0x10);
	comm->host_addr= readq(data_addr + 0x18);

	db_addr = mbox->ctx_addr + HMBOX_UPDATE_BITMASK + HMBOX_DB_OFFSET;
	ctx.head = get_next_index(ctx.head, sizeof(struct mx_command) / sizeof(uint64_t), mbox->depth);
	writel(ctx.u32[1], db_addr);

	pr_debug_dma("[CQ] id=%u opcode=%u ep_addr=%#llx host_addr=%#llx size=%#llx",
			comm->id, comm->opcode, comm->device_addr, comm->host_addr, comm->length);
}

/******************************************************************************/
/* MX submit/complete handler                                                 */
/******************************************************************************/
int mx_command_submit_handler(void *arg)
{
	struct mx_engine *engine = (struct mx_engine *)arg;
	struct mx_mbox *sq_mbox;
	struct mx_transfer *transfer;
	unsigned long flags;

	if (engine->magic != MAGIC_ENGINE)
		return -EINVAL;

	sq_mbox = &engine->submit;

	while (kthread_should_stop() == false) {
		if (list_empty(&sq_mbox->wait_list) == false && is_pushable(sq_mbox) == true) {
			spin_lock_irqsave(&sq_mbox->lock, flags);
			transfer = list_first_entry(&sq_mbox->wait_list, struct mx_transfer, entry);
			list_del(&transfer->entry);
			spin_unlock_irqrestore(&sq_mbox->lock, flags);

			atomic_inc(&wait_count);
			push_mx_command(sq_mbox, &transfer->cmd);
		} else {
			msleep(SQ_POLLING_MSEC);
		}
	}

	return 0;
}

int mx_command_complete_handler(void *arg)
{
	struct mx_engine *engine = (struct mx_engine *)arg;
	struct mx_mbox *cq_mbox;
	struct mx_transfer *transfer;
	struct mx_command cmd;

	if (engine->magic != MAGIC_ENGINE)
		return -EINVAL;

	cq_mbox = &engine->complete;

	while (kthread_should_stop() == false) {
		if (atomic_read(&wait_count) > 0 && is_popable(cq_mbox) == true) {
			pop_mx_command(cq_mbox, &cmd);
			atomic_dec(&wait_count);

			if (cmd.magic != MAGIC_COMMAND) {
				pr_warn("magic of mx_command is wrong. cmd=expected=%#x real=%#x\n",
						MAGIC_COMMAND, cmd.magic);
				continue;
			}

			transfer = find_transfer_by_id(cmd.id);
			if (transfer == NULL) {
				pr_warn("Can't find transfer by id=%u. Maybe timeout\n", cmd.id);
				continue;
			}

			transfer->cmd.header = cmd.header;
			transfer->cmd.host_addr = cmd.host_addr;
			complete(&transfer->done);
		} else {
			msleep(CQ_POLLING_MSEC);
		}
	}

	return 0;
}

