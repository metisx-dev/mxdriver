// SPDX-License-Identifier: <SPDX License Expression>

#include "mx_dma.h"

bool is_empty(struct mx_mbox *mbox)
{
	return mbox->ctx.head == mbox->ctx.tail;
}

bool is_full(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	return (head.index == tail.index) && (head.phase != tail.phase);
}

uint32_t get_free_space(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	return head.index - tail.index + mbox->depth * (1 - (head.phase ^ tail.phase));
}

uint32_t get_pending_count(struct mx_mbox *mbox)
{
	mbox_index_t head, tail;

	head.full = mbox->ctx.head;
	tail.full = mbox->ctx.tail;

	return tail.index - head.index + mbox->depth * (head.phase ^ tail.phase);
}

uint8_t get_next_index(uint8_t _index, uint32_t count, uint32_t depth)
{
	mbox_index_t last, next;

	last.full = _index;
	next.full = _index;

	next.index = (next.index + count) & (depth - 1);
	if (count && (next.index <= last.index))
		next.phase ^= 1;

	return next.full;
}

uint32_t get_data_offset(uint8_t _db)
{
	mbox_index_t db;

	db.full = _db;

	return sizeof(uint64_t) * db.index;
}

void mx_mbox_init(struct mx_mbox *mbox, uint64_t ctx_addr, uint64_t data_addr, uint64_t ctx)
{
	mbox->ctx.u64 = ctx;
	mbox->r_ctx_addr = ctx_addr;
	mbox->w_ctx_addr = ctx_addr | HMBOX_UPDATE_BITMASK;
	mbox->data_addr = data_addr + sizeof(uint64_t) * mbox->ctx.data_base;
	mbox->depth = BIT(mbox->ctx.q_size);
}
