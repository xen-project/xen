/******************************************************************************
 * xenbus_comms.c
 *
 * Low level code to talks to Xen Store: ringbuffer and event channel.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <asm-xen/hypervisor.h>
#include <asm-xen/evtchn.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/err.h>
#include "xenbus_comms.h"

#define RINGBUF_DATASIZE ((PAGE_SIZE / 2) - sizeof(struct ringbuf_head))
struct ringbuf_head
{
	u32 write; /* Next place to write to */
	u32 read; /* Next place to read from */
	u8 flags;
	char buf[0];
} __attribute__((packed));

DECLARE_WAIT_QUEUE_HEAD(xb_waitq);

static inline struct ringbuf_head *outbuf(void)
{
	return mfn_to_virt(xen_start_info->store_mfn);
}

static inline struct ringbuf_head *inbuf(void)
{
	return mfn_to_virt(xen_start_info->store_mfn) + PAGE_SIZE/2;
}

static irqreturn_t wake_waiting(int irq, void *unused, struct pt_regs *regs)
{
	wake_up(&xb_waitq);
	return IRQ_HANDLED;
}

static int check_buffer(const struct ringbuf_head *h)
{
	return (h->write < RINGBUF_DATASIZE && h->read < RINGBUF_DATASIZE);
}

/* We can't fill last byte: would look like empty buffer. */
static void *get_output_chunk(const struct ringbuf_head *h,
			      void *buf, u32 *len)
{
	u32 read_mark;

	if (h->read == 0)
		read_mark = RINGBUF_DATASIZE - 1;
	else
		read_mark = h->read - 1;

	/* Here to the end of buffer, unless they haven't read some out. */
	*len = RINGBUF_DATASIZE - h->write;
	if (read_mark >= h->write)
		*len = read_mark - h->write;
	return buf + h->write;
}

static const void *get_input_chunk(const struct ringbuf_head *h,
				   const void *buf, u32 *len)
{
	/* Here to the end of buffer, unless they haven't written some. */
	*len = RINGBUF_DATASIZE - h->read;
	if (h->write >= h->read)
		*len = h->write - h->read;
	return buf + h->read;
}

static void update_output_chunk(struct ringbuf_head *h, u32 len)
{
	h->write += len;
	if (h->write == RINGBUF_DATASIZE)
		h->write = 0;
}

static void update_input_chunk(struct ringbuf_head *h, u32 len)
{
	h->read += len;
	if (h->read == RINGBUF_DATASIZE)
		h->read = 0;
}

static int output_avail(struct ringbuf_head *out)
{
	unsigned int avail;

	get_output_chunk(out, out->buf, &avail);
	return avail != 0;
}

int xb_write(const void *data, unsigned len)
{
	struct ringbuf_head h;
	struct ringbuf_head *out = outbuf();

	do {
		void *dst;
		unsigned int avail;

		wait_event(xb_waitq, output_avail(out));

		/* Read, then check: not that we don't trust store.
		 * Hell, some of my best friends are daemons.  But,
		 * in this post-911 world... */
		h = *out;
		mb();
		if (!check_buffer(&h)) {
			set_current_state(TASK_RUNNING);
			return -EIO; /* ETERRORIST! */
		}

		dst = get_output_chunk(&h, out->buf, &avail);
		if (avail > len)
			avail = len;
		memcpy(dst, data, avail);
		data += avail;
		len -= avail;
		update_output_chunk(out, avail);
		notify_via_evtchn(xen_start_info->store_evtchn);
	} while (len != 0);

	return 0;
}

int xs_input_avail(void)
{
	unsigned int avail;
	struct ringbuf_head *in = inbuf();

	get_input_chunk(in, in->buf, &avail);
	return avail != 0;
}

int xb_read(void *data, unsigned len)
{
	struct ringbuf_head h;
	struct ringbuf_head *in = inbuf();
	int was_full;

	while (len != 0) {
		unsigned int avail;
		const char *src;

		wait_event(xb_waitq, xs_input_avail());
		h = *in;
		mb();
		if (!check_buffer(&h)) {
			set_current_state(TASK_RUNNING);
			return -EIO;
		}

		src = get_input_chunk(&h, in->buf, &avail);
		if (avail > len)
			avail = len;
		was_full = !output_avail(&h);

		memcpy(data, src, avail);
		data += avail;
		len -= avail;
		update_input_chunk(in, avail);
		pr_debug("Finished read of %i bytes (%i to go)\n", avail, len);
		/* If it was full, tell them we've taken some. */
		if (was_full)
			notify_via_evtchn(xen_start_info->store_evtchn);
	}

	/* If we left something, wake watch thread to deal with it. */
	if (xs_input_avail())
		wake_up(&xb_waitq);

	return 0;
}

/* Set up interrupt handler off store event channel. */
int xb_init_comms(void)
{
	int err;

	if (!xen_start_info->store_evtchn)
		return 0;

	err = bind_evtchn_to_irqhandler(
		xen_start_info->store_evtchn, wake_waiting,
		0, "xenbus", &xb_waitq);
	if (err) {
		printk(KERN_ERR "XENBUS request irq failed %i\n", err);
		unbind_evtchn_from_irq(xen_start_info->store_evtchn);
		return err;
	}

	/* FIXME zero out page -- domain builder should probably do this*/
	memset(mfn_to_virt(xen_start_info->store_mfn), 0, PAGE_SIZE);

	return 0;
}

void xb_suspend_comms(void)
{

	if (!xen_start_info->store_evtchn)
		return;

	unbind_evtchn_from_irqhandler(xen_start_info->store_evtchn, &xb_waitq);
}
