/*
 * xenbus_dev.c
 * 
 * Driver giving user-space access to the kernel's xenbus connection
 * to xenstore.
 * 
 * Copyright (c) 2005, Christian Limpach
 * Copyright (c) 2005, Rusty Russell, IBM Corporation
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

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/uio.h>
#include <linux/notifier.h>
#include <linux/wait.h>
#include <linux/fs.h>

#include "xenbus_comms.h"

#include <asm/uaccess.h>
#include <asm/hypervisor.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/xen_proc.h>
#include <asm-xen/linux-public/xenstored.h>

struct xenbus_dev_data {
	/* Are there bytes left to be read in this message? */
	int bytes_left;
	/* Are we still waiting for the reply to a message we wrote? */
	int awaiting_reply;
	/* Buffer for outgoing messages. */
	unsigned int len;
	union {
		struct xsd_sockmsg msg;
		char buffer[PAGE_SIZE];
	} u;
};

static struct proc_dir_entry *xenbus_dev_intf;

/* Reply can be long (dir, getperm): don't buffer, just examine
 * headers so we can discard rest if they die. */
static ssize_t xenbus_dev_read(struct file *filp,
			       char __user *ubuf,
			       size_t len, loff_t *ppos)
{
	struct xenbus_dev_data *data = filp->private_data;
	struct xsd_sockmsg msg;
	int err;

	/* Refill empty buffer? */
	if (data->bytes_left == 0) {
		if (len < sizeof(msg))
			return -EINVAL;

		err = xb_read(&msg, sizeof(msg));
		if (err)
			return err;
		data->bytes_left = msg.len;
		if (ubuf && copy_to_user(ubuf, &msg, sizeof(msg)) != 0)
			return -EFAULT;
		/* We can receive spurious XS_WATCH_EVENT messages. */
		if (msg.type != XS_WATCH_EVENT)
			data->awaiting_reply = 0;
		return sizeof(msg);
	}

	/* Don't read over next header, or over temporary buffer. */
	if (len > sizeof(data->u.buffer))
		len = sizeof(data->u.buffer);
	if (len > data->bytes_left)
		len = data->bytes_left;

	err = xb_read(data->u.buffer, len);
	if (err)
		return err;

	data->bytes_left -= len;
	if (ubuf && copy_to_user(ubuf, data->u.buffer, len) != 0)
		return -EFAULT;
	return len;
}

/* We do v. basic sanity checking so they don't screw up kernel later. */
static ssize_t xenbus_dev_write(struct file *filp,
				const char __user *ubuf,
				size_t len, loff_t *ppos)
{
	struct xenbus_dev_data *data = filp->private_data;
	int err;

	/* We gather data in buffer until we're ready to send it. */
	if (len > data->len + sizeof(data->u))
		return -EINVAL;
	if (copy_from_user(data->u.buffer + data->len, ubuf, len) != 0)
		return -EFAULT;
	data->len += len;
	if (data->len >= sizeof(data->u.msg) + data->u.msg.len) {
		err = xb_write(data->u.buffer, data->len);
		if (err)
			return err;
		data->len = 0;
		data->awaiting_reply = 1;
	}
	return len;
}

static int xenbus_dev_open(struct inode *inode, struct file *filp)
{
	struct xenbus_dev_data *u;

	if (xen_start_info->store_evtchn == 0)
		return -ENOENT;

	/* Don't try seeking. */
	nonseekable_open(inode, filp);

	u = kmalloc(sizeof(*u), GFP_KERNEL);
	if (u == NULL)
		return -ENOMEM;

	memset(u, 0, sizeof(*u));

	filp->private_data = u;

	down(&xenbus_lock);

	return 0;
}

static int xenbus_dev_release(struct inode *inode, struct file *filp)
{
	struct xenbus_dev_data *data = filp->private_data;

	/* Discard any unread replies. */
	while (data->bytes_left || data->awaiting_reply)
		xenbus_dev_read(filp, NULL, sizeof(data->u.buffer), NULL);

	/* Harmless if no transaction in progress. */
	xenbus_transaction_end(1);

	up(&xenbus_lock);

	kfree(data);

	return 0;
}

static struct file_operations xenbus_dev_file_ops = {
	.read = xenbus_dev_read,
	.write = xenbus_dev_write,
	.open = xenbus_dev_open,
	.release = xenbus_dev_release,
};

static int __init
xenbus_dev_init(void)
{
	xenbus_dev_intf = create_xen_proc_entry("xenbus", 0400);
	if (xenbus_dev_intf)
		xenbus_dev_intf->proc_fops = &xenbus_dev_file_ops;

	return 0;
}

__initcall(xenbus_dev_init);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
