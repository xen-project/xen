/*
 * xenbus_dev.c
 * 
 * Driver giving user-space access to the kernel's xenbus connection
 * to xenstore.
 * 
 * Copyright (c) 2005, Christian Limpach
 * Copyright (c) 2005, Rusty Russell, IBM Corporation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/uio.h>
#include <linux/notifier.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/mutex.h>

#include "xenbus_comms.h"

#include <asm/uaccess.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <xen/xen_proc.h>
#include <asm/hypervisor.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

struct xenbus_dev_transaction {
	struct list_head list;
	struct xenbus_transaction handle;
};

struct read_buffer {
	struct list_head list;
	unsigned int cons;
	unsigned int len;
	char msg[];
};

struct xenbus_dev_data {
	/* In-progress transaction. */
	struct list_head transactions;

	/* Active watches. */
	struct list_head watches;

	/* Partial request. */
	unsigned int len;
	union {
		struct xsd_sockmsg msg;
		char buffer[PAGE_SIZE];
	} u;

	/* Response queue. */
	struct list_head read_buffers;
	wait_queue_head_t read_waitq;

	struct mutex reply_mutex;
};

static struct proc_dir_entry *xenbus_dev_intf;

static ssize_t xenbus_dev_read(struct file *filp,
			       char __user *ubuf,
			       size_t len, loff_t *ppos)
{
	struct xenbus_dev_data *u = filp->private_data;
	struct read_buffer *rb;
	int i, ret;

	mutex_lock(&u->reply_mutex);
	while (list_empty(&u->read_buffers)) {
		mutex_unlock(&u->reply_mutex);
		ret = wait_event_interruptible(u->read_waitq,
					       !list_empty(&u->read_buffers));
		if (ret)
			return ret;
		mutex_lock(&u->reply_mutex);
	}

	rb = list_entry(u->read_buffers.next, struct read_buffer, list);
	for (i = 0; i < len;) {
		put_user(rb->msg[rb->cons], ubuf + i);
		i++;
		rb->cons++;
		if (rb->cons == rb->len) {
			list_del(&rb->list);
			kfree(rb);
			if (list_empty(&u->read_buffers))
				break;
			rb = list_entry(u->read_buffers.next,
					struct read_buffer, list);
		}
	}
	mutex_unlock(&u->reply_mutex);

	return i;
}

static void queue_reply(struct xenbus_dev_data *u,
			char *data, unsigned int len)
{
	struct read_buffer *rb;

	if (len == 0)
		return;

	rb = kmalloc(sizeof(*rb) + len, GFP_KERNEL);
	BUG_ON(rb == NULL);

	rb->cons = 0;
	rb->len = len;

	memcpy(rb->msg, data, len);

	list_add_tail(&rb->list, &u->read_buffers);

	wake_up(&u->read_waitq);
}

struct watch_adapter
{
	struct list_head list;
	struct xenbus_watch watch;
	struct xenbus_dev_data *dev_data;
	char *token;
};

static void free_watch_adapter (struct watch_adapter *watch)
{
	kfree(watch->watch.node);
	kfree(watch->token);
	kfree(watch);
}

static void watch_fired(struct xenbus_watch *watch,
			const char **vec,
			unsigned int len)
{
	struct watch_adapter *adap =
            container_of(watch, struct watch_adapter, watch);
	struct xsd_sockmsg hdr;
	const char *path, *token;
	int path_len, tok_len, body_len;

	path = vec[XS_WATCH_PATH];
	token = adap->token;

	path_len = strlen(path) + 1;
	tok_len = strlen(token) + 1;
	body_len = path_len + tok_len;

	hdr.type = XS_WATCH_EVENT;
	hdr.len = body_len;

	mutex_lock(&adap->dev_data->reply_mutex);
	queue_reply(adap->dev_data, (char *)&hdr, sizeof(hdr));
	queue_reply(adap->dev_data, (char *)path, path_len);
	queue_reply(adap->dev_data, (char *)token, tok_len);
	mutex_unlock(&adap->dev_data->reply_mutex);
}

static LIST_HEAD(watch_list);

static ssize_t xenbus_dev_write(struct file *filp,
				const char __user *ubuf,
				size_t len, loff_t *ppos)
{
	struct xenbus_dev_data *u = filp->private_data;
	struct xenbus_dev_transaction *trans = NULL;
	uint32_t msg_type;
	void *reply;
	char *path, *token;
	struct watch_adapter *watch, *tmp_watch;
	int err, rc = len;

	if ((len + u->len) > sizeof(u->u.buffer)) {
		rc = -EINVAL;
		goto out;
	}

	if (copy_from_user(u->u.buffer + u->len, ubuf, len) != 0) {
		rc = -EFAULT;
		goto out;
	}

	u->len += len;
	if ((u->len < sizeof(u->u.msg)) ||
	    (u->len < (sizeof(u->u.msg) + u->u.msg.len)))
		return rc;

	msg_type = u->u.msg.type;

	switch (msg_type) {
	case XS_TRANSACTION_START:
	case XS_TRANSACTION_END:
	case XS_DIRECTORY:
	case XS_READ:
	case XS_GET_PERMS:
	case XS_RELEASE:
	case XS_GET_DOMAIN_PATH:
	case XS_WRITE:
	case XS_MKDIR:
	case XS_RM:
	case XS_SET_PERMS:
		if (msg_type == XS_TRANSACTION_START) {
			trans = kmalloc(sizeof(*trans), GFP_KERNEL);
			if (!trans) {
				rc = -ENOMEM;
				goto out;
			}
		}

		reply = xenbus_dev_request_and_reply(&u->u.msg);
		if (IS_ERR(reply)) {
			kfree(trans);
			rc = PTR_ERR(reply);
			goto out;
		}

		if (msg_type == XS_TRANSACTION_START) {
			trans->handle.id = simple_strtoul(reply, NULL, 0);
			list_add(&trans->list, &u->transactions);
		} else if (msg_type == XS_TRANSACTION_END) {
			list_for_each_entry(trans, &u->transactions, list)
				if (trans->handle.id == u->u.msg.tx_id)
					break;
			BUG_ON(&trans->list == &u->transactions);
			list_del(&trans->list);
			kfree(trans);
		}
		mutex_lock(&u->reply_mutex);
		queue_reply(u, (char *)&u->u.msg, sizeof(u->u.msg));
		queue_reply(u, (char *)reply, u->u.msg.len);
		mutex_unlock(&u->reply_mutex);
		kfree(reply);
		break;

	case XS_WATCH:
	case XS_UNWATCH: {
		static const char *XS_RESP = "OK";
		struct xsd_sockmsg hdr;

		path = u->u.buffer + sizeof(u->u.msg);
		token = memchr(path, 0, u->u.msg.len);
		if (token == NULL) {
			rc = -EILSEQ;
			goto out;
		}
		token++;

		if (msg_type == XS_WATCH) {
			watch = kmalloc(sizeof(*watch), GFP_KERNEL);
			watch->watch.node = kmalloc(strlen(path)+1,
                                                    GFP_KERNEL);
			strcpy((char *)watch->watch.node, path);
			watch->watch.callback = watch_fired;
			watch->token = kmalloc(strlen(token)+1, GFP_KERNEL);
			strcpy(watch->token, token);
			watch->dev_data = u;

			err = register_xenbus_watch(&watch->watch);
			if (err) {
				free_watch_adapter(watch);
				rc = err;
				goto out;
			}
			
			list_add(&watch->list, &u->watches);
		} else {
			list_for_each_entry_safe(watch, tmp_watch,
                                                 &u->watches, list) {
				if (!strcmp(watch->token, token) &&
				    !strcmp(watch->watch.node, path))
				{
					unregister_xenbus_watch(&watch->watch);
					list_del(&watch->list);
					free_watch_adapter(watch);
					break;
				}
			}
		}

		hdr.type = msg_type;
		hdr.len = strlen(XS_RESP) + 1;
		mutex_lock(&u->reply_mutex);
		queue_reply(u, (char *)&hdr, sizeof(hdr));
		queue_reply(u, (char *)XS_RESP, hdr.len);
		mutex_unlock(&u->reply_mutex);
		break;
	}

	default:
		rc = -EINVAL;
		break;
	}

 out:
	u->len = 0;
	return rc;
}

static int xenbus_dev_open(struct inode *inode, struct file *filp)
{
	struct xenbus_dev_data *u;

	if (xen_store_evtchn == 0)
		return -ENOENT;

	nonseekable_open(inode, filp);

	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (u == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&u->transactions);
	INIT_LIST_HEAD(&u->watches);
	INIT_LIST_HEAD(&u->read_buffers);
	init_waitqueue_head(&u->read_waitq);

	mutex_init(&u->reply_mutex);

	filp->private_data = u;

	return 0;
}

static int xenbus_dev_release(struct inode *inode, struct file *filp)
{
	struct xenbus_dev_data *u = filp->private_data;
	struct xenbus_dev_transaction *trans, *tmp;
	struct watch_adapter *watch, *tmp_watch;

	list_for_each_entry_safe(trans, tmp, &u->transactions, list) {
		xenbus_transaction_end(trans->handle, 1);
		list_del(&trans->list);
		kfree(trans);
	}

	list_for_each_entry_safe(watch, tmp_watch, &u->watches, list) {
		unregister_xenbus_watch(&watch->watch);
		list_del(&watch->list);
		free_watch_adapter(watch);
	}

	kfree(u);

	return 0;
}

static unsigned int xenbus_dev_poll(struct file *file, poll_table *wait)
{
	struct xenbus_dev_data *u = file->private_data;

	poll_wait(file, &u->read_waitq, wait);
	if (!list_empty(&u->read_buffers))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct file_operations xenbus_dev_file_ops = {
	.read = xenbus_dev_read,
	.write = xenbus_dev_write,
	.open = xenbus_dev_open,
	.release = xenbus_dev_release,
	.poll = xenbus_dev_poll,
};

int xenbus_dev_init(void)
{
	xenbus_dev_intf = create_xen_proc_entry("xenbus", 0400);
	if (xenbus_dev_intf)
		xenbus_dev_intf->proc_fops = &xenbus_dev_file_ops;

	return 0;
}
