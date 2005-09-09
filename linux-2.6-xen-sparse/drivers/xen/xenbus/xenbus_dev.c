/*
 * xenbus_dev.c
 * 
 * Driver giving user-space access to the kernel's xenbus connection
 * to xenstore.
 * 
 * Copyright (c) 2005, Christian Limpach
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

#include "xenstored.h"
#include "xenbus_comms.h"

#include <asm/uaccess.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/linux-public/xenbus_dev.h>
#include <asm-xen/xen_proc.h>

struct xenbus_dev_data {
	int in_transaction;
};

static struct proc_dir_entry *xenbus_dev_intf;

void *xs_talkv(enum xsd_sockmsg_type type, const struct kvec *iovec,
	       unsigned int num_vecs, unsigned int *len);

static int xenbus_dev_talkv(struct xenbus_dev_data *u, unsigned long data)
{
	struct xenbus_dev_talkv xt;
	unsigned int len;
	void *resp, *base;
	struct kvec *iovec;
	int ret = -EFAULT, v = 0;

	if (copy_from_user(&xt, (void *)data, sizeof(xt)))
		return -EFAULT;

	iovec = kmalloc(xt.num_vecs * sizeof(struct kvec), GFP_KERNEL);
	if (iovec == NULL)
		return -ENOMEM;

	if (copy_from_user(iovec, xt.iovec,
			   xt.num_vecs * sizeof(struct kvec)))
		goto out;

	for (v = 0; v < xt.num_vecs; v++) {
		base = iovec[v].iov_base;
		iovec[v].iov_base = kmalloc(iovec[v].iov_len, GFP_KERNEL);
		if (iovec[v].iov_base == NULL ||
		    copy_from_user(iovec[v].iov_base, base, iovec[v].iov_len))
		{
			if (iovec[v].iov_base)
				kfree(iovec[v].iov_base);
			else
				ret = -ENOMEM;
			v--;
			goto out;
		}
	}

	resp = xs_talkv(xt.type, iovec, xt.num_vecs, &len);
	if (IS_ERR(resp)) {
		ret = PTR_ERR(resp);
		goto out;
	}

	switch (xt.type) {
	case XS_TRANSACTION_START:
		u->in_transaction = 1;
		break;
	case XS_TRANSACTION_END:
		u->in_transaction = 0;
		break;
	default:
		break;
	}

	ret = len;
	if (len > xt.len)
		len = xt.len;

	if (copy_to_user(xt.buf, resp, len))
		ret = -EFAULT;

	kfree(resp);
 out:
	while (v-- > 0)
		kfree(iovec[v].iov_base);
	kfree(iovec);
	return ret;
}

static int xenbus_dev_ioctl(struct inode *inode, struct file *filp,
			    unsigned int cmd, unsigned long data)
{
	struct xenbus_dev_data *u = filp->private_data;
	int ret = -ENOSYS;

	switch (cmd) {
	case IOCTL_XENBUS_DEV_TALKV:
		ret = xenbus_dev_talkv(u, data);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int xenbus_dev_open(struct inode *inode, struct file *filp)
{
	struct xenbus_dev_data *u;

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
	struct xenbus_dev_data *u = filp->private_data;

	if (u->in_transaction)
		xenbus_transaction_end(1);

	up(&xenbus_lock);

	kfree(u);

	return 0;
}

static struct file_operations xenbus_dev_file_ops = {
	ioctl: xenbus_dev_ioctl,
	open: xenbus_dev_open,
	release: xenbus_dev_release
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
