/******************************************************************************
 * xenbus_xs.c
 *
 * This is the kernel equivalent of the "xs" library.  We don't need everything
 * and we use xenbus_comms for communication.
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

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/kthread.h>
#include <asm-xen/xenbus.h>
#include "xenstored.h"
#include "xenbus_comms.h"

#define streq(a, b) (strcmp((a), (b)) == 0)

static char printf_buffer[4096];
static LIST_HEAD(watches);

DECLARE_MUTEX(xenbus_lock);
EXPORT_SYMBOL(xenbus_lock);

static int get_error(const char *errorstring)
{
	unsigned int i;

	for (i = 0; !streq(errorstring, xsd_errors[i].errstring); i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			printk(KERN_WARNING
			       "XENBUS xen store gave: unknown error %s",
			       errorstring);
			return EINVAL;
		}
	}
	return xsd_errors[i].errnum;
}

static void *read_reply(enum xsd_sockmsg_type *type, unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret;
	int err;

	err = xb_read(&msg, sizeof(msg));
	if (err)
		return ERR_PTR(err);

	ret = kmalloc(msg.len + 1, GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	err = xb_read(ret, msg.len);
	if (err) {
		kfree(ret);
		return ERR_PTR(err);
	}
	((char*)ret)[msg.len] = '\0';

	*type = msg.type;
	if (len)
		*len = msg.len;
	return ret;
}

/* Emergency write. */
void xenbus_debug_write(const char *str, unsigned int count)
{
	struct xsd_sockmsg msg;

	msg.type = XS_DEBUG;
	msg.len = sizeof("print") + count + 1;

	xb_write(&msg, sizeof(msg));
	xb_write("print", sizeof("print"));
	xb_write(str, count);
	xb_write("", 1);
}

/* Send message to xs, get kmalloc'ed reply.  ERR_PTR() on error. */
void *xs_talkv(enum xsd_sockmsg_type type,
	       const struct kvec *iovec,
	       unsigned int num_vecs,
	       unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret = NULL;
	unsigned int i;
	int err;

	WARN_ON(down_trylock(&xenbus_lock) == 0);

	msg.type = type;
	msg.len = 0;
	for (i = 0; i < num_vecs; i++)
		msg.len += iovec[i].iov_len;

	err = xb_write(&msg, sizeof(msg));
	if (err)
		return ERR_PTR(err);

	for (i = 0; i < num_vecs; i++) {
		err = xb_write(iovec[i].iov_base, iovec[i].iov_len);;
		if (err)
			return ERR_PTR(err);
	}

	/* Watches can have fired before reply comes: daemon detects
	 * and re-transmits, so we can ignore this. */
	do {
		kfree(ret);
		ret = read_reply(&msg.type, len);
		if (IS_ERR(ret))
			return ret;
	} while (msg.type == XS_WATCH_EVENT);

	if (msg.type == XS_ERROR) {
		err = get_error(ret);
		kfree(ret);
		return ERR_PTR(-err);
	}

	BUG_ON(msg.type != type);
	return ret;
}

/* Simplified version of xs_talkv: single message. */
static void *xs_single(enum xsd_sockmsg_type type,
		       const char *string, unsigned int *len)
{
	struct kvec iovec;

	iovec.iov_base = (void *)string;
	iovec.iov_len = strlen(string) + 1;
	return xs_talkv(type, &iovec, 1, len);
}

/* Many commands only need an ack, don't care what it says. */
static int xs_error(char *reply)
{
	if (IS_ERR(reply))
		return PTR_ERR(reply);
	kfree(reply);
	return 0;
}

static unsigned int count_strings(const char *strings, unsigned int len)
{
	unsigned int num;
	const char *p;

	for (p = strings, num = 0; p < strings + len; p += strlen(p) + 1)
		num++;

	return num;
}

/* Return the path to dir with /name appended. */ 
static char *join(const char *dir, const char *name)
{
	static char buffer[4096];

	BUG_ON(down_trylock(&xenbus_lock) == 0);
	/* XXX FIXME: might not be correct if name == "" */
	BUG_ON(strlen(dir) + strlen("/") + strlen(name) + 1 > sizeof(buffer));

	strcpy(buffer, dir);
	if (!streq(name, "")) {
		strcat(buffer, "/");
		strcat(buffer, name);
	}
	return buffer;
}

char **xenbus_directory(const char *dir, const char *node, unsigned int *num)
{
	char *strings, *p, **ret;
	unsigned int len;

	strings = xs_single(XS_DIRECTORY, join(dir, node), &len);
	if (IS_ERR(strings))
		return (char **)strings;

	/* Count the strings. */
	*num = count_strings(strings, len);

	/* Transfer to one big alloc for easy freeing. */
	ret = kmalloc(*num * sizeof(char *) + len, GFP_ATOMIC);
	if (!ret) {
		kfree(strings);
		return ERR_PTR(-ENOMEM);
	}
	memcpy(&ret[*num], strings, len);
	kfree(strings);

	strings = (char *)&ret[*num];
	for (p = strings, *num = 0; p < strings + len; p += strlen(p) + 1)
		ret[(*num)++] = p;
	return ret;
}
EXPORT_SYMBOL(xenbus_directory);

/* Check if a path exists. Return 1 if it does. */
int xenbus_exists(const char *dir, const char *node)
{
	char **d;
	int dir_n;

	d = xenbus_directory(dir, node, &dir_n);
	if (IS_ERR(d))
		return 0;
	kfree(d);
	return 1;
}
EXPORT_SYMBOL(xenbus_exists);

/* Get the value of a single file.
 * Returns a kmalloced value: call free() on it after use.
 * len indicates length in bytes.
 */
void *xenbus_read(const char *dir, const char *node, unsigned int *len)
{
	return xs_single(XS_READ, join(dir, node), len);
}
EXPORT_SYMBOL(xenbus_read);

/* Write the value of a single file.
 * Returns -err on failure.  createflags can be 0, O_CREAT, or O_CREAT|O_EXCL.
 */
int xenbus_write(const char *dir, const char *node,
		 const char *string, int createflags)
{
	const char *flags, *path;
	struct kvec iovec[3];

	path = join(dir, node);
	/* Format: Flags (as string), path, data. */
	if (createflags == 0)
		flags = XS_WRITE_NONE;
	else if (createflags == O_CREAT)
		flags = XS_WRITE_CREATE;
	else if (createflags == (O_CREAT|O_EXCL))
		flags = XS_WRITE_CREATE_EXCL;
	else
		return -EINVAL;

	iovec[0].iov_base = (void *)path;
	iovec[0].iov_len = strlen(path) + 1;
	iovec[1].iov_base = (void *)flags;
	iovec[1].iov_len = strlen(flags) + 1;
	iovec[2].iov_base = (void *)string;
	iovec[2].iov_len = strlen(string);

	return xs_error(xs_talkv(XS_WRITE, iovec, ARRAY_SIZE(iovec), NULL));
}
EXPORT_SYMBOL(xenbus_write);

/* Create a new directory. */
int xenbus_mkdir(const char *dir, const char *node)
{
	return xs_error(xs_single(XS_MKDIR, join(dir, node), NULL));
}
EXPORT_SYMBOL(xenbus_mkdir);

/* Destroy a file or directory (directories must be empty). */
int xenbus_rm(const char *dir, const char *node)
{
	return xs_error(xs_single(XS_RM, join(dir, node), NULL));
}
EXPORT_SYMBOL(xenbus_rm);

/* Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 * Transaction only applies to the given subtree.
 * You can only have one transaction at any time.
 */
int xenbus_transaction_start(const char *subtree)
{
	return xs_error(xs_single(XS_TRANSACTION_START, subtree, NULL));
}
EXPORT_SYMBOL(xenbus_transaction_start);

/* End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 */
int xenbus_transaction_end(int abort)
{
	char abortstr[2];

	if (abort)
		strcpy(abortstr, "F");
	else
		strcpy(abortstr, "T");
	return xs_error(xs_single(XS_TRANSACTION_END, abortstr, NULL));
}
EXPORT_SYMBOL(xenbus_transaction_end);

/* Single read and scanf: returns -errno or num scanned. */
int xenbus_scanf(const char *dir, const char *node, const char *fmt, ...)
{
	va_list ap;
	int ret;
	char *val;

	val = xenbus_read(dir, node, NULL);
	if (IS_ERR(val))
		return PTR_ERR(val);

	va_start(ap, fmt);
	ret = vsscanf(val, fmt, ap);
	va_end(ap);
	kfree(val);
	/* Distinctive errno. */
	if (ret == 0)
		return -ERANGE;
	return ret;
}
EXPORT_SYMBOL(xenbus_scanf);

/* Single printf and write: returns -errno or 0. */
int xenbus_printf(const char *dir, const char *node, const char *fmt, ...)
{
	va_list ap;
	int ret;

	BUG_ON(down_trylock(&xenbus_lock) == 0);
	va_start(ap, fmt);
	ret = vsnprintf(printf_buffer, sizeof(printf_buffer), fmt, ap);
	va_end(ap);

	BUG_ON(ret > sizeof(printf_buffer)-1);
	return xenbus_write(dir, node, printf_buffer, O_CREAT);
}
EXPORT_SYMBOL(xenbus_printf);

/* Report a (negative) errno into the store, with explanation. */
void xenbus_dev_error(struct xenbus_device *dev, int err, const char *fmt, ...)
{
	va_list ap;
	int ret;
	unsigned int len;

	BUG_ON(down_trylock(&xenbus_lock) == 0);

	len = sprintf(printf_buffer, "%i ", -err);
	va_start(ap, fmt);
	ret = vsnprintf(printf_buffer+len, sizeof(printf_buffer)-len, fmt, ap);
	va_end(ap);

	BUG_ON(len + ret > sizeof(printf_buffer)-1);
	dev->has_error = 1;
	if (xenbus_write(dev->nodename, "error", printf_buffer, O_CREAT) != 0)
		printk("xenbus: failed to write error node for %s (%s)\n",
		       dev->nodename, printf_buffer);
}
EXPORT_SYMBOL(xenbus_dev_error);

/* Clear any error. */
void xenbus_dev_ok(struct xenbus_device *dev)
{
	if (dev->has_error) {
		if (xenbus_rm(dev->nodename, "error") != 0)
			printk("xenbus: failed to clear error node for %s\n",
			       dev->nodename);
		else
			dev->has_error = 0;
	}
}
EXPORT_SYMBOL(xenbus_dev_ok);
	
/* Takes tuples of names, scanf-style args, and void **, NULL terminated. */
int xenbus_gather(const char *dir, ...)
{
	va_list ap;
	const char *name;
	int ret = 0;

	va_start(ap, dir);
	while (ret == 0 && (name = va_arg(ap, char *)) != NULL) {
		const char *fmt = va_arg(ap, char *);
		void *result = va_arg(ap, void *);
		char *p;

		p = xenbus_read(dir, name, NULL);
		if (IS_ERR(p)) {
			ret = PTR_ERR(p);
			break;
		}
		if (fmt) {
			if (sscanf(p, fmt, result) == 0)
				ret = -EINVAL;
			kfree(p);
		} else
			*(char **)result = p;
	}
	va_end(ap);
	return ret;
}
EXPORT_SYMBOL(xenbus_gather);

static int xs_watch(const char *path, const char *token)
{
	struct kvec iov[2];

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (void *)token;
	iov[1].iov_len = strlen(token) + 1;

	return xs_error(xs_talkv(XS_WATCH, iov, ARRAY_SIZE(iov), NULL));
}

static char *xs_read_watch(char **token)
{
	enum xsd_sockmsg_type type;
	char *ret;

	ret = read_reply(&type, NULL);
	if (IS_ERR(ret))
		return ret;

	BUG_ON(type != XS_WATCH_EVENT);
	*token = ret + strlen(ret) + 1;
	return ret;
}

static int xs_acknowledge_watch(const char *token)
{
	return xs_error(xs_single(XS_WATCH_ACK, token, NULL));
}

static int xs_unwatch(const char *path, const char *token)
{
	struct kvec iov[2];

	iov[0].iov_base = (char *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (char *)token;
	iov[1].iov_len = strlen(token) + 1;

	return xs_error(xs_talkv(XS_UNWATCH, iov, ARRAY_SIZE(iov), NULL));
}

/* A little paranoia: we don't just trust token. */
static struct xenbus_watch *find_watch(const char *token)
{
	struct xenbus_watch *i, *cmp;

	cmp = (void *)simple_strtoul(token, NULL, 16);

	list_for_each_entry(i, &watches, list)
		if (i == cmp)
			return i;
	return NULL;
}

/* Register callback to watch this node. */
int register_xenbus_watch(struct xenbus_watch *watch)
{
	/* Pointer in ascii is the token. */
	char token[sizeof(watch) * 2 + 1];
	int err;

	sprintf(token, "%lX", (long)watch);
	BUG_ON(find_watch(token));

	err = xs_watch(watch->node, token);
	if (!err)
		list_add(&watch->list, &watches);
	return err;
}
EXPORT_SYMBOL(register_xenbus_watch);

void unregister_xenbus_watch(struct xenbus_watch *watch)
{
	char token[sizeof(watch) * 2 + 1];
	int err;

	sprintf(token, "%lX", (long)watch);
	BUG_ON(!find_watch(token));

	err = xs_unwatch(watch->node, token);
	list_del(&watch->list);

	if (err)
		printk(KERN_WARNING
		       "XENBUS Failed to release watch %s: %i\n",
		       watch->node, err);
}
EXPORT_SYMBOL(unregister_xenbus_watch);

/* Re-register callbacks to all watches. */
void reregister_xenbus_watches(void)
{
	struct xenbus_watch *watch;
	char token[sizeof(watch) * 2 + 1];

	list_for_each_entry(watch, &watches, list) {
		sprintf(token, "%lX", (long)watch);
		xs_watch(watch->node, token);
	}
}

static int watch_thread(void *unused)
{
	for (;;) {
		char *token;
		char *node = NULL;

		wait_event(xb_waitq, xs_input_avail());

		/* If this is a spurious wakeup caused by someone
		 * doing an op, they'll hold the lock and the buffer
		 * will be empty by the time we get there.		 
		 */
		down(&xenbus_lock);
		if (xs_input_avail())
			node = xs_read_watch(&token);

		if (node && !IS_ERR(node)) {
			struct xenbus_watch *w;
			int err;

			err = xs_acknowledge_watch(token);
			if (err)
				printk(KERN_WARNING "XENBUS ack %s fail %i\n",
				       node, err);
			w = find_watch(token);
			BUG_ON(!w);
			w->callback(w, node);
			kfree(node);
		} else if (node)
			printk(KERN_WARNING "XENBUS xs_read_watch: %li\n",
			       PTR_ERR(node));
		up(&xenbus_lock);
	}
}

int xs_init(void)
{
	int err;
	struct task_struct *watcher;

	err = xb_init_comms();
	if (err)
		return err;
	
	watcher = kthread_run(watch_thread, NULL, "kxbwatch");
	if (IS_ERR(watcher))
		return PTR_ERR(watcher);
	return 0;
}
