/******************************************************************************
 * xenbus_xs.c
 *
 * This is the kernel equivalent of the "xs" library.  We don't need everything
 * and we use xenbus_comms to communication.
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
#include "xenstore/xenstored.h"
#include <linux/uio.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/kthread.h>
#include <asm-xen/xenbus.h>
#include "xenbus_comms.h"

#define streq(a, b) (strcmp((a), (b)) == 0)

static void *xs_in, *xs_out;
static LIST_HEAD(watches);
static DECLARE_MUTEX(watches_lock);
DECLARE_MUTEX(xs_lock);

static int get_error(const char *errorstring)
{
	unsigned int i;

	for (i = 0; !streq(errorstring, xsd_errors[i].errstring); i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			printk(KERN_WARNING "XENBUS xen store gave: unknown error %s",
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

	err = xb_read(xs_in, &msg, sizeof(msg));
	if (err)
		return ERR_PTR(err);

	ret = kmalloc(msg.len + 1, GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	err = xb_read(xs_in, ret, msg.len);
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

/* Send message to xs, get kmalloc'ed reply.  ERR_PTR() on error. */
static void *xs_talkv(enum xsd_sockmsg_type type,
		      const struct kvec *iovec,
		      unsigned int num_vecs,
		      unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret = NULL;
	unsigned int i;
	int err;

	WARN_ON(down_trylock(&xs_lock) == 0);

	msg.type = type;
	msg.len = 0;
	for (i = 0; i < num_vecs; i++)
		msg.len += iovec[i].iov_len;

	err = xb_write(xs_out, &msg, sizeof(msg));
	if (err)
		return ERR_PTR(err);

	for (i = 0; i < num_vecs; i++) {
		err = xb_write(xs_out, iovec[i].iov_base, iovec[i].iov_len);;
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

char **xs_directory(const char *path, unsigned int *num)
{
	char *strings, *p, **ret;
	unsigned int len;

	strings = xs_single(XS_DIRECTORY, path, &len);
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

/* Check if a path exists. Return 1 if it does. */
int xs_exists(const char *path)
{
        char **dir;
        int dir_n;

        dir = xs_directory(path, &dir_n);
        if(IS_ERR(dir))
                return 0;
        kfree(dir);
        return 1;
}

/* Make a directory, creating dirs on the path to it if necessary.
 * Return 0 on success, error code otherwise.
 */
int xs_mkdirs(const char *path)
{
        int err = 0;
        char s[strlen(path) + 1], *p = s;

        if(xs_exists(path))
                goto out;
        strcpy(p, path);
        if(*p == '/')
                p++;
        for( ; ; ){
                p = strchr(p, '/');
                if(p)
                        *p = '\0';
                if(!xs_exists(s)){
                        err = xs_mkdir(s);
                        if(err)
                                goto out;
                        
                }
                if(!p)
                        break;
                *p++ = '/';
       }
  out:
        return err;
}


/* Get the value of a single file.
 * Returns a kmalloced value: call free() on it after use.
 * len indicates length in bytes.
 */
void *xs_read(const char *path, unsigned int *len)
{
	return xs_single(XS_READ, path, len);
}

/* Write the value of a single file.
 * Returns -err on failure.  createflags can be 0, O_CREAT, or O_CREAT|O_EXCL.
 */
int xs_write(const char *path,
	      const void *data, unsigned int len, int createflags)
{
	const char *flags;
	struct kvec iovec[3];

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
	iovec[2].iov_base = (void *)data;
	iovec[2].iov_len = len;

	return xs_error(xs_talkv(XS_WRITE, iovec, ARRAY_SIZE(iovec), NULL));
}

/* Create a new directory. */
int xs_mkdir(const char *path)
{
	return xs_error(xs_single(XS_MKDIR, path, NULL));
}

/* Destroy a file or directory (directories must be empty). */
int xs_rm(const char *path)
{
	return xs_error(xs_single(XS_RM, path, NULL));
}

/* Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 * Transaction only applies to the given subtree.
 * You can only have one transaction at any time.
 */
int xs_transaction_start(const char *subtree)
{
	return xs_error(xs_single(XS_TRANSACTION_START, subtree, NULL));
}

/* End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 */
int xs_transaction_end(int abort)
{
	char abortstr[2];

	if (abort)
		strcpy(abortstr, "F");
	else
		strcpy(abortstr, "T");
	return xs_error(xs_single(XS_TRANSACTION_END, abortstr, NULL));
}

char *xs_get_domain_path(domid_t domid)
{
	char domid_str[32];

	sprintf(domid_str, "%u", domid);
	return xs_single(XS_GETDOMAINPATH, domid_str, NULL);
}

static int xs_watch(const char *path, const char *token, unsigned int priority)
{
	char prio[32];
	struct kvec iov[3];

	sprintf(prio, "%u", priority);
	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (void *)token;
	iov[1].iov_len = strlen(token) + 1;
	iov[2].iov_base = prio;
	iov[2].iov_len = strlen(prio) + 1;

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
	down(&watches_lock);
	BUG_ON(find_watch(token));

	down(&xs_lock);
	err = xs_watch(watch->node, token, watch->priority);
	up(&xs_lock);
	if (!err)
		list_add(&watch->list, &watches);
	up(&watches_lock);
	return err;
}

void unregister_xenbus_watch(struct xenbus_watch *watch)
{
	char token[sizeof(watch) * 2 + 1];
	int err;

	sprintf(token, "%lX", (long)watch);
	down(&watches_lock);
	BUG_ON(!find_watch(token));

	down(&xs_lock);
	err = xs_unwatch(watch->node, token);
	up(&xs_lock);
	list_del(&watch->list);
	up(&watches_lock);

	if (err)
		printk(KERN_WARNING "XENBUS Failed to release watch %s: %i\n",
		       watch->node, err);
}

static int watch_thread(void *unused)
{
	int err;
	unsigned long mtu;

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ*10);
	printk("watch_thread, doing read\n");
	down(&xs_lock);
	err = xenbus_read_long("", "mtu", &mtu);
	up(&xs_lock);
	printk("fake field read: %i (%lu)\n", err, mtu);

	for (;;) {
		char *token;
		char *node = NULL;

		wait_event(xb_waitq, xs_input_avail(xs_in));

		/* If this is a spurious wakeup caused by someone
		 * doing an op, they'll hold the lock and the buffer
		 * will be empty by the time we get there.		 
		 */
		down(&xs_lock);
		if (xs_input_avail(xs_in))
			node = xs_read_watch(&token);
		/* Release lock before calling callback. */
		up(&xs_lock);
		if (node && !IS_ERR(node)) {
			struct xenbus_watch *w;
			int err;

			down(&watches_lock);
			w = find_watch(token);
			BUG_ON(!w);
			w->callback(w, node);
			up(&watches_lock);
			down(&xs_lock);
			err = xs_acknowledge_watch(token);
			if (err)
				printk(KERN_WARNING
				       "XENBUS acknowledge %s failed %i\n",
				       node, err);
			up(&xs_lock);
			kfree(node);
		} else
			printk(KERN_WARNING "XENBUS xs_read_watch: %li\n",
			       PTR_ERR(node));
	}
}

int xs_init(void)
{
	int err;
	struct task_struct *watcher;

	err = xb_init_comms(&xs_in, &xs_out);
	if (err)
		return err;
	
	watcher = kthread_run(watch_thread, NULL, "kxbwatch");
	if (IS_ERR(watcher))
		return PTR_ERR(watcher);
	return 0;
}
