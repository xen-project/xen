/******************************************************************************
 * xenbus.h
 *
 * Talks to Xen Store to figure out what devices we have.
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

#ifndef _ASM_XEN_XENBUS_H
#define _ASM_XEN_XENBUS_H


/* Caller must hold this lock to call these functions: it's also held
 * across watch callbacks. */
// TODO
//extern struct semaphore xenbus_lock;

char **xenbus_directory(const char *dir, const char *node, unsigned int *num);
void *xenbus_read(const char *dir, const char *node, unsigned int *len);
int xenbus_write(const char *dir, const char *node,
		 const char *string, int createflags);
int xenbus_mkdir(const char *dir, const char *node);
int xenbus_exists(const char *dir, const char *node);
int xenbus_rm(const char *dir, const char *node);
int xenbus_transaction_start(const char *subtree);
int xenbus_transaction_end(int abort);

/* Single read and scanf: returns -errno or num scanned if > 0. */
int xenbus_scanf(const char *dir, const char *node, const char *fmt, ...)
	__attribute__((format(scanf, 3, 4)));

/* Single printf and write: returns -errno or 0. */
int xenbus_printf(const char *dir, const char *node, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* Generic read function: NULL-terminated triples of name,
 * sprintf-style type string, and pointer. Returns 0 or errno.*/
int xenbus_gather(const char *dir, ...);

/* Register callback to watch this node. */
struct xenbus_watch
{
	struct list_head list;
	char *node;
	void (*callback)(struct xenbus_watch *, const char *node);
};

int register_xenbus_watch(struct xenbus_watch *watch);
void unregister_xenbus_watch(struct xenbus_watch *watch);
void reregister_xenbus_watches(void);

/* Called from xen core code. */
void xenbus_suspend(void);
void xenbus_resume(void);

#define XENBUS_IS_ERR_READ(str) ({			\
	if (!IS_ERR(str) && strlen(str) == 0) {		\
		kfree(str);				\
		str = ERR_PTR(-ERANGE);			\
	}						\
	IS_ERR(str);					\
})

#define XENBUS_EXIST_ERR(err) ((err) == -ENOENT || (err) == -ERANGE)

int xs_init(void);

#endif /* _ASM_XEN_XENBUS_H */
