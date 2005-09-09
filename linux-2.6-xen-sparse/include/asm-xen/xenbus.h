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

#include <linux/device.h>
#include <linux/notifier.h>
#include <asm/semaphore.h>

/* A xenbus device. */
struct xenbus_device {
	char *devicetype;
	char *nodename;
	struct device dev;
	int has_error;
	void *data;
};

static inline struct xenbus_device *to_xenbus_device(struct device *dev)
{
	return container_of(dev, struct xenbus_device, dev);
}

struct xenbus_device_id
{
	/* .../device/<device_type>/<identifier> */
	char devicetype[32]; 	/* General class of device. */
};

/* A xenbus driver. */
struct xenbus_driver {
	char *name;
	struct module *owner;
	const struct xenbus_device_id *ids;
	int (*probe)(struct xenbus_device *dev,
		     const struct xenbus_device_id *id);
	int (*remove)(struct xenbus_device *dev);
	int (*suspend)(struct xenbus_device *dev);
	int (*resume)(struct xenbus_device *dev);
	int (*hotplug)(struct xenbus_device *, char **, int, char *, int);
	struct device_driver driver;
};

static inline struct xenbus_driver *to_xenbus_driver(struct device_driver *drv)
{
	return container_of(drv, struct xenbus_driver, driver);
}

int xenbus_register_device(struct xenbus_driver *drv);
int xenbus_register_backend(struct xenbus_driver *drv);
void xenbus_unregister_driver(struct xenbus_driver *drv);

/* Caller must hold this lock to call these functions: it's also held
 * across watch callbacks. */
extern struct semaphore xenbus_lock;

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

/* Report a (negative) errno into the store, with explanation. */
void xenbus_dev_error(struct xenbus_device *dev, int err, const char *fmt,...);

/* Clear any error. */
void xenbus_dev_ok(struct xenbus_device *dev);

/* Register callback to watch this node. */
struct xenbus_watch
{
	struct list_head list;
	char *node;
	void (*callback)(struct xenbus_watch *, const char *node);
};

/* notifer routines for when the xenstore comes up */
int register_xenstore_notifier(struct notifier_block *nb);
void unregister_xenstore_notifier(struct notifier_block *nb);

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

#endif /* _ASM_XEN_XENBUS_H */
