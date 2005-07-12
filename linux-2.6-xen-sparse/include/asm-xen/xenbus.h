#ifndef _ASM_XEN_XENBUS_H
#define _ASM_XEN_XENBUS_H
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
#include <linux/device.h>
#include <asm/semaphore.h>

/* A xenbus device. */
struct xenbus_device {
	char *devicetype;
	char *subtype;
	char *nodename;
	int id;
	struct device dev;
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
	char subtype[32];	/* Contents of "subtype" for this device */
};

/* A xenbus driver. */
struct xenbus_driver {
	char *name;
	struct module *owner;
	const struct xenbus_device_id *ids;
        /* Called when xenstore is connected. */
        int  (*connect) (struct xenbus_driver * drv);

	int  (*probe)    (struct xenbus_device * dev, const struct xenbus_device_id * id);
        int  (*remove)   (struct xenbus_device * dev);
        int  (*configure)(struct xenbus_device * dev);

	struct device_driver driver;
};

struct xenbus_evtchn {
        unsigned long dom1;
        unsigned long port1;
        unsigned long dom2;
        unsigned long port2;
};

static inline struct xenbus_driver *to_xenbus_driver(struct device_driver *drv)
{
	return container_of(drv, struct xenbus_driver, driver);
}

int xenbus_register_driver(struct xenbus_driver *drv);
void xenbus_unregister_driver(struct xenbus_driver *drv);

int xenbus_register_backend(struct xenbus_driver *drv);
void xenbus_unregister_backend(struct xenbus_driver *drv);

/* Iterator over xenbus devices (frontend). */
int xenbus_for_each_dev(struct xenbus_device * start, void * data,
                        int (*fn)(struct xenbus_device *, void *));

/* Iterator over xenbus drivers (frontend). */
int xenbus_for_each_drv(struct xenbus_driver * start, void * data,
                        int (*fn)(struct xenbus_driver *, void *));

/* Iterator over xenbus drivers (backend). */
int xenbus_for_each_backend(struct xenbus_driver * start, void * data,
                            int (*fn)(struct xenbus_driver *, void *));

/* Caller must hold this lock to call these functions: it's also held
 * across watch callbacks. */
extern struct semaphore xs_lock;

char **xs_directory(const char *path, unsigned int *num);
void *xs_read(const char *path, unsigned int *len);
int xs_write(const char *path,
	     const void *data, unsigned int len, int createflags);
int xs_mkdir(const char *path);
int xs_exists(const char *path);
int xs_mkdirs(const char *path);
int xs_rm(const char *path);
int xs_transaction_start(const char *subtree);
int xs_transaction_end(int abort);
char *xs_get_domain_path(domid_t domid);

/* Register callback to watch this node. */
struct xenbus_watch
{
	struct list_head list;
	char *node;
	unsigned int priority;
	void (*callback)(struct xenbus_watch *, const char *node);
};

int register_xenbus_watch(struct xenbus_watch *watch);
void unregister_xenbus_watch(struct xenbus_watch *watch);

/* Generic read function: NULL-terminated triples of name,
 * sprintf-style type string, and pointer. */
int xenbus_gather(const char *dir, ...);

char *xenbus_path(const char *dir, const char *name);
char *xenbus_read(const char *dir, const char *name, unsigned int *data_n);
int xenbus_write(const char *dir, const char *name,
                 const char *data, int data_n);

int xenbus_read_string(const char *dir, const char *name, char **val);
int xenbus_write_string(const char *dir, const char *name, const char *val);
int xenbus_read_ulong(const char *dir, const char *name, unsigned long *val);
int xenbus_write_ulong(const char *dir, const char *name, unsigned long val);
int xenbus_read_long(const char *dir, const char *name, long *val);
int xenbus_write_long(const char *dir, const char *name, long val);

#endif /* _ASM_XEN_XENBUS_H */
