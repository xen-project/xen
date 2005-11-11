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
#include <asm-xen/xen-public/io/xs_wire.h>

/* Register callback to watch this node. */
struct xenbus_watch
{
	struct list_head list;

	/* Path being watched. */
	const char *node;

	/* Callback (executed in a process context with no locks held). */
	void (*callback)(struct xenbus_watch *,
			 const char **vec, unsigned int len);
};


/* The state of either end of the Xenbus, i.e. the current communication
   status of initialisation across the bus.  States here imply nothing about
   the state of the connection between the driver and the kernel's device
   layers.  */
typedef enum
{
  XenbusStateUnknown      = 0,
  XenbusStateInitialising = 1,
  XenbusStateInitWait     = 2,  /* Finished early initialisation, but waiting
                                   for information from the peer or hotplug
				   scripts. */
  XenbusStateInitialised  = 3,  /* Initialised and waiting for a connection
				   from the peer. */
  XenbusStateConnected    = 4,
  XenbusStateClosing      = 5,  /* The device is being closed due to an error
				   or an unplug event. */
  XenbusStateClosed       = 6

} XenbusState;


/* A xenbus device. */
struct xenbus_device {
	const char *devicetype;
	const char *nodename;
	const char *otherend;
	int otherend_id;
	struct xenbus_watch otherend_watch;
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
	void (*otherend_changed)(struct xenbus_device *dev,
				 XenbusState backend_state);
	int (*remove)(struct xenbus_device *dev);
	int (*suspend)(struct xenbus_device *dev);
	int (*resume)(struct xenbus_device *dev);
	int (*hotplug)(struct xenbus_device *, char **, int, char *, int);
	struct device_driver driver;
	int (*read_otherend_details)(struct xenbus_device *dev);
};

static inline struct xenbus_driver *to_xenbus_driver(struct device_driver *drv)
{
	return container_of(drv, struct xenbus_driver, driver);
}

int xenbus_register_frontend(struct xenbus_driver *drv);
int xenbus_register_backend(struct xenbus_driver *drv);
void xenbus_unregister_driver(struct xenbus_driver *drv);

struct xenbus_transaction;

char **xenbus_directory(struct xenbus_transaction *t,
			const char *dir, const char *node, unsigned int *num);
void *xenbus_read(struct xenbus_transaction *t,
		  const char *dir, const char *node, unsigned int *len);
int xenbus_write(struct xenbus_transaction *t,
		 const char *dir, const char *node, const char *string);
int xenbus_mkdir(struct xenbus_transaction *t,
		 const char *dir, const char *node);
int xenbus_exists(struct xenbus_transaction *t,
		  const char *dir, const char *node);
int xenbus_rm(struct xenbus_transaction *t, const char *dir, const char *node);
struct xenbus_transaction *xenbus_transaction_start(void);
int xenbus_transaction_end(struct xenbus_transaction *t, int abort);

/* Single read and scanf: returns -errno or num scanned if > 0. */
int xenbus_scanf(struct xenbus_transaction *t,
		 const char *dir, const char *node, const char *fmt, ...)
	__attribute__((format(scanf, 4, 5)));

/* Single printf and write: returns -errno or 0. */
int xenbus_printf(struct xenbus_transaction *t,
		  const char *dir, const char *node, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

/* Generic read function: NULL-terminated triples of name,
 * sprintf-style type string, and pointer. Returns 0 or errno.*/
int xenbus_gather(struct xenbus_transaction *t, const char *dir, ...);

/* notifer routines for when the xenstore comes up */
int register_xenstore_notifier(struct notifier_block *nb);
void unregister_xenstore_notifier(struct notifier_block *nb);

int register_xenbus_watch(struct xenbus_watch *watch);
void unregister_xenbus_watch(struct xenbus_watch *watch);
void xs_suspend(void);
void xs_resume(void);

/* Used by xenbus_dev to borrow kernel's store connection. */
void *xenbus_dev_request_and_reply(struct xsd_sockmsg *msg);

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


/**
 * Register a watch on the given path, using the given xenbus_watch structure
 * for storage, and the given callback function as the callback.  Return 0 on
 * success, or -errno on error.  On success, the given path will be saved as
 * watch->node, and remains the caller's to free.  On error, watch->node will
 * be NULL, the device will switch to XenbusStateClosing, and the error will
 * be saved in the store.
 */
int xenbus_watch_path(struct xenbus_device *dev, const char *path,
		      struct xenbus_watch *watch, 
		      void (*callback)(struct xenbus_watch *,
				       const char **, unsigned int));


/**
 * Register a watch on the given path/path2, using the given xenbus_watch
 * structure for storage, and the given callback function as the callback.
 * Return 0 on success, or -errno on error.  On success, the watched path
 * (path/path2) will be saved as watch->node, and becomes the caller's to
 * kfree().  On error, watch->node will be NULL, so the caller has nothing to
 * free, the device will switch to XenbusStateClosing, and the error will be
 * saved in the store.
 */
int xenbus_watch_path2(struct xenbus_device *dev, const char *path,
		       const char *path2, struct xenbus_watch *watch, 
		       void (*callback)(struct xenbus_watch *,
					const char **, unsigned int));


/**
 * Advertise in the store a change of the given driver to the given new_state.
 * Perform the change inside the given transaction xbt.  xbt may be NULL, in
 * which case this is performed inside its own transaction.  Return 0 on
 * success, or -errno on error.  On error, the device will switch to
 * XenbusStateClosing, and the error will be saved in the store.
 */
int xenbus_switch_state(struct xenbus_device *dev,
			struct xenbus_transaction *xbt,
			XenbusState new_state);


/**
 * Grant access to the given ring_mfn to the peer of the given device.  Return
 * 0 on success, or -errno on error.  On error, the device will switch to
 * XenbusStateClosing, and the error will be saved in the store.
 */
int xenbus_grant_ring(struct xenbus_device *dev, unsigned long ring_mfn);


/**
 * Allocate an event channel for the given xenbus_device, assigning the newly
 * created local port to *port.  Return 0 on success, or -errno on error.  On
 * error, the device will switch to XenbusStateClosing, and the error will be
 * saved in the store.
 */
int xenbus_alloc_evtchn(struct xenbus_device *dev, int *port);


/**
 * Return the state of the driver rooted at the given store path, or
 * XenbusStateClosed if no state can be read.
 */
XenbusState xenbus_read_driver_state(const char *path);


/***
 * Report the given negative errno into the store, along with the given
 * formatted message.
 */
void xenbus_dev_error(struct xenbus_device *dev, int err, const char *fmt,
		      ...);


/***
 * Equivalent to xenbus_dev_error(dev, err, fmt, args), followed by
 * xenbus_switch_state(dev, NULL, XenbusStateClosing) to schedule an orderly
 * closedown of this driver and its peer.
 */
void xenbus_dev_fatal(struct xenbus_device *dev, int err, const char *fmt,
		      ...);


#endif /* _ASM_XEN_XENBUS_H */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
