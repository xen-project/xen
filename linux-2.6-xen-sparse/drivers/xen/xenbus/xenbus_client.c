/******************************************************************************
 * Client-facing interface for the Xenbus driver.  In other words, the
 * interface between the Xenbus and the device-specific code, be it the
 * frontend or the backend of that driver.
 *
 * Copyright (C) 2005 XenSource Ltd
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

#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include <xen/driver_util.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#define DPRINTK(fmt, args...) \
    pr_debug("xenbus_client (%s:%d) " fmt ".\n", __FUNCTION__, __LINE__, ##args)

const char *xenbus_strstate(enum xenbus_state state)
{
	static const char *const name[] = {
		[ XenbusStateUnknown      ] = "Unknown",
		[ XenbusStateInitialising ] = "Initialising",
		[ XenbusStateInitWait     ] = "InitWait",
		[ XenbusStateInitialised  ] = "Initialised",
		[ XenbusStateConnected    ] = "Connected",
		[ XenbusStateClosing      ] = "Closing",
		[ XenbusStateClosed	  ] = "Closed",
	};
	return (state < ARRAY_SIZE(name)) ? name[state] : "INVALID";
}
EXPORT_SYMBOL_GPL(xenbus_strstate);

int xenbus_watch_path(struct xenbus_device *dev, const char *path,
		      struct xenbus_watch *watch,
		      void (*callback)(struct xenbus_watch *,
				       const char **, unsigned int))
{
	int err;

	watch->node = path;
	watch->callback = callback;

	err = register_xenbus_watch(watch);

	if (err) {
		watch->node = NULL;
		watch->callback = NULL;
		xenbus_dev_fatal(dev, err, "adding watch on %s", path);
	}

	return err;
}
EXPORT_SYMBOL_GPL(xenbus_watch_path);


int xenbus_watch_path2(struct xenbus_device *dev, const char *path,
		       const char *path2, struct xenbus_watch *watch,
		       void (*callback)(struct xenbus_watch *,
					const char **, unsigned int))
{
	int err;
	char *state = kasprintf(GFP_KERNEL, "%s/%s", path, path2);
	if (!state) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating path for watch");
		return -ENOMEM;
	}
	err = xenbus_watch_path(dev, state, watch, callback);

	if (err)
		kfree(state);
	return err;
}
EXPORT_SYMBOL_GPL(xenbus_watch_path2);


int xenbus_switch_state(struct xenbus_device *dev, enum xenbus_state state)
{
	/* We check whether the state is currently set to the given value, and
	   if not, then the state is set.  We don't want to unconditionally
	   write the given state, because we don't want to fire watches
	   unnecessarily.  Furthermore, if the node has gone, we don't write
	   to it, as the device will be tearing down, and we don't want to
	   resurrect that directory.

	   Note that, because of this cached value of our state, this function
	   will not work inside a Xenstore transaction (something it was
	   trying to in the past) because dev->state would not get reset if
	   the transaction was aborted.

	 */

	int current_state;
	int err;

	if (state == dev->state)
		return 0;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "state", "%d",
			   &current_state);
	if (err != 1)
		return 0;

	err = xenbus_printf(XBT_NIL, dev->nodename, "state", "%d", state);
	if (err) {
		if (state != XenbusStateClosing) /* Avoid looping */
			xenbus_dev_fatal(dev, err, "writing new state");
		return err;
	}

	dev->state = state;

	return 0;
}
EXPORT_SYMBOL_GPL(xenbus_switch_state);

int xenbus_frontend_closed(struct xenbus_device *dev)
{
	xenbus_switch_state(dev, XenbusStateClosed);
	complete(&dev->down);
	return 0;
}
EXPORT_SYMBOL_GPL(xenbus_frontend_closed);

/**
 * Return the path to the error node for the given device, or NULL on failure.
 * If the value returned is non-NULL, then it is the caller's to kfree.
 */
static char *error_path(struct xenbus_device *dev)
{
	return kasprintf(GFP_KERNEL, "error/%s", dev->nodename);
}


void _dev_error(struct xenbus_device *dev, int err, const char *fmt,
		va_list ap)
{
	int ret;
	unsigned int len;
	char *printf_buffer = NULL, *path_buffer = NULL;

#define PRINTF_BUFFER_SIZE 4096
	printf_buffer = kmalloc(PRINTF_BUFFER_SIZE, GFP_KERNEL);
	if (printf_buffer == NULL)
		goto fail;

	len = sprintf(printf_buffer, "%i ", -err);
	ret = vsnprintf(printf_buffer+len, PRINTF_BUFFER_SIZE-len, fmt, ap);

	BUG_ON(len + ret > PRINTF_BUFFER_SIZE-1);

	dev_err(&dev->dev, "%s\n", printf_buffer);

	path_buffer = error_path(dev);

	if (path_buffer == NULL) {
		printk("xenbus: failed to write error node for %s (%s)\n",
		       dev->nodename, printf_buffer);
		goto fail;
	}

	if (xenbus_write(XBT_NIL, path_buffer, "error", printf_buffer) != 0) {
		printk("xenbus: failed to write error node for %s (%s)\n",
		       dev->nodename, printf_buffer);
		goto fail;
	}

fail:
	if (printf_buffer)
		kfree(printf_buffer);
	if (path_buffer)
		kfree(path_buffer);
}


void xenbus_dev_error(struct xenbus_device *dev, int err, const char *fmt,
		      ...)
{
	va_list ap;

	va_start(ap, fmt);
	_dev_error(dev, err, fmt, ap);
	va_end(ap);
}
EXPORT_SYMBOL_GPL(xenbus_dev_error);


void xenbus_dev_fatal(struct xenbus_device *dev, int err, const char *fmt,
		      ...)
{
	va_list ap;

	va_start(ap, fmt);
	_dev_error(dev, err, fmt, ap);
	va_end(ap);

	xenbus_switch_state(dev, XenbusStateClosing);
}
EXPORT_SYMBOL_GPL(xenbus_dev_fatal);


int xenbus_grant_ring(struct xenbus_device *dev, unsigned long ring_mfn)
{
	int err = gnttab_grant_foreign_access(dev->otherend_id, ring_mfn, 0);
	if (err < 0)
		xenbus_dev_fatal(dev, err, "granting access to ring page");
	return err;
}
EXPORT_SYMBOL_GPL(xenbus_grant_ring);


int xenbus_alloc_evtchn(struct xenbus_device *dev, int *port)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err;

	alloc_unbound.dom        = DOMID_SELF;
	alloc_unbound.remote_dom = dev->otherend_id;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);
	if (err)
		xenbus_dev_fatal(dev, err, "allocating event channel");
	else
		*port = alloc_unbound.port;

	return err;
}
EXPORT_SYMBOL_GPL(xenbus_alloc_evtchn);


int xenbus_free_evtchn(struct xenbus_device *dev, int port)
{
	struct evtchn_close close;
	int err;

	close.port = port;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
	if (err)
		xenbus_dev_error(dev, err, "freeing event channel %d", port);

	return err;
}
EXPORT_SYMBOL_GPL(xenbus_free_evtchn);


enum xenbus_state xenbus_read_driver_state(const char *path)
{
	enum xenbus_state result;
	int err = xenbus_gather(XBT_NIL, path, "state", "%d", &result, NULL);
	if (err)
		result = XenbusStateUnknown;

	return result;
}
EXPORT_SYMBOL_GPL(xenbus_read_driver_state);
