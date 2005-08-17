/******************************************************************************
 * Talks to Xen Store to figure out what devices we have.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 * Copyright (C) 2005 Mike Wray, Hewlett-Packard
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
#define DEBUG

#include <asm-xen/hypervisor.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/balloon.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <stdarg.h>
#include <linux/notifier.h>
#include "xenbus_comms.h"

#define streq(a, b) (strcmp((a), (b)) == 0)

static struct notifier_block *xenstore_chain;

/* If something in array of ids matches this device, return it. */
static const struct xenbus_device_id *
match_device(const struct xenbus_device_id *arr, struct xenbus_device *dev)
{
	for (; !streq(arr->devicetype, ""); arr++) {
		if (!streq(arr->devicetype, dev->devicetype))
			continue;

		/* If they don't care what subtype, it's a match. */
		if (streq(arr->subtype, ""))
			return arr;

		/* If they care, device must have (same) subtype. */
		if (dev->subtype && streq(arr->subtype, dev->subtype))
			return arr;
	}
	return NULL;
}

static int xenbus_match(struct device *_dev, struct device_driver *_drv)
{
	struct xenbus_driver *drv = to_xenbus_driver(_drv);

	if (!drv->ids)
		return 0;

	return match_device(drv->ids, to_xenbus_device(_dev)) != NULL;
}

/* Bus type for frontend drivers. */
static struct bus_type xenbus_type = {
	.name  = "xenbus",
	.match = xenbus_match,
};

static int xenbus_dev_probe(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);
	const struct xenbus_device_id *id;

	if (!drv->probe)
		return -ENODEV;

	id = match_device(drv->ids, dev);
	if (!id)
		return -ENODEV;

	return drv->probe(dev, id);
}

static int xenbus_dev_remove(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);

	if (!drv->remove)
		return 0;
	return drv->remove(dev);
}

int xenbus_register_driver(struct xenbus_driver *drv)
{
	int err;

	drv->driver.name = drv->name;
	drv->driver.bus = &xenbus_type;
	drv->driver.owner = drv->owner;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;

	down(&xenbus_lock);
	err = driver_register(&drv->driver);
	up(&xenbus_lock);
	return err;
}

void xenbus_unregister_driver(struct xenbus_driver *drv)
{
	down(&xenbus_lock);
	driver_unregister(&drv->driver);
	up(&xenbus_lock);
}

struct xb_find_info
{
	struct xenbus_device *dev;
	const char *busid;
};

static int cmp_dev(struct device *dev, void *data)
{
	struct xb_find_info *info = data;

	if (streq(dev->bus_id, info->busid)) {
		info->dev = container_of(get_device(dev),
					 struct xenbus_device, dev);
		return 1;
	}
	return 0;
}

/* FIXME: device_find is fixed in 2.6.13-rc2 according to Greg KH --RR */
struct xenbus_device *xenbus_device_find(const char *busid)
{
	struct xb_find_info info = { .dev = NULL, .busid = busid };

	bus_for_each_dev(&xenbus_type, NULL, &info, cmp_dev);
	return info.dev;
}


static void xenbus_release_device(struct device *dev)
{
	if (dev) {
		struct xenbus_device *xendev = to_xenbus_device(dev);

		kfree(xendev->subtype);
		kfree(xendev);
	}
}
/* devices/<typename>/<name> */
static int xenbus_probe_device(const char *dirpath, const char *devicetype,
			       const char *name)
{
	int err;
	struct xenbus_device *xendev;
	unsigned int stringlen;

	/* Nodename: /device/<typename>/<name>/ */
	stringlen = strlen(dirpath) + strlen(devicetype) + strlen(name) + 3;
	/* Typename */
	stringlen += strlen(devicetype) + 1;
	xendev = kmalloc(sizeof(*xendev) + stringlen, GFP_KERNEL);
	if (!xendev)
		return -ENOMEM;
	memset(xendev, 0, sizeof(*xendev));

	/* Copy the strings into the extra space. */
	xendev->nodename = (char *)(xendev + 1);
	sprintf(xendev->nodename, "%s/%s/%s", dirpath, devicetype, name);
	xendev->devicetype = xendev->nodename + strlen(xendev->nodename) + 1;
	strcpy(xendev->devicetype, devicetype);

	/* FIXME: look for "subtype" field. */
	snprintf(xendev->dev.bus_id, BUS_ID_SIZE, "%s-%s", devicetype, name);
	xendev->dev.bus = &xenbus_type;
	xendev->dev.release = xenbus_release_device;

	/* Register with generic device framework. */
	err = device_register(&xendev->dev);
	if (err) {
		printk("XENBUS: Registering device %s: error %i\n",
		       xendev->dev.bus_id, err);
		kfree(xendev);
	}
	return err;
}

static int xenbus_probe_device_type(const char *dirpath, const char *typename)
{
	int err = 0;
	char **dir;
	unsigned int dir_n = 0;
	int i;

	dir = xenbus_directory(dirpath, typename, &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device(dirpath, typename, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static int xenbus_probe_devices(const char *path)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	dir = xenbus_directory(path, "", &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(path, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static unsigned int char_count(const char *str, char c)
{
	unsigned int i, ret = 0;

	for (i = 0; str[i]; i++)
		if (str[i] == c)
			ret++;
	return ret;
}

static void dev_changed(struct xenbus_watch *watch, const char *node)
{
	char busid[BUS_ID_SIZE];
	int exists;
	struct xenbus_device *dev;
	char *p;

	/* Node is of form device/<type>/<identifier>[/...] */
	if (char_count(node, '/') != 2)
		return;

	/* Created or deleted? */
	exists = xenbus_exists(node, "");

	p = strchr(node, '/') + 1;
	if (strlen(p) + 1 > BUS_ID_SIZE) {
		printk("Device for node %s is too big!\n", node);
		return;
	}
	/* Bus ID is name with / changed to - */
	strcpy(busid, p);
	*strchr(busid, '/') = '-';

	dev = xenbus_device_find(busid);
	printk("xenbus: device %s %s\n", busid, dev ? "exists" : "new");
	if (dev && !exists) {
		printk("xenbus: Unregistering device %s\n", busid);
		/* FIXME: free? */
		device_unregister(&dev->dev);
	} else if (!dev && exists) {
		printk("xenbus: Adding device %s\n", busid);
		/* Hack bus id back into two strings. */
		*strrchr(busid, '-') = '\0';
		xenbus_probe_device("device", busid, busid+strlen(busid)+1);
	} else
		printk("xenbus: strange, %s already %s\n", busid,
		       exists ? "exists" : "gone");
	if (dev)
		put_device(&dev->dev);
}

/* We watch for devices appearing and vanishing. */
static struct xenbus_watch dev_watch = {
	/* FIXME: Ideally we'd only watch for changes 2 levels deep... */
	.node = "device",
	.callback = dev_changed,
};

void xenbus_suspend(void)
{
	/* We keep lock, so no comms can happen as page moves. */
	down(&xenbus_lock);
	xb_suspend_comms();
}

void xenbus_resume(void)
{
	xb_init_comms();
	reregister_xenbus_watches();
	up(&xenbus_lock);
}

int register_xenstore_notifier(struct notifier_block *nb)
{
	int ret = 0;

	down(&xenbus_lock);

	if (xen_start_info.store_evtchn) {
		ret = nb->notifier_call(nb, 0, NULL);
	} else {
		notifier_chain_register(&xenstore_chain, nb);
	}

	up(&xenbus_lock);

	return ret;
}
EXPORT_SYMBOL(register_xenstore_notifier);

void unregister_xenstore_notifier(struct notifier_block *nb)
{
	down(&xenbus_lock);
	notifier_chain_unregister(&xenstore_chain, nb);
	up(&xenbus_lock);
}
EXPORT_SYMBOL(unregister_xenstore_notifier);

/* called from a thread in privcmd/privcmd.c */
int do_xenbus_probe(void *unused)
{
	int err = 0;

	/* Initialize xenstore comms unless already done. */
	printk("store_evtchn = %i\n", xen_start_info.store_evtchn);
	err = xs_init();
	if (err) {
		printk("XENBUS: Error initializing xenstore comms:"
		       " %i\n", err);
		return err;
	}

	down(&xenbus_lock);
	err = notifier_call_chain(&xenstore_chain, 0, 0);
	up(&xenbus_lock);

	if (err == NOTIFY_BAD) {
		printk("%s: calling xenstore notify chain failed\n",
		       __FUNCTION__);
		return -EINVAL;
	}

	err = 0;

	down(&xenbus_lock);
	/* Enumerate devices in xenstore. */
	xenbus_probe_devices("device");
	/* Watch for changes. */
	register_xenbus_watch(&dev_watch);
	up(&xenbus_lock);
	return 0;
}

static int __init xenbus_probe_init(void)
{
	bus_register(&xenbus_type);

	if (!xen_start_info.store_evtchn)
		return 0;

	do_xenbus_probe(NULL);
	return 0;
}

postcore_initcall(xenbus_probe_init);
