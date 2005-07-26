/******************************************************************************
 * Talks to Xen Store to figure out what devices we have.
 * Currently experiment code, but when I grow up I'll be a bus driver!
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
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <stdarg.h>
#include "xenbus_comms.h"

/* Name of field containing device type. */
#define XENBUS_DEVICE_TYPE "type"

static int xs_init_done = 0;

#define streq(a, b) (strcmp((a), (b)) == 0)

/* If something in array of ids matches this device, return it. */
static const struct xenbus_device_id *
match_device(const struct xenbus_device_id *arr, struct xenbus_device *dev)
{
	for (; !streq(arr->devicetype, ""); arr++) {
		if (!streq(arr->devicetype, dev->devicetype))
			continue;

		if (streq(arr->subtype, "") ||
		    streq(arr->subtype, dev->subtype)) {
			return arr;
		}
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

	printk("Probing device '%s'\n", _dev->bus_id);
	if (!drv->probe) {
		printk("'%s' no probefn\n", _dev->bus_id);
		return -ENODEV;
	}

	id = match_device(drv->ids, dev);
	if (!id) {
		printk("'%s' no id match\n", _dev->bus_id);
		return -ENODEV;
	}
	printk("probing '%s' fn %p\n", _dev->bus_id, drv->probe);
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
	drv->driver.name = drv->name;
	drv->driver.bus = &xenbus_type;
	drv->driver.owner = drv->owner;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;

	return driver_register(&drv->driver);
}

void xenbus_unregister_driver(struct xenbus_driver *drv)
{
	driver_unregister(&drv->driver);
}

/* devices/<typename>/<name> */
static int xenbus_probe_device(const char *typename, const char *name)
{
	int err;
	struct xenbus_device *xendev;
	unsigned int stringlen;

	pr_debug("> dir=%s name=%s\n", typename, name);

	/* FIXME: This could be a rescan. Don't re-register existing devices. */

	/* Nodename: /device/<typename>/<name>/ */
	stringlen = strlen("device") + strlen(typename) + strlen(name) + 3;
	/* Typename */
	stringlen += strlen(typename) + 1;

	xendev = kmalloc(sizeof(*xendev) + stringlen, GFP_KERNEL);
	if (!xendev)
		return -ENOMEM;

	memset(xendev, 0, sizeof(*xendev));
	/* Copy the strings into the extra space. */
	xendev->nodename = (char *)(xendev + 1);
	sprintf(xendev->nodename, "%s/%s/%s", "device", typename, name);
	xendev->devicetype = xendev->nodename + strlen(xendev->nodename) + 1;
	strcpy(xendev->devicetype, typename);

	/* FIXME: look for "subtype" field. */
	snprintf(xendev->dev.bus_id, BUS_ID_SIZE, "%s-%s", typename, name);
	xendev->dev.bus = &xenbus_type;

	/* Register with generic device framework. */
	printk("XENBUS: Registering device %s\n", xendev->dev.bus_id);
	err = device_register(&xendev->dev);
	if (err) {
		printk("XENBUS: Registering device %s: error %i\n",
		       xendev->dev.bus_id, err);
		kfree(xendev);
	}

	pr_debug("< err=%i\n", err);
	return err;
}

/* /device/<typename> */
static int xenbus_probe_device_type(const char *typename)
{
	int err = 0;
	char **dir;
	unsigned int dir_n = 0;
	int i;

	dir = xenbus_directory("device", typename, &dir_n);
	printk("dir %s has %u entries\n", typename, dir_n);
	if (IS_ERR(dir)) {
		printk("dir %s returned %li\n", typename, PTR_ERR(dir));
		return PTR_ERR(dir);
	}

	for (i = 0; i < dir_n; i++) {
		printk("Probing %s/%s\n", dir[i], typename);
		err = xenbus_probe_device(dir[i], typename);
		if (err)
			break;
	}
	kfree(dir);
	pr_debug("< err=%i\n", err);
	return err;
}

static int xenbus_probe_devices(void)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	down(&xenbus_lock);
	dir = xenbus_directory("device", "", &dir_n);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto unlock;
	}
	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(dir[i]);
		if (err) {
			printk("xenbus: error %i probing device %s\n",
			       -err, dir[i]);
			break;
		}
	}
	kfree(dir);
unlock:
	up(&xenbus_lock);
	return err;
}

/* called from a thread in privcmd/privcmd.c */
int do_xenbus_probe(void *unused)
{
	int err = 0;

	printk("%s> xs_init_done=%d\n", __FUNCTION__, xs_init_done);
	if (xs_init_done)
		goto exit;
	/* Initialize xenstore comms unless already done. */
	printk("store_evtchn = %i\n", xen_start_info.store_evtchn);
	err = xs_init();
	if (err) {
		printk("XENBUS: Error initializing xenstore comms:"
		       " %i\n", err);
		goto exit;
	}
	xs_init_done = 1;

	/* Enumerate devices in xenstore. */
	xenbus_probe_devices();

exit:
	printk("%s< err=%d\n", __FUNCTION__, err);
	return err;
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
