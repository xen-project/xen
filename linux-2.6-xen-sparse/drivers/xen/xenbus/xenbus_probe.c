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

#define DEBUG

#ifdef DEBUG
#define dprintf(_fmt, _args...) \
printk(KERN_INFO __stringify(KBUILD_MODNAME) " [DBG] %s"    _fmt, __FUNCTION__, ##_args)
#else
#define dprintf(_fmt, _args...) do { } while(0)
#endif

static int xs_init_done = 0;

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
		if (sscanf(p, fmt, result) == 0)
			ret = -EINVAL;
		kfree(p);
	}
	va_end(ap);
	return ret;
}

/* Return the path to dir with /name appended.
 * If name is null or empty returns a copy of dir.
 */ 
char *xenbus_path(const char *dir, const char *name)
{
	char *ret;
	int len;

	len = strlen(dir) + 1;
	if (name)
		len += strlen(name) + 1;
	ret = kmalloc(len, GFP_KERNEL);
	if (ret == NULL)
	    return NULL;
	strcpy(ret, dir);
	if (name) {
		strcat(ret, "/");
		strcat(ret, name);
	}
	return ret;
}

#define streq(a, b) (strcmp((a), (b)) == 0)

char *xenbus_read(const char *dir, const char *name, unsigned int *data_n)
{
	int err = 0;
	char *data = NULL;
	char *path = xenbus_path(dir, name);
	int n = 0;

	if (!path) {
		err = -ENOMEM;
		goto out;
	}
	data = xs_read(path, &n);
	if (IS_ERR(data)) {
		err = PTR_ERR(data);
		if (err == -EISDIR)
			err = -ENOENT;
	} else if (n == 0) {
		err = -ENOENT;
		kfree(data);
	}
	kfree(path);
  out:
	if (data_n)
		*data_n = n;
	return (err ? ERR_PTR(err) : data);
}

int xenbus_write(const char *dir, const char *name, const char *data, int data_n)
{
	int err = 0;
	char *path = xenbus_path(dir, name);

	if (!path)
		return -ENOMEM;
	err = xs_write(path, data, data_n, O_CREAT);
	kfree(path);
	return err;
}

int xenbus_read_string(const char *dir, const char *name, char **val)
{
	int err = 0;

	*val = xenbus_read(dir, name, NULL);
	if (IS_ERR(*val)) {
		err = PTR_ERR(*val);
		*val = NULL;
	}
	return err;
}

int xenbus_write_string(const char *dir, const char *name, const char *val)
{
	return xenbus_write(dir, name, val, strlen(val));
}

int xenbus_read_ulong(const char *dir, const char *name, unsigned long *val)
{
	return xenbus_gather(dir, name, "%lu", val, NULL);
}

int xenbus_write_ulong(const char *dir, const char *name, unsigned long val)
{
	char data[32] = {};

	snprintf(data, sizeof(data), "%lu", val);
	return xenbus_write(dir, name, data, strlen(data));
}

int xenbus_read_long(const char *dir, const char *name, long *val)
{
	return xenbus_gather(dir, name, "%li", val, NULL);
}

int xenbus_write_long(const char *dir, const char *name, long val)
{
	char data[32] = {};

	snprintf(data, sizeof(data), "%li", val);
	return xenbus_write(dir, name, data, strlen(data));
}

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


/* Bus type for backend drivers. */
static struct bus_type xenback_type = {
	.name  = "xenback",
	.match = xenbus_match,
};

struct xenbus_for_dev {
	int (*fn)(struct xenbus_device *, void *);
	void *data;
};

static int for_dev(struct device *_dev, void *_data)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_for_dev *data = _data;
	dev = to_xenbus_device(_dev);
	return data->fn(dev, data->data);
}

int xenbus_for_each_dev(struct xenbus_device * start, void * data,
			int (*fn)(struct xenbus_device *, void *))
{
	struct xenbus_for_dev for_data = {
		.fn = fn,
		.data = data,
	};
	if (!fn)
		return -EINVAL;
	printk("%s> data=%p fn=%p for_data=%p\n", __FUNCTION__,
	       data, fn, &for_data);
	return bus_for_each_dev(&xenbus_type, 
				(start ? &start->dev : NULL),
				&for_data, for_dev);
}

struct xenbus_for_drv {
	int (*fn)(struct xenbus_driver *, void *);
	void *data;
};

static int for_drv(struct device_driver *_drv, void *_data)
{
	struct xenbus_driver *drv = to_xenbus_driver(_drv);
	struct xenbus_for_drv *data = _data;
	return data->fn(drv, data->data);
}

int xenbus_for_each_drv(struct xenbus_driver * start, void * data,
			int (*fn)(struct xenbus_driver *, void *))
{
	struct xenbus_for_drv for_data = {
		.fn = fn,
		.data = data,
	};
	if (!fn)
		return -EINVAL;
	return bus_for_each_drv(&xenbus_type,
				(start ? &start->driver: NULL),
				&for_data, for_drv);
}

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
	int err = 0;

	printk("%s> frontend driver %p %s\n", __FUNCTION__,
	       drv, drv->name);
	drv->driver.name = drv->name;
	drv->driver.bus = &xenbus_type;
	drv->driver.owner = drv->owner;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;

	err = driver_register(&drv->driver);
	if (err == 0 && xs_init_done && drv->connect) {
		printk("%s> connecting driver %p %s\n", __FUNCTION__,
		       drv, drv->name);
		drv->connect(drv);
	}
	return err;
}

void xenbus_unregister_driver(struct xenbus_driver *drv)
{
	driver_unregister(&drv->driver);
}

static int xenbus_probe_device(const char *dir, const char *name, const char *devicetype)
{
	int err;
	struct xenbus_device *xendev;
	unsigned int xendev_n;
	char *nodename;

	dprintf("> dir=%s name=%s\n", dir, name);
	nodename = xenbus_path(dir, name);
	if (!nodename)
		return -ENOMEM;

	/* FIXME: This could be a rescan. Don't re-register existing devices. */

	/* Add space for the strings. */
	xendev_n = sizeof(*xendev) + strlen(nodename) + strlen(devicetype) + 2;
	xendev = kmalloc(xendev_n, GFP_KERNEL);
	if (!xendev) {
		err = -ENOMEM;
		goto free_nodename;
	}
	memset(xendev, 0, xendev_n);

	snprintf(xendev->dev.bus_id, BUS_ID_SIZE, "%s-%s", devicetype, name);
	xendev->dev.bus = &xenbus_type;

	xendev->id = simple_strtol(name, NULL, 0);

	/* Copy the strings into the extra space. */
	xendev->nodename = (char *)(xendev + 1);
	strcpy(xendev->nodename, nodename);
	xendev->devicetype = xendev->nodename + strlen(xendev->nodename) + 1;
	strcpy(xendev->devicetype, devicetype);

	/* Register with generic device framework. */
	printk("XENBUS: Registering device %s\n", xendev->dev.bus_id);
	err = device_register(&xendev->dev);
	if (err) {
		printk("XENBUS: Registering device %s: error %i\n",
		       xendev->dev.bus_id, err);
		kfree(xendev);
	}

free_nodename:
	kfree(nodename);
	dprintf("< err=%i\n", err);
	return err;
}

static int xenbus_probe_device_type(const char *dirpath, const char *typename)
{
	int err = 0;
	char **dir;
	char *path;
	unsigned int dir_n = 0;
	int i;

	dprintf("> dirpath=%s typename=%s\n", dirpath, typename);
	path = xenbus_path(dirpath, typename);
	if (!path)
		return -ENOMEM;

	dir = xs_directory(path, &dir_n);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto out;
	}

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device(path, dir[i], typename);
		if (err)
			break;
	}
	kfree(dir);
out:
	kfree(path);
	dprintf("< err=%i\n", err);
	return err;
}

static int xenbus_probe_devices(const char *path)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	dprintf("> path=%s\n", path);
	down(&xs_lock);
	dir = xs_directory(path, &dir_n);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto unlock;
	}
	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(path, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
unlock:
	up(&xs_lock);
	dprintf("< err=%i\n", err);
	return err;
}


static int xenbus_probe_backend(const char *dir, const char *name)
{
	int err = 0;
	struct xenbus_device *xendev = NULL;
	unsigned int xendev_n = 0;
	char *nodename = NULL, *devicetype = NULL;
	unsigned int devicetype_n = 0;

	dprintf("> dir=%s name=%s\n", dir, name);
	nodename = xenbus_path(dir, name);
	if (!nodename)
		return -ENOMEM;

	devicetype = xenbus_read(nodename, XENBUS_DEVICE_TYPE, &devicetype_n);
	if (IS_ERR(devicetype)) {
		err = PTR_ERR(devicetype);
		goto free_nodename;
	}

	dprintf("> devicetype='%s'\n", devicetype);
	/* FIXME: This could be a rescan. Don't re-register existing devices. */

	/* Add space for the strings. */
	xendev_n = sizeof(*xendev) + strlen(nodename) + strlen(devicetype) + 2;
	xendev = kmalloc(xendev_n, GFP_KERNEL);
	if (!xendev) {
		err = -ENOMEM;
		goto free_devicetype;
	}
	memset(xendev, 0, xendev_n);

	snprintf(xendev->dev.bus_id, BUS_ID_SIZE, "%s", devicetype);
	xendev->dev.bus = &xenback_type;

	/* Copy the strings into the extra space. */
	xendev->nodename = (char *)(xendev + 1);
	strcpy(xendev->nodename, nodename);
	xendev->devicetype = xendev->nodename + strlen(xendev->nodename) + 1;
	strcpy(xendev->devicetype, devicetype);

	/* Register with generic device framework. */
	printk("XENBUS: Registering backend %s\n", xendev->dev.bus_id);
	err = device_register(&xendev->dev);
	if (err) {
		printk("XENBUS: Registering device %s: error %i\n",
		       xendev->dev.bus_id, err);
		kfree(xendev);
	}

free_devicetype:
	kfree(devicetype);
free_nodename:
	kfree(nodename);
	dprintf("< err=%i\n", err);
	return err;
}

static int xenbus_probe_backends(const char *path)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	dprintf("> path=%s\n", path);
	down(&xs_lock);
	dir = xs_directory(path, &dir_n);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto unlock;
	}
	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_backend(path, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
unlock:
	up(&xs_lock);
	dprintf("< err=%i\n", err);
	return err;
}

int xenbus_register_backend(struct xenbus_driver *drv)
{
	int err = 0;

	printk("%s> backend driver %p %s\n", __FUNCTION__,
	       drv, drv->name);
	drv->driver.name = drv->name;
	drv->driver.bus = &xenback_type;
	drv->driver.owner = drv->owner;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;

	err = driver_register(&drv->driver);
	if (err == 0 && xs_init_done && drv->connect) {
		printk("%s> connecting driver %p %s\n", __FUNCTION__,
		       drv, drv->name);
		drv->connect(drv);
	}
	return err;
}

void xenbus_unregister_backend(struct xenbus_driver *drv)
{
	driver_unregister(&drv->driver);
}

int xenbus_for_each_backend(struct xenbus_driver * start, void * data,
			    int (*fn)(struct xenbus_driver *, void *))
{
	struct xenbus_for_drv for_data = {
		.fn = fn,
		.data = data,
	};
	if (!fn)
		return -EINVAL;
	return bus_for_each_drv(&xenback_type,
				(start ? &start->driver: NULL),
				&for_data, for_drv);
}

static int xenbus_driver_connect(struct xenbus_driver *drv, void *data)
{
	printk("%s> driver %p %s\n", __FUNCTION__, drv, drv->name);
	if (drv->connect) {
		printk("%s> connecting driver %p %s\n", __FUNCTION__,
		       drv, drv->name);
		drv->connect(drv);
	}
	printk("%s< driver %p %s\n", __FUNCTION__, drv, drv->name);
	return 0;
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

	/* Notify drivers that xenstore has connected. */
	printk("%s> connect drivers...\n", __FUNCTION__);
	xenbus_for_each_drv(NULL, NULL, xenbus_driver_connect);
	printk("%s> connect backends...\n", __FUNCTION__);
	xenbus_for_each_backend(NULL, NULL, xenbus_driver_connect);
	
	/* Enumerate devices and backends in xenstore. */
	xenbus_probe_devices("device");
	xenbus_probe_backends("backend");

exit:
	printk("%s< err=%d\n", __FUNCTION__, err);
	return err;
}

static int __init xenbus_probe_init(void)
{
	bus_register(&xenbus_type);
	bus_register(&xenback_type);

	if (!xen_start_info.store_evtchn)
		return 0;

	do_xenbus_probe(NULL);
	return 0;
}

postcore_initcall(xenbus_probe_init);
