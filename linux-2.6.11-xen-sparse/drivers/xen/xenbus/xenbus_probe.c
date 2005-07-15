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

/* Directory inside a domain containing devices. */
#define XENBUS_DEVICE_DIR  "device"

/* Directory inside a domain containing backends. */
#define XENBUS_BACKEND_DIR  "backend"

/* Name of field containing device id. */
#define XENBUS_DEVICE_ID   "id"

/* Name of field containing device type. */
#define XENBUS_DEVICE_TYPE "type"

//#define DEBUG

#ifdef DEBUG
#define dprintf(_fmt, _args...) \
printk(KERN_INFO __stringify(KBUILD_MODNAME) " [DBG] %s"    _fmt, __FUNCTION__, ##_args)
#else
#define dprintf(_fmt, _args...) do { } while(0)
#endif

static int xs_init_done = 0;

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
	int err = 0;
	char *data = NULL, *end = NULL;
	unsigned int data_n = 0;

	data = xenbus_read(dir, name, &data_n);
	if (IS_ERR(data)) {
		err = PTR_ERR(data);
		goto out;
	}
	if (data_n <= 1) {
		err = -ENOENT;
		goto free_data;
	}
	*val = simple_strtoul(data, &end, 10);
	if (end != data + data_n) {
		printk("XENBUS: Path %s/%s, bad parse of '%s' as ulong\n",
		       dir, name, data);
		err = -EINVAL;
	}
  free_data:
	kfree(data);
  out:
	if (err)
		*val = 0;
	return err;
}

int xenbus_write_ulong(const char *dir, const char *name, unsigned long val)
{
	char data[32] = {};

	snprintf(data, sizeof(data), "%lu", val);
	return xenbus_write(dir, name, data, strlen(data));
}

int xenbus_read_long(const char *dir, const char *name, long *val)
{
	int err = 0;
	char *data = NULL, *end = NULL;
	unsigned int data_n = 0;

	data = xenbus_read(dir, name, &data_n);
	if (IS_ERR(data)) {
		err = PTR_ERR(data);
		goto out;
	}
	if (data_n <= 1) {
		err = -ENOENT;
		goto free_data;
	}
	*val = simple_strtol(data, &end, 10);
	if (end != data + data_n) {
		printk("XENBUS: Path %s/%s, bad parse of '%s' as long\n",
		       dir, name, data);
		err = -EINVAL;
	}
  free_data:
	kfree(data);
  out:
	if (err)
		*val = 0;
	return err;
}

int xenbus_write_long(const char *dir, const char *name, long val)
{
	char data[32] = {};

	snprintf(data, sizeof(data), "%li", val);
	return xenbus_write(dir, name, data, strlen(data));
}

/* Number of characters in string form of a MAC address. */
#define MAC_LENGTH    17

/** Convert a mac address from a string of the form
 * XX:XX:XX:XX:XX:XX to numerical form (an array of 6 unsigned chars).
 * Each X denotes a hex digit: 0..9, a..f, A..F.
 * Also supports using '-' as the separator instead of ':'.
 */
static int mac_aton(const char *macstr, unsigned int n, unsigned char mac[6])
{
	int err = -EINVAL;
	int i, j;
	const char *p;
	char sep = 0;
	
	if (!macstr || n != MAC_LENGTH)
		goto exit;
	for (i = 0, p = macstr; i < 6; i++) {
		unsigned char d = 0;
		if (i) {
			if (!sep && (*p == ':' || *p == '-'))
				sep = *p;
			if (sep && *p == sep)
				p++;
			else
				goto exit;
		}
		for (j = 0; j < 2; j++, p++) {
			if (j)
				d <<= 4;
			if (isdigit(*p))
				d += *p - '0';
			else if (isxdigit(*p))
				d += toupper(*p) - 'A' + 10;
			else
				goto exit;
		}
		mac[i] = d;
	}
	err = 0;
  exit:
	return err;
}

int xenbus_read_mac(const char *dir, const char *name, unsigned char mac[6])
{
	int err = 0;
	char *data = 0;
	unsigned int data_n = 0;

	data = xenbus_read(dir, name, &data_n);
	if (IS_ERR(data)) {
		err = PTR_ERR(data);
		goto out;
	}
	if (data_n <= 1) {
		err = -ENOENT;
		goto free_data;
	}
	err = mac_aton(data, data_n, mac);
	if (err) {
		printk("XENBUS: Path %s/%s, bad parse of '%s' as mac\n",
		       dir, name, data);
		err = -EINVAL;
	}
  free_data:
	kfree(data);
  out:
	if (err)
		memset(mac, 0, sizeof(mac));
	return err;
}

int xenbus_write_mac(const char *dir, const char *name, const unsigned char mac[6])
{
	char buf[MAC_LENGTH] = {};
	int buf_n = sizeof(buf);
	
	snprintf(buf, buf_n, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return xenbus_write(dir, name, buf, buf_n);
}

/* Read event channel information from xenstore.
 *
 * Event channel xenstore fields:
 * dom1		- backend domain id (int)
 * port1	- backend port (int)
 * dom2		- frontend domain id (int)
 * port2	- frontend port (int)
 */
int xenbus_read_evtchn(const char *dir, const char *name, struct xenbus_evtchn *evtchn)
{
	int err = 0;
	char *evtchn_path = xenbus_path(dir, name);

	if (!evtchn_path) {
		err = -ENOMEM;
		goto out;
	}
	err = xenbus_read_ulong(evtchn_path, "dom1",  &evtchn->dom1);
	if (err)
		goto free_evtchn_path;
	err = xenbus_read_ulong(evtchn_path, "port1", &evtchn->port1);
	if (err)
		goto free_evtchn_path;
	err = xenbus_read_ulong(evtchn_path, "dom2",  &evtchn->dom2);
	if (err)
		goto free_evtchn_path;
	err = xenbus_read_ulong(evtchn_path, "port2", &evtchn->port2);

  free_evtchn_path:
	kfree(evtchn_path);
  out:
	if (err)
		*evtchn = (struct xenbus_evtchn){};
	return err;
}

/* Write a message to 'dir'.
 * The data is 'val' followed by parameter names and values,
 * terminated by NULL.
 */
int xenbus_message(const char *dir, const char *val, ...)
{
	static const char *mid_name = "@mid";
	va_list args;
	int err = 0;
	char *mid_path = NULL; 
	char *msg_path = NULL;
	char mid_str[32] = {};
	long mid = 0;
	int i;

	va_start(args, val);
	mid_path = xenbus_path(dir, mid_name);
	if (!mid_path) {
		err = -ENOMEM;
		goto out;
	}
	err = xenbus_read_long(dir, mid_name, &mid);
	if (err != -ENOENT)
		goto out;
	mid++;
	err = xenbus_write_long(dir, mid_name, mid);
	if (err)
		goto out;
	sprintf(mid_str, "%li", mid);
	msg_path = xenbus_path(dir, mid_str);
	if (!mid_path) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < 16; i++) {
		char *k, *v;
		k = va_arg(args, char *);
		if (!k)
			break;
		v = va_arg(args, char *);
		if (!v)
			break;
		err = xenbus_write_string(msg_path, k, v);
		if (err)
			goto out;
	}
	err = xenbus_write_string(msg_path, NULL, val);

  out:
	kfree(msg_path);
	kfree(mid_path);
	va_end(args);
	return err;
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

static int xenbus_probe_device(const char *dir, const char *name)
{
	int err;
	struct xenbus_device *xendev;
	unsigned int xendev_n;
	long id;
	char *nodename, *devicetype;
	unsigned int devicetype_n;

	dprintf("> dir=%s name=%s\n", dir, name);
	nodename = xenbus_path(dir, name);
	if (!nodename)
		return -ENOMEM;

	devicetype = xenbus_read(nodename, XENBUS_DEVICE_TYPE, &devicetype_n);
	if (IS_ERR(devicetype)) {
		err = PTR_ERR(devicetype);
		goto free_nodename;
	}

	err = xenbus_read_long(nodename, XENBUS_DEVICE_ID, &id);
	if (err == -ENOENT)
		id = 0;
	else if (err != 0)
		goto free_devicetype;

	dprintf("> devicetype='%s' name='%s' id=%ld\n", devicetype, name, id);
	/* FIXME: This could be a rescan. Don't re-register existing devices. */

	/* Add space for the strings. */
	xendev_n = sizeof(*xendev) + strlen(nodename) + strlen(devicetype) + 2;
	xendev = kmalloc(xendev_n, GFP_KERNEL);
	if (!xendev) {
		err = -ENOMEM;
		goto free_devicetype;
	}
	memset(xendev, 0, xendev_n);

	snprintf(xendev->dev.bus_id, BUS_ID_SIZE, "%s-%s", devicetype, name);
	xendev->dev.bus = &xenbus_type;

	xendev->id = id;

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

free_devicetype:
	kfree(devicetype);
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
		err = xenbus_probe_device(path, dir[i]);
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

static void test_callback(struct xenbus_watch *w, const char *node)
{
	printk("test_callback: got watch hit for %s\n", node);
}

static void test_watch(void)
{
	static int init_done = 0;
	static struct xenbus_watch watch = { .node = "/", 
					     .priority = 0, 
					     .callback = test_callback };

	if (init_done)
		return;
	printk("registering watch %lX = %i\n",
	       (long)&watch,
	       register_xenbus_watch(&watch));
	init_done = 1;
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

int do_xenbus_connect(void *unused)
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
	test_watch();
	printk("%s> connect drivers...\n", __FUNCTION__);
	xenbus_for_each_drv(NULL, NULL, xenbus_driver_connect);
	printk("%s> connect backends...\n", __FUNCTION__);
	xenbus_for_each_backend(NULL, NULL, xenbus_driver_connect);
	
	/* Enumerate devices and backends in xenstore. */
	xenbus_probe_devices(XENBUS_DEVICE_DIR);
	xenbus_probe_backends(XENBUS_BACKEND_DIR);

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

	do_xenbus_connect(NULL);
	return 0;
}

postcore_initcall(xenbus_probe_init);
