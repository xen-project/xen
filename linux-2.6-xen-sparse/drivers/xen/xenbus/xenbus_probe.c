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
		if (streq(arr->devicetype, dev->devicetype))
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

struct xen_bus_type
{
	char *root;
	unsigned int levels;
	int (*get_bus_id)(char bus_id[BUS_ID_SIZE], const char *nodename);
	int (*probe)(const char *type, const char *dir);
	struct bus_type bus;
	struct device dev;
};

/* device/<type>/<id> => <type>-<id> */
static int frontend_bus_id(char bus_id[BUS_ID_SIZE], const char *nodename)
{
	nodename = strchr(nodename, '/');
	if (!nodename || strlen(nodename + 1) >= BUS_ID_SIZE) {
		printk(KERN_WARNING "XENBUS: bad frontend %s\n", nodename);
		return -EINVAL;
	}

	strlcpy(bus_id, nodename + 1, BUS_ID_SIZE);
	if (!strchr(bus_id, '/')) {
		printk(KERN_WARNING "XENBUS: bus_id %s no slash\n", bus_id);
		return -EINVAL;
	}
	*strchr(bus_id, '/') = '-';
	return 0;
}

/* Bus type for frontend drivers. */
static int xenbus_probe_frontend(const char *type, const char *name);
static struct xen_bus_type xenbus_frontend = {
	.root = "device",
	.levels = 2, 		/* device/type/<id> */
	.get_bus_id = frontend_bus_id,
	.probe = xenbus_probe_frontend,
	.bus = {
		.name  = "xen",
		.match = xenbus_match,
	},
	.dev = {
		.bus_id = "xen",
	},
};

/* backend/<type>/<fe-uuid>/<id> => <type>-<fe-domid>-<id> */
static int backend_bus_id(char bus_id[BUS_ID_SIZE], const char *nodename)
{
	int domid, err;
	const char *devid, *type, *frontend;
	unsigned int typelen;

	type = strchr(nodename, '/');
	if (!type)
		return -EINVAL;
	type++;
	typelen = strcspn(type, "/");
	if (!typelen || type[typelen] != '/')
		return -EINVAL;

	devid = strrchr(nodename, '/') + 1;

	err = xenbus_gather(nodename, "frontend-id", "%i", &domid,
			    "frontend", NULL, &frontend,
			    NULL);
	if (err)
		return err;
	if (strlen(frontend) == 0)
		err = -ERANGE;

	if (!err && !xenbus_exists(frontend, ""))
		err = -ENOENT;

	if (err) {
		kfree(frontend);
		return err;
	}

	if (snprintf(bus_id, BUS_ID_SIZE,
		     "%.*s-%i-%s", typelen, type, domid, devid) >= BUS_ID_SIZE)
		return -ENOSPC;
	return 0;
}

static int xenbus_hotplug_backend(struct device *dev, char **envp,
				  int num_envp, char *buffer, int buffer_size)
{
	struct xenbus_device *xdev;
	int i = 0;
	int length = 0;

	if (dev == NULL)
		return -ENODEV;

	xdev = to_xenbus_device(dev);
	if (xdev == NULL)
		return -ENODEV;

	/* stuff we want to pass to /sbin/hotplug */
	add_hotplug_env_var(envp, num_envp, &i,
			    buffer, buffer_size, &length,
			    "XENBUS_TYPE=%s", xdev->devicetype);

	/* terminate, set to next free slot, shrink available space */
	envp[i] = NULL;
	envp = &envp[i];
	num_envp -= i;
	buffer = &buffer[length];
	buffer_size -= length;

	if (dev->driver && to_xenbus_driver(dev->driver)->hotplug)
		return to_xenbus_driver(dev->driver)->hotplug
			(xdev, envp, num_envp, buffer, buffer_size);

	return 0;
}

static int xenbus_probe_backend(const char *type, const char *uuid);
static struct xen_bus_type xenbus_backend = {
	.root = "backend",
	.levels = 3, 		/* backend/type/<frontend>/<id> */
	.get_bus_id = backend_bus_id,
	.probe = xenbus_probe_backend,
	.bus = {
		.name  = "xen-backend",
		.match = xenbus_match,
		.hotplug = xenbus_hotplug_backend,
	},
	.dev = {
		.bus_id = "xen-backend",
	},
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

static int xenbus_register_driver(struct xenbus_driver *drv,
				  struct xen_bus_type *bus)
{
	int err;

	drv->driver.name = drv->name;
	drv->driver.bus = &bus->bus;
	drv->driver.owner = drv->owner;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;

	down(&xenbus_lock);
	err = driver_register(&drv->driver);
	up(&xenbus_lock);
	return err;
}

int xenbus_register_device(struct xenbus_driver *drv)
{
	return xenbus_register_driver(drv, &xenbus_frontend);
}
EXPORT_SYMBOL(xenbus_register_device);

int xenbus_register_backend(struct xenbus_driver *drv)
{
	return xenbus_register_driver(drv, &xenbus_backend);
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
	const char *nodename;
};

static int cmp_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;

	if (streq(xendev->nodename, info->nodename)) {
		info->dev = xendev;
		get_device(dev);
		return 1;
	}
	return 0;
}

struct xenbus_device *xenbus_device_find(const char *nodename,
					 struct bus_type *bus)
{
	struct xb_find_info info = { .dev = NULL, .nodename = nodename };

	bus_for_each_dev(bus, NULL, &info, cmp_dev);
	return info.dev;
}

static int cleanup_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;
	int len = strlen(info->nodename);

	if (!strncmp(xendev->nodename, info->nodename, len)) {
		info->dev = xendev;
		get_device(dev);
		return 1;
	}
	return 0;
}

static void xenbus_cleanup_devices(const char *path, struct bus_type *bus)
{
	struct xb_find_info info = { .nodename = path };

	do {
		info.dev = NULL;
		bus_for_each_dev(bus, NULL, &info, cleanup_dev);
		if (info.dev) {
			device_unregister(&info.dev->dev);
			put_device(&info.dev->dev);
		}
	} while (info.dev);
}

static void xenbus_release_device(struct device *dev)
{
	if (dev) {
		struct xenbus_device *xendev = to_xenbus_device(dev);

		kfree(xendev);
	}
}

/* Simplified asprintf. */
static char *kasprintf(const char *fmt, ...)
{
	va_list ap;
	unsigned int len;
	char *p, dummy[1];

	va_start(ap, fmt);
	/* FIXME: vsnprintf has a bug, NULL should work */
	len = vsnprintf(dummy, 0, fmt, ap);
	va_end(ap);

	p = kmalloc(len + 1, GFP_KERNEL);
	if (!p)
		return NULL;
	va_start(ap, fmt);
	vsprintf(p, fmt, ap);
	va_end(ap);
	return p;
}

static int xenbus_probe_node(struct xen_bus_type *bus,
			     const char *type,
			     const char *nodename)
{
	int err;
	struct xenbus_device *xendev;
	unsigned int stringlen;

	stringlen = strlen(nodename) + 1 + strlen(type) + 1;
	xendev = kmalloc(sizeof(*xendev) + stringlen, GFP_KERNEL);
	if (!xendev)
		return -ENOMEM;
	memset(xendev, 0, sizeof(*xendev));

	/* Copy the strings into the extra space. */
	xendev->nodename = (char *)(xendev + 1);
	strcpy(xendev->nodename, nodename);
	xendev->devicetype = xendev->nodename + strlen(xendev->nodename) + 1;
	strcpy(xendev->devicetype, type);

	xendev->dev.parent = &bus->dev;
	xendev->dev.bus = &bus->bus;
	xendev->dev.release = xenbus_release_device;

	err = bus->get_bus_id(xendev->dev.bus_id, xendev->nodename);
	if (err) {
		kfree(xendev);
		return err;
	}

	/* Register with generic device framework. */
	err = device_register(&xendev->dev);
	if (err) {
		printk("XENBUS: Registering %s device %s: error %i\n",
		       bus->bus.name, xendev->dev.bus_id, err);
		kfree(xendev);
	}
	return err;
}

/* device/<typename>/<name> */
static int xenbus_probe_frontend(const char *type, const char *name)
{
	char *nodename;
	int err;

	nodename = kasprintf("%s/%s/%s", xenbus_frontend.root, type, name);
	if (!nodename)
		return -ENOMEM;
	
	err = xenbus_probe_node(&xenbus_frontend, type, nodename);
	kfree(nodename);
	return err;
}

/* backend/<typename>/<frontend-uuid>/<name> */
static int xenbus_probe_backend_unit(const char *dir,
				     const char *type,
				     const char *name)
{
	char *nodename;
	int err;

	nodename = kasprintf("%s/%s", dir, name);
	if (!nodename)
		return -ENOMEM;

	err = xenbus_probe_node(&xenbus_backend, type, nodename);
	kfree(nodename);
	return err;
}

/* backend/<typename>/<frontend-uuid> */
static int xenbus_probe_backend(const char *type, const char *uuid)
{
	char *nodename;
	int err = 0;
	char **dir;
	unsigned int i, dir_n = 0;

	nodename = kasprintf("%s/%s/%s", xenbus_backend.root, type, uuid);
	if (!nodename)
		return -ENOMEM;

	dir = xenbus_directory(nodename, "", &dir_n);
	if (IS_ERR(dir)) {
		kfree(nodename);
		return PTR_ERR(dir);
	}

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_backend_unit(nodename, type, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	kfree(nodename);
	return err;
}

static int xenbus_probe_device_type(struct xen_bus_type *bus, const char *type)
{
	int err = 0;
	char **dir;
	unsigned int dir_n = 0;
	int i;

	dir = xenbus_directory(bus->root, type, &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = bus->probe(type, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static int xenbus_probe_devices(struct xen_bus_type *bus)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	dir = xenbus_directory(bus->root, "", &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(bus, dir[i]);
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

static int strsep_len(const char *str, char c, unsigned int len)
{
	unsigned int i;

	for (i = 0; str[i]; i++)
		if (str[i] == c) {
			if (len == 0)
				return i;
			len--;
		}
	return (len == 0) ? i : -ERANGE;
}

static void dev_changed(const char *node, struct xen_bus_type *bus)
{
	int exists, rootlen;
	struct xenbus_device *dev;
	char type[BUS_ID_SIZE];
	const char *p, *root;

	if (char_count(node, '/') < 2)
 		return;

	exists = xenbus_exists(node, "");
	if (!exists) {
		xenbus_cleanup_devices(node, &bus->bus);
		return;
	}

	/* backend/<type>/... or device/<type>/... */
	p = strchr(node, '/') + 1;
	snprintf(type, BUS_ID_SIZE, "%.*s", strcspn(p, "/"), p);
	type[BUS_ID_SIZE-1] = '\0';

	rootlen = strsep_len(node, '/', bus->levels);
	if (rootlen < 0)
		return;
	root = kasprintf("%.*s", rootlen, node);
	if (!root)
		return;

	dev = xenbus_device_find(root, &bus->bus);
	if (!dev)
		xenbus_probe_node(bus, type, root);
	else
		put_device(&dev->dev);

	kfree(root);
}

static void frontend_changed(struct xenbus_watch *watch, const char *node)
{
	dev_changed(node, &xenbus_frontend);
}

static void backend_changed(struct xenbus_watch *watch, const char *node)
{
	dev_changed(node, &xenbus_backend);
}

/* We watch for devices appearing and vanishing. */
static struct xenbus_watch fe_watch = {
	.node = "device",
	.callback = frontend_changed,
};

static struct xenbus_watch be_watch = {
	.node = "backend",
	.callback = backend_changed,
};

static int suspend_dev(struct device *dev, void *data)
{
	int err = 0;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	if (dev->driver == NULL)
		return 0;
	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);
	if (drv->suspend)
		err = drv->suspend(xdev);
	if (err)
		printk("xenbus: suspend %s failed: %i\n", dev->bus_id, err);
	return 0;
}

static int resume_dev(struct device *dev, void *data)
{
	int err = 0;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	if (dev->driver == NULL)
		return 0;
	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);
	if (drv->resume)
		err = drv->resume(xdev);
	if (err)
		printk("xenbus: resume %s failed: %i\n", dev->bus_id, err);
	return 0;
}

void xenbus_suspend(void)
{
	/* We keep lock, so no comms can happen as page moves. */
	down(&xenbus_lock);
	bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, suspend_dev);
	bus_for_each_dev(&xenbus_backend.bus, NULL, NULL, suspend_dev);
	xb_suspend_comms();
}

void xenbus_resume(void)
{
	xb_init_comms();
	reregister_xenbus_watches();
	bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, resume_dev);
	bus_for_each_dev(&xenbus_backend.bus, NULL, NULL, resume_dev);
	up(&xenbus_lock);
}

int register_xenstore_notifier(struct notifier_block *nb)
{
	int ret = 0;

	down(&xenbus_lock);

	if (xen_start_info->store_evtchn) {
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
	printk("store_evtchn = %i\n", xen_start_info->store_evtchn);
	err = xs_init();
	if (err) {
		printk("XENBUS: Error initializing xenstore comms:"
		       " %i\n", err);
		return err;
	}

	down(&xenbus_lock);
	/* Enumerate devices in xenstore. */
	xenbus_probe_devices(&xenbus_frontend);
	xenbus_probe_devices(&xenbus_backend);
	/* Watch for changes. */
	register_xenbus_watch(&fe_watch);
	register_xenbus_watch(&be_watch);
	/* Notify others that xenstore is up */
	notifier_call_chain(&xenstore_chain, 0, 0);
	up(&xenbus_lock);
	return 0;
}

static int __init xenbus_probe_init(void)
{
	bus_register(&xenbus_frontend.bus);
	bus_register(&xenbus_backend.bus);
	device_register(&xenbus_frontend.dev);
	device_register(&xenbus_backend.dev);

	if (!xen_start_info->store_evtchn)
		return 0;

	do_xenbus_probe(NULL);
	return 0;
}

postcore_initcall(xenbus_probe_init);
