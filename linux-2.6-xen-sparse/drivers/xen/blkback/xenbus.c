/*  Xenbus code for blkif backend
    Copyright (C) 2005 Rusty Russell <rusty@rustcorp.com.au>
    Copyright (C) 2005 XenSource Ltd

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <stdarg.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <xen/xenbus.h>
#include "common.h"

#undef DPRINTK
#define DPRINTK(fmt, args...) \
    pr_debug("blkback/xenbus (%s:%d) " fmt ".\n", __FUNCTION__, __LINE__, ##args)


struct backend_info
{
	struct xenbus_device *dev;
	blkif_t *blkif;
	struct xenbus_watch backend_watch;

	unsigned major;
	unsigned minor;
	char *mode;
};


static void maybe_connect(struct backend_info *);
static void connect(struct backend_info *);
static int connect_ring(struct backend_info *);
static void backend_changed(struct xenbus_watch *, const char **,
			    unsigned int);


void update_blkif_status(blkif_t *blkif)
{ 
	if(blkif->irq && blkif->vbd.bdev) {
		blkif->status = CONNECTED; 
		(void)blkif_be_int(0, blkif, NULL); 
	}
	maybe_connect(blkif->be); 
}


static ssize_t show_physical_device(struct device *_dev,
				    struct device_attribute *attr, char *buf)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct backend_info *be = dev->data;
	return sprintf(buf, "%x:%x\n", be->major, be->minor);
}
DEVICE_ATTR(physical_device, S_IRUSR | S_IRGRP | S_IROTH,
	    show_physical_device, NULL);


static ssize_t show_mode(struct device *_dev, struct device_attribute *attr,
			 char *buf)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct backend_info *be = dev->data;
	return sprintf(buf, "%s\n", be->mode);
}
DEVICE_ATTR(mode, S_IRUSR | S_IRGRP | S_IROTH, show_mode, NULL);


static int blkback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev->data;

	DPRINTK("");

	if (be->backend_watch.node) {
		unregister_xenbus_watch(&be->backend_watch);
		kfree(be->backend_watch.node);
		be->backend_watch.node = NULL;
	}
	if (be->blkif) {
		be->blkif->status = DISCONNECTED; 
		if (be->blkif->xenblkd)
			kthread_stop(be->blkif->xenblkd);
		blkif_put(be->blkif);
		be->blkif = NULL;
	}

	device_remove_file(&dev->dev, &dev_attr_physical_device);
	device_remove_file(&dev->dev, &dev_attr_mode);

	kfree(be);
	dev->data = NULL;
	return 0;
}


/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures, and watch the store waiting for the hotplug scripts to tell us
 * the device's physical major and minor numbers.  Switch to InitWait.
 */
static int blkback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	int err;
	struct backend_info *be = kzalloc(sizeof(struct backend_info),
					  GFP_KERNEL);
	if (!be) {
		xenbus_dev_fatal(dev, -ENOMEM,
				 "allocating backend structure");
		return -ENOMEM;
	}
	be->dev = dev;
	dev->data = be;

	be->blkif = alloc_blkif(dev->otherend_id);
	if (IS_ERR(be->blkif)) {
		err = PTR_ERR(be->blkif);
		be->blkif = NULL;
		xenbus_dev_fatal(dev, err, "creating block interface");
		goto fail;
	}

	/* setup back pointer */
	be->blkif->be = be; 

	err = xenbus_watch_path2(dev, dev->nodename, "physical-device",
				 &be->backend_watch, backend_changed);
	if (err)
		goto fail;

	err = xenbus_switch_state(dev, XBT_NULL, XenbusStateInitWait);
	if (err)
		goto fail;

	return 0;

fail:
	DPRINTK("failed");
	blkback_remove(dev);
	return err;
}


/**
 * Callback received when the hotplug scripts have placed the physical-device
 * node.  Read it and the mode node, and create a vbd.  If the frontend is
 * ready, connect.
 */
static void backend_changed(struct xenbus_watch *watch,
			    const char **vec, unsigned int len)
{
	int err;
	unsigned major;
	unsigned minor;
	struct backend_info *be
		= container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;

	DPRINTK("");

	err = xenbus_scanf(XBT_NULL, dev->nodename, "physical-device", "%x:%x",
			   &major, &minor);
	if (XENBUS_EXIST_ERR(err)) {
		/* Since this watch will fire once immediately after it is
		   registered, we expect this.  Ignore it, and wait for the
		   hotplug scripts. */
		return;
	}
	if (err != 2) {
		xenbus_dev_fatal(dev, err, "reading physical-device");
		return;
	}

	if (be->major && be->minor &&
	    (be->major != major || be->minor != minor)) {
		printk(KERN_WARNING
		       "blkback: changing physical device (from %x:%x to "
		       "%x:%x) not supported.\n", be->major, be->minor,
		       major, minor);
		return;
	}

	be->mode = xenbus_read(XBT_NULL, dev->nodename, "mode", NULL);
	if (IS_ERR(be->mode)) {
		err = PTR_ERR(be->mode);
		be->mode = NULL;
		xenbus_dev_fatal(dev, err, "reading mode");
		return;
	}

	if (be->major == 0 && be->minor == 0) {
		/* Front end dir is a number, which is used as the handle. */

		char *p = strrchr(dev->otherend, '/') + 1;
		long handle = simple_strtoul(p, NULL, 0);

		be->major = major;
		be->minor = minor;

		err = vbd_create(be->blkif, handle, major, minor,
				 (NULL == strchr(be->mode, 'w')));
		if (err) {
			be->major = 0;
			be->minor = 0;
			xenbus_dev_fatal(dev, err, "creating vbd structure");
			return;
		}

		be->blkif->xenblkd = kthread_run(blkif_schedule, be->blkif,
						 "xvd %d %02x:%02x",
						 be->blkif->domid,
						 be->major, be->minor);
		if (IS_ERR(be->blkif->xenblkd)) {
			err = PTR_ERR(be->blkif->xenblkd);
			be->blkif->xenblkd = NULL;
			xenbus_dev_error(dev, err, "start xenblkd");
			return;
		}

		device_create_file(&dev->dev, &dev_attr_physical_device);
		device_create_file(&dev->dev, &dev_attr_mode);

		/* We're potentially connected now */
		update_blkif_status(be->blkif); 
	}
}


/**
 * Callback received when the frontend's state changes.
 */
static void frontend_changed(struct xenbus_device *dev,
			     XenbusState frontend_state)
{
	struct backend_info *be = dev->data;
	int err;

	DPRINTK("");

	switch (frontend_state) {
	case XenbusStateInitialising:
	case XenbusStateConnected:
		break;

	case XenbusStateInitialised:
		err = connect_ring(be);
		if (err) {
			return;
		}
		update_blkif_status(be->blkif); 
		break;

	case XenbusStateClosing:
		xenbus_switch_state(dev, XBT_NULL, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		device_unregister(&dev->dev);
		break;

	case XenbusStateUnknown:
	case XenbusStateInitWait:
	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}


/* ** Connection ** */


static void maybe_connect(struct backend_info *be)
{
	if ((be->major != 0 || be->minor != 0) &&
	    be->blkif->status == CONNECTED)
		connect(be);
}


/**
 * Write the physical details regarding the block device to the store, and
 * switch to Connected state.
 */
static void connect(struct backend_info *be)
{
	xenbus_transaction_t xbt;
	int err;
	struct xenbus_device *dev = be->dev;

	DPRINTK("%s", dev->otherend);

	/* Supply the information about the device the frontend needs */
again:
	err = xenbus_transaction_start(&xbt);

	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		return;
	}

	err = xenbus_printf(xbt, dev->nodename, "sectors", "%lu",
			    vbd_size(&be->blkif->vbd));
	if (err) {
		xenbus_dev_fatal(dev, err, "writing %s/sectors",
				 dev->nodename);
		goto abort;
	}

	/* FIXME: use a typename instead */
	err = xenbus_printf(xbt, dev->nodename, "info", "%u",
			    vbd_info(&be->blkif->vbd));
	if (err) {
		xenbus_dev_fatal(dev, err, "writing %s/info",
				 dev->nodename);
		goto abort;
	}
	err = xenbus_printf(xbt, dev->nodename, "sector-size", "%lu",
			    vbd_secsize(&be->blkif->vbd));
	if (err) {
		xenbus_dev_fatal(dev, err, "writing %s/sector-size",
				 dev->nodename);
		goto abort;
	}

	err = xenbus_switch_state(dev, xbt, XenbusStateConnected);
	if (err)
		goto abort;

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err)
		xenbus_dev_fatal(dev, err, "ending transaction");
	return;
 abort:
	xenbus_transaction_end(xbt, 1);
}


static int connect_ring(struct backend_info *be)
{
	struct xenbus_device *dev = be->dev;
	unsigned long ring_ref;
	unsigned int evtchn;
	int err;

	DPRINTK("%s", dev->otherend);

	err = xenbus_gather(XBT_NULL, dev->otherend, "ring-ref", "%lu", &ring_ref,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_fatal(dev, err,
				 "reading %s/ring-ref and event-channel",
				 dev->otherend);
		return err;
	}

	/* Map the shared frame, irq etc. */
	err = blkif_map(be->blkif, ring_ref, evtchn);
	if (err) {
		xenbus_dev_fatal(dev, err, "mapping ring-ref %lu port %u",
				 ring_ref, evtchn);
		return err;
	}

	return 0;
}


/* ** Driver Registration ** */


static struct xenbus_device_id blkback_ids[] = {
	{ "vbd" },
	{ "" }
};


static struct xenbus_driver blkback = {
	.name = "vbd",
	.owner = THIS_MODULE,
	.ids = blkback_ids,
	.probe = blkback_probe,
	.remove = blkback_remove,
	.otherend_changed = frontend_changed
};


void blkif_xenbus_init(void)
{
	xenbus_register_backend(&blkback);
}


/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
