/*  Xenbus code for blkif backend
    Copyright (C) 2005 Rusty Russell <rusty@rustcorp.com.au>

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
#include <asm-xen/xenbus.h>
#include "common.h"

struct backend_info
{
	struct xenbus_device *dev;

	/* our communications channel */
	blkif_t *blkif;
	struct vbd *vbd;

	long int frontend_id;
	long int pdev;
	long int readonly;

	/* watch back end for changes */
	struct xenbus_watch backend_watch;

	/* watch front end for changes */
	struct xenbus_watch watch;
	char *frontpath;
};

static int blkback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev->data;

	unregister_xenbus_watch(&be->watch);
	unregister_xenbus_watch(&be->backend_watch);
	vbd_free(be->blkif, be->vbd);
	blkif_put(be->blkif);
	kfree(be->frontpath);
	kfree(be);
	return 0;
}

/* Front end tells us frame. */
static void frontend_changed(struct xenbus_watch *watch, const char *node)
{
	unsigned long sharedmfn;
	unsigned int evtchn;
	int err;
	struct backend_info *be
		= container_of(watch, struct backend_info, watch);

	// printk("Got front end event on %s (%s)\n", node, be->frontpath);

	if (vbd_is_active(be->vbd)) {
		/* If other end is gone, delete ourself. */
		if (!xenbus_exists(be->frontpath, "")) {
			// printk("Removing...\n");
			xenbus_rm(be->dev->nodename, "");
			device_unregister(&be->dev->dev);
		}
		return;
	}

#ifndef CONFIG_XEN_BLKDEV_GRANT
	err = xenbus_gather(be->frontpath, "shared-frame", "%lu", &sharedmfn,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_error(be->dev, err, 
				 "reading %s/shared-frame and event-channel",
				 be->frontpath);
		return;
	}
#else
	err = xenbus_gather(be->frontpath, "grant-id", "%lu", &sharedmfn,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_error(be->dev, err, 
				 "reading %s/grant-id and event-channel",
				 be->frontpath);
		return;
	}
#endif

	/* Domains must use same shared frame for all vbds. */
	if (be->blkif->status == CONNECTED &&
	    (evtchn != be->blkif->remote_evtchn ||
	     sharedmfn != be->blkif->shmem_frame)) {
		xenbus_dev_error(be->dev, err,
				 "Shared frame/evtchn %li/%u not same as"
				 " old %li/%u",
				 sharedmfn, evtchn,
				 be->blkif->shmem_frame,
				 be->blkif->remote_evtchn);
		return;
	}

	/* Supply the information about the device the frontend needs */
	err = xenbus_transaction_start(be->dev->nodename);
	if (err) {
		xenbus_dev_error(be->dev, err, "starting transaction");
		return;
	}

	err = xenbus_printf(be->dev->nodename, "sectors", "%lu",
			    vbd_size(be->vbd));
	if (err) {
		xenbus_dev_error(be->dev, err, "writing %s/sectors",
				 be->dev->nodename);
		goto abort;
	}

	/* FIXME: use a typename instead */
	err = xenbus_printf(be->dev->nodename, "info", "%u",
			    vbd_info(be->vbd));
	if (err) {
		xenbus_dev_error(be->dev, err, "writing %s/info",
				 be->dev->nodename);
		goto abort;
	}
	err = xenbus_printf(be->dev->nodename, "sector-size", "%lu",
			    vbd_secsize(be->vbd));
	if (err) {
		xenbus_dev_error(be->dev, err, "writing %s/sector-size",
				 be->dev->nodename);
		goto abort;
	}

	/* First vbd?  We need to map the shared frame, irq etc. */
	if (be->blkif->status != CONNECTED) {
		err = blkif_map(be->blkif, sharedmfn, evtchn);
		if (err) {
			xenbus_dev_error(be->dev, err,
					 "mapping shared-frame %lu port %u",
					 sharedmfn, evtchn);
			goto abort;
		}
	}

	/* We're ready, activate. */
	vbd_activate(be->blkif, be->vbd);

	xenbus_transaction_end(0);
	xenbus_dev_ok(be->dev);

	return;

abort:
	xenbus_transaction_end(1);
}

/* 
   Setup supplies physical device.  
   We provide event channel and device details to front end.
   Frontend supplies shared frame and event channel.
 */
static void backend_changed(struct xenbus_watch *watch, const char *node)
{
	int err;
	char *p;
	char *frontend;
	long int handle, pdev;
	struct backend_info *be
		= container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;

	err = xenbus_scanf(dev->nodename, "frontend-id", "%li",
			   &be->frontend_id);
	if (err == -ENOENT || err == -ERANGE)
		goto out;
	if (err < 0) {
		xenbus_dev_error(dev, err, "Reading frontend-id");
		goto out;
	}

	err = xenbus_scanf(dev->nodename, "physical-device", "%li", &pdev);
	if (err == -ENOENT || err == -ERANGE)
		goto out;
	if (err < 0) {
		xenbus_dev_error(dev, err, "Reading physical-device");
		goto out;
	}
	if (be->pdev && be->pdev != pdev) {
		printk(KERN_WARNING
		       "changing physical-device not supported\n");
		return;
	}
	be->pdev = pdev;

	frontend = xenbus_read(dev->nodename, "frontend", NULL);
	if (IS_ERR(frontend))
		return;
	if (strlen(frontend) == 0) {
		kfree(frontend);
		return;
	}

	/* If there's a read-only node, we're read only. */
	p = xenbus_read(dev->nodename, "read-only", NULL);
	if (!IS_ERR(p)) {
		be->readonly = 1;
		kfree(p);
	}

	if (!be->frontpath || strcmp(frontend, be->frontpath)) {
		if (be->watch.node)
			unregister_xenbus_watch(&be->watch);
		if (be->frontpath)
			kfree(be->frontpath);
		be->frontpath = frontend;
		be->watch.node = be->frontpath;
		be->watch.callback = frontend_changed;
		err = register_xenbus_watch(&be->watch);
		if (err)
			goto out;

		/* Front end dir is a number, which is used as the handle. */
		p = strrchr(be->frontpath, '/') + 1;
		handle = simple_strtoul(p, NULL, 0);

		be->blkif = blkif_find(be->frontend_id);
		if (IS_ERR(be->blkif)) {
			err = PTR_ERR(be->blkif);
			be->blkif = NULL;
			goto free_watch;
		}

		be->vbd = vbd_create(be->blkif, handle, be->pdev,
				     be->readonly);
		if (IS_ERR(be->vbd)) {
			err = PTR_ERR(be->vbd);
			blkif_put(be->blkif);
			be->blkif = NULL;
			be->vbd = NULL;
			goto free_watch;
		}

		frontend_changed(&be->watch, be->frontpath);
	} else
		kfree(frontend);

	return;

 free_watch:
	unregister_xenbus_watch(&be->watch);
	be->watch.node = NULL;
	kfree(be->frontpath);
	be->frontpath = NULL;
 out:
	return;
}

static int blkback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	struct backend_info *be;
	int err;

	be = kmalloc(sizeof(*be), GFP_KERNEL);
	if (!be)
		return -ENOMEM;

	memset(be, 0, sizeof(*be));

	be->dev = dev;
	be->backend_watch.node = dev->nodename;
	be->backend_watch.callback = backend_changed;
	err = register_xenbus_watch(&be->backend_watch);
	if (err)
		goto free_be;

	dev->data = be;

	backend_changed(&be->backend_watch, dev->nodename);
	return err;
 free_be:
	kfree(be);
	return err;
}

static struct xenbus_device_id blkback_ids[] = {
	{ "vbd" },
	{ "" }
};

static struct xenbus_driver blkback = {
	.name = __stringify(KBUILD_MODNAME),
	.owner = THIS_MODULE,
	.ids = blkback_ids,
	.probe = blkback_probe,
	.remove = blkback_remove,
};

void blkif_xenbus_init(void)
{
	xenbus_register_backend(&blkback);
}
