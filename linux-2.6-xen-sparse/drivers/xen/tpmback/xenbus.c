/*  Xenbus code for tpmif backend
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
	tpmif_t *tpmif;

	long int frontend_id;
	long int instance; // instance of TPM

	/* watch front end for changes */
	struct xenbus_watch backend_watch;

	struct xenbus_watch watch;
	char * frontpath;
};

static int tpmback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev->data;

	if (be->watch.node) {
		unregister_xenbus_watch(&be->watch);
	}
	unregister_xenbus_watch(&be->backend_watch);

	tpmif_vtpm_close(be->instance);

	if (be->tpmif) {
		tpmif_put(be->tpmif);
	}

	if (be->frontpath)
		kfree(be->frontpath);
	kfree(be);
	return 0;
}


static void frontend_changed(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	unsigned long ringref;
	unsigned int evtchn;
	unsigned long ready = 1;
	int err;
	struct xenbus_transaction *xbt;
	struct backend_info *be
		= container_of(watch, struct backend_info, watch);

	/* If other end is gone, delete ourself. */
	if (vec && !xenbus_exists(NULL, be->frontpath, "")) {
		xenbus_rm(NULL, be->dev->nodename, "");
		device_unregister(&be->dev->dev);
		return;
	}

	if (be->tpmif == NULL || be->tpmif->status == CONNECTED)
		return;

	err = xenbus_gather(NULL, be->frontpath,
	                    "ring-ref", "%lu", &ringref,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_error(be->dev, err,
				 "reading %s/ring-ref and event-channel",
				 be->frontpath);
		return;
	}

	err = tpmif_map(be->tpmif, ringref, evtchn);
	if (err) {
		xenbus_dev_error(be->dev, err,
				 "mapping shared-frame %lu port %u",
				 ringref, evtchn);
		return;
	}

	err = tpmif_vtpm_open(be->tpmif,
	                      be->frontend_id,
	                      be->instance);
	if (err) {
		xenbus_dev_error(be->dev, err,
		                 "queueing vtpm open packet");
		/*
		 * Should close down this device and notify FE
		 * about closure.
		 */
		return;
	}

	/*
	 * Tell the front-end that we are ready to go -
	 * unless something bad happens
	 */
again:
	xbt = xenbus_transaction_start();
	if (IS_ERR(xbt)) {
		xenbus_dev_error(be->dev, err, "starting transaction");
		return;
	}

	err = xenbus_printf(xbt, be->dev->nodename,
	                    "ready", "%lu", ready);
	if (err) {
		xenbus_dev_error(be->dev, err, "writing 'ready'");
		goto abort;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err) {
		xenbus_dev_error(be->dev, err, "end of transaction");
		goto abort;
	}

	xenbus_dev_ok(be->dev);
	return;
abort:
	xenbus_transaction_end(xbt, 1);
}


static void backend_changed(struct xenbus_watch *watch,
			    const char **vec, unsigned int len)
{
	int err;
	long int instance;
	struct backend_info *be
		= container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;

	err = xenbus_scanf(NULL, dev->nodename, "instance", "%li", &instance);
	if (XENBUS_EXIST_ERR(err))
		return;
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading 'instance' variable");
		return;
	}

	if (be->instance != -1 && be->instance != instance) {
		printk(KERN_WARNING
		       "cannot change the instance\n");
		return;
	}
	be->instance = instance;

	if (be->tpmif == NULL) {
		unsigned int len = max(XS_WATCH_PATH, XS_WATCH_TOKEN) + 1;
		const char *vec[len];

		be->tpmif = tpmif_find(be->frontend_id,
		                       instance);
		if (IS_ERR(be->tpmif)) {
			err = PTR_ERR(be->tpmif);
			be->tpmif = NULL;
			xenbus_dev_error(dev, err, "creating interface");
			return;
		}

		vec[XS_WATCH_PATH] = be->frontpath;
		vec[XS_WATCH_TOKEN] = NULL;

		/* Pass in NULL node to skip exist test. */
		frontend_changed(&be->watch, vec, len);
	}
}


static int tpmback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	struct backend_info *be;
	char *frontend;
	int err;

	be = kmalloc(sizeof(*be), GFP_KERNEL);
	if (!be) {
		xenbus_dev_error(dev, -ENOMEM, "allocating backend structure");
		err = -ENOMEM;
	}

	memset(be, 0, sizeof(*be));

	frontend = NULL;
	err = xenbus_gather(NULL, dev->nodename,
			    "frontend-id", "%li", &be->frontend_id,
			    "frontend", NULL, &frontend,
			    NULL);
	if (XENBUS_EXIST_ERR(err))
		goto free_be;
	if (err < 0) {
		xenbus_dev_error(dev, err,
				 "reading %s/frontend or frontend-id",
				 dev->nodename);
		goto free_be;
	}
	if (strlen(frontend) == 0 || !xenbus_exists(NULL, frontend, "")) {
		/* If we can't get a frontend path and a frontend-id,
		 * then our bus-id is no longer valid and we need to
		 * destroy the backend device.
		 */
		err = -ENOENT;
		goto free_be;
	}

	be->dev = dev;
	be->backend_watch.node     = dev->nodename;
	/* Implicitly calls backend_changed() once. */
	be->backend_watch.callback = backend_changed;
	be->instance = -1;
	err = register_xenbus_watch(&be->backend_watch);
	if (err) {
		be->backend_watch.node = NULL;
		xenbus_dev_error(dev, err, "adding backend watch on %s",
				 dev->nodename);
		goto free_be;
	}

	be->frontpath = frontend;
	be->watch.node = be->frontpath;
	be->watch.callback = frontend_changed;
	err = register_xenbus_watch(&be->watch);
	if (err) {
		be->watch.node = NULL;
		xenbus_dev_error(dev, err,
				 "adding frontend watch on %s",
				 be->frontpath);
		goto free_be;
	}

	dev->data = be;
	return err;

free_be:
	if (be->backend_watch.node)
		unregister_xenbus_watch(&be->backend_watch);
	if (frontend)
		kfree(frontend);
	kfree(be);
	return err;
}


static struct xenbus_device_id tpmback_ids[] = {
	{ "vtpm" },
	{ "" }
};


static struct xenbus_driver tpmback = {
	.name = "vtpm",
	.owner = THIS_MODULE,
	.ids = tpmback_ids,
	.probe = tpmback_probe,
	.remove = tpmback_remove,
};


void tpmif_xenbus_init(void)
{
	xenbus_register_backend(&tpmback);
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
