/*  Xenbus code for tpmif backend
    Copyright (C) 2005 IBM Corporation
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
#include <xen/xenbus.h>
#include "common.h"

struct backend_info
{
	struct xenbus_device *dev;

	/* our communications channel */
	tpmif_t *tpmif;

	long int frontend_id;
	long int instance; // instance of TPM
	u8 is_instance_set;// whether instance number has been set

	/* watch front end for changes */
	struct xenbus_watch backend_watch;
	enum xenbus_state frontend_state;
};

static void maybe_connect(struct backend_info *be);
static void connect(struct backend_info *be);
static int connect_ring(struct backend_info *be);
static void backend_changed(struct xenbus_watch *watch,
                            const char **vec, unsigned int len);
static void frontend_changed(struct xenbus_device *dev,
                             enum xenbus_state frontend_state);

static int tpmback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev->data;

	if (!be) return 0;

	if (be->backend_watch.node) {
		unregister_xenbus_watch(&be->backend_watch);
		kfree(be->backend_watch.node);
		be->backend_watch.node = NULL;
	}
	if (be->tpmif) {
		vtpm_release_packets(be->tpmif, 0);
		tpmif_put(be->tpmif);
		be->tpmif = NULL;
	}
	kfree(be);
	dev->data = NULL;
	return 0;
}

static int tpmback_probe(struct xenbus_device *dev,
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

	be->is_instance_set = 0;
	be->dev = dev;
	dev->data = be;

	err = xenbus_watch_path2(dev, dev->nodename,
	                        "instance", &be->backend_watch,
	                        backend_changed);
	if (err) {
		goto fail;
	}

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err) {
		goto fail;
	}
	return 0;
fail:
	tpmback_remove(dev);
	return err;
}


static void backend_changed(struct xenbus_watch *watch,
                            const char **vec, unsigned int len)
{
	int err;
	long instance;
	struct backend_info *be
		= container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;

	err = xenbus_scanf(XBT_NULL, dev->nodename,
	                   "instance","%li", &instance);
	if (XENBUS_EXIST_ERR(err)) {
		return;
	}

	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading instance");
		return;
	}

	if (be->is_instance_set == 0) {
		be->instance = instance;
		be->is_instance_set = 1;
	}
}


static void frontend_changed(struct xenbus_device *dev,
                             enum xenbus_state frontend_state)
{
	struct backend_info *be = dev->data;
	int err;

	be->frontend_state = frontend_state;

	switch (frontend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
		break;

	case XenbusStateConnected:
		err = connect_ring(be);
		if (err) {
			return;
		}
		maybe_connect(be);
		break;

	case XenbusStateClosing:
		be->tpmif->tpm_instance = -1;
		break;

	case XenbusStateClosed:
		/*
		 * Notify the vTPM manager about the front-end
		 * having left.
		 */
		tpmif_vtpm_close(be->instance);
		device_unregister(&be->dev->dev);
		tpmback_remove(dev);
		break;

	case XenbusStateUnknown:
	case XenbusStateInitWait:
	default:
		xenbus_dev_fatal(dev, -EINVAL,
		                 "saw state %d at frontend",
		                 frontend_state);
		break;
	}
}



static void maybe_connect(struct backend_info *be)
{
	int err;

	if (be->tpmif == NULL || be->tpmif->status == CONNECTED)
		return;

	connect(be);

	/*
	 * Notify the vTPM manager about a new front-end.
	 */
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
}


static void connect(struct backend_info *be)
{
	xenbus_transaction_t xbt;
	int err;
	struct xenbus_device *dev = be->dev;
	unsigned long ready = 1;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(be->dev, err, "starting transaction");
		return;
	}

	err = xenbus_printf(xbt, be->dev->nodename,
	                    "ready", "%lu", ready);
	if (err) {
		xenbus_dev_fatal(be->dev, err, "writing 'ready'");
		goto abort;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err)
		xenbus_dev_fatal(be->dev, err, "end of transaction");

	err = xenbus_switch_state(dev, XenbusStateConnected);
	if (!err)
		be->tpmif->status = CONNECTED;
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

	err = xenbus_gather(XBT_NULL, dev->otherend,
	                    "ring-ref", "%lu", &ring_ref,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_error(dev, err,
				 "reading %s/ring-ref and event-channel",
				 dev->otherend);
		return err;
	}

	if (!be->tpmif) {
		be->tpmif = tpmif_find(dev->otherend_id,
		                       be->instance);
		if (IS_ERR(be->tpmif)) {
			err = PTR_ERR(be->tpmif);
			be->tpmif = NULL;
			xenbus_dev_fatal(dev,err,"creating vtpm interface");
			return err;
		}
	}

	if (be->tpmif != NULL) {
		err = tpmif_map(be->tpmif, ring_ref, evtchn);
		if (err) {
			xenbus_dev_error(dev, err,
			    	         "mapping shared-frame %lu port %u",
				         ring_ref, evtchn);
			return err;
		}
	}
	return 0;
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
	.otherend_changed = frontend_changed,
};


void tpmif_xenbus_init(void)
{
	xenbus_register_backend(&tpmback);
}

void tpmif_xenbus_exit(void)
{
	xenbus_unregister_driver(&tpmback);
}
