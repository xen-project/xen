/*  Xenbus code for netif backend
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
	netif_t *netif;

	long int frontend_id;

	/* watch back end for changes */
	struct xenbus_watch backend_watch;

	/* watch front end for changes */
	struct xenbus_watch watch;
	char *frontpath;
};

static int netback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev->data;

	if (be->watch.node)
		unregister_xenbus_watch(&be->watch);
	unregister_xenbus_watch(&be->backend_watch);
	if (be->netif)
		netif_disconnect(be->netif);
	if (be->frontpath)
		kfree(be->frontpath);
	kfree(be);
	return 0;
}

/* Front end tells us frame. */
static void frontend_changed(struct xenbus_watch *watch, 
			     const char **vec, unsigned int len)
{
	unsigned long tx_ring_ref, rx_ring_ref;
	unsigned int evtchn;
	int err;
	struct backend_info *be
		= container_of(watch, struct backend_info, watch);
	char *mac, *e, *s;
	int i;

	/* If other end is gone, delete ourself. */
	if (vec && !xenbus_exists(NULL, be->frontpath, "")) {
		xenbus_rm(NULL, be->dev->nodename, "");
		device_unregister(&be->dev->dev);
		return;
	}
	if (be->netif == NULL || be->netif->status == CONNECTED)
		return;

	mac = xenbus_read(NULL, be->frontpath, "mac", NULL);
	if (IS_ERR(mac)) {
		err = PTR_ERR(mac);
		xenbus_dev_error(be->dev, err, "reading %s/mac",
				 be->dev->nodename);
		return;
	}
	s = mac;
	for (i = 0; i < ETH_ALEN; i++) {
		be->netif->fe_dev_addr[i] = simple_strtoul(s, &e, 16);
		if (s == e || (e[0] != ':' && e[0] != 0)) {
			kfree(mac);
			err = -ENOENT;
			xenbus_dev_error(be->dev, err, "parsing %s/mac",
					 be->dev->nodename);
			return;
		}
		s = &e[1];
	}
	kfree(mac);

	err = xenbus_gather(NULL, be->frontpath,
			    "tx-ring-ref", "%lu", &tx_ring_ref,
			    "rx-ring-ref", "%lu", &rx_ring_ref,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_error(be->dev, err,
				 "reading %s/ring-ref and event-channel",
				 be->frontpath);
		return;
	}

	/* Map the shared frame, irq etc. */
	err = netif_map(be->netif, tx_ring_ref, rx_ring_ref, evtchn);
	if (err) {
		xenbus_dev_error(be->dev, err,
				 "mapping shared-frames %lu/%lu port %u",
				 tx_ring_ref, rx_ring_ref, evtchn);
		return;
	}

	xenbus_dev_ok(be->dev);

	return;
}

/* 
   Setup supplies physical device.  
   We provide event channel and device details to front end.
   Frontend supplies shared frame and event channel.
 */
static void backend_changed(struct xenbus_watch *watch,
			    const char **vec, unsigned int len)
{
	int err;
	long int handle;
	struct backend_info *be
		= container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;
	u8 be_mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };

	err = xenbus_scanf(NULL, dev->nodename, "handle", "%li", &handle);
	if (XENBUS_EXIST_ERR(err))
		return;
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading handle");
		return;
	}

	if (be->netif == NULL) {
		be->netif = alloc_netif(be->frontend_id, handle, be_mac);
		if (IS_ERR(be->netif)) {
			err = PTR_ERR(be->netif);
			be->netif = NULL;
			xenbus_dev_error(dev, err, "creating interface");
			return;
		}

		kobject_hotplug(&dev->dev.kobj, KOBJ_ONLINE);

		/* Pass in NULL node to skip exist test. */
		frontend_changed(&be->watch, NULL, 0);
	}
}

static int netback_hotplug(struct xenbus_device *xdev, char **envp,
			   int num_envp, char *buffer, int buffer_size)
{
	struct backend_info *be = xdev->data;
	netif_t *netif = be->netif;
	int i = 0, length = 0;

	char *val = xenbus_read(NULL, xdev->nodename, "script", NULL);
	if (IS_ERR(val)) {
		int err = PTR_ERR(val);
		xenbus_dev_error(xdev, err, "reading script");
		return err;
	}
	else {
		add_hotplug_env_var(envp, num_envp, &i,
				    buffer, buffer_size, &length,
				    "script=%s", val);
		kfree(val);
	}

	add_hotplug_env_var(envp, num_envp, &i,
			    buffer, buffer_size, &length,
			    "vif=%s", netif->dev->name);

	envp[i] = NULL;

	return 0;
}

static int netback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	struct backend_info *be;
	char *frontend;
	int err;

	be = kmalloc(sizeof(*be), GFP_KERNEL);
	if (!be) {
		xenbus_dev_error(dev, -ENOMEM, "allocating backend structure");
		return -ENOMEM;
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
	be->backend_watch.node = dev->nodename;
	be->backend_watch.callback = backend_changed;
	/* Registration implicitly calls backend_changed. */
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
	return 0;

 free_be:
	if (be->backend_watch.node)
		unregister_xenbus_watch(&be->backend_watch);
	if (frontend)
		kfree(frontend);
	kfree(be);
	return err;
}

static struct xenbus_device_id netback_ids[] = {
	{ "vif" },
	{ "" }
};

static struct xenbus_driver netback = {
	.name = "vif",
	.owner = THIS_MODULE,
	.ids = netback_ids,
	.probe = netback_probe,
	.remove = netback_remove,
	.hotplug = netback_hotplug,
};

void netif_xenbus_init(void)
{
	xenbus_register_backend(&netback);
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
