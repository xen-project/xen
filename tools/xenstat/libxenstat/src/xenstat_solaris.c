/* libxenstat: statistics-collection library for Xen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <kstat.h>

#include "xenstat_priv.h"

#define DEVICE_NIC 1
#define DEVICE_XDB 2

typedef struct stdevice {
	int domid;
	int used;
	int type;
	char name[256];
	int instance;
	uint64_t stats[2][8];
	struct stdevice *next;
} stdevice_t;

typedef struct priv_data {
	kstat_ctl_t *kc;
	stdevice_t *devs;
} priv_data_t;

static priv_data_t *get_priv_data(xenstat_handle *handle)
{
	priv_data_t *priv = handle->priv;

	if (priv == NULL) {
		priv = malloc(sizeof (priv_data_t));
		if (priv == NULL)
			return NULL;
		priv->devs = NULL;
		priv->kc = NULL;
	}

	if (priv->kc == NULL) {
		if ((priv->kc = kstat_open()) == NULL) {
			free(priv);
			return NULL;
		}
	}

	handle->priv = priv;
	return handle->priv;
}

static int kstat_get(kstat_t *ksp, const char *name, uint64_t *val)
{
	kstat_named_t *ksn = kstat_data_lookup(ksp, (char *)name);
	if (ksn == NULL)
		return 0;
	*val = ksn->value.ui64;
	return 1;
}

static void gc_devs(priv_data_t *priv, int type)
{
	stdevice_t *start = NULL;
	stdevice_t *dev;
	stdevice_t *tmp;

	for (dev = priv->devs; dev != NULL; dev = tmp) {
		tmp = dev->next;

		if (dev->used || dev->type != type) {
			dev->next = start;
			start = dev;
		} else {
			free(dev);
		}
	}

	priv->devs = start;
}

static void xenstat_uninit_devs(xenstat_handle *handle, int type)
{
	priv_data_t *priv = get_priv_data(handle);
	stdevice_t *dev;

	if (priv == NULL)
		return;

	for (dev = priv->devs; dev != NULL; dev = dev->next)
		dev->used = 0;

	gc_devs(priv, type);

	if (priv->kc != NULL)
	 	kstat_close(priv->kc);
	priv->kc = NULL;
}

static int update_dev_stats(priv_data_t *priv, stdevice_t *dev)
{
	kstat_t *ksp;

	if (kstat_chain_update(priv->kc) == -1)
		return 0;

	if (dev->type == DEVICE_NIC) {
		ksp = kstat_lookup(priv->kc, "link", 0, (char *)dev->name);
	} else {
		ksp = kstat_lookup(priv->kc, "xdb", dev->instance,
		    (char *)"req_statistics");
	}

	if (ksp == NULL)
		return 0;

	if (kstat_read(priv->kc, ksp, NULL) == -1)
		return 0;

	dev->used = 1;

	bcopy(&(dev->stats[1][0]), &(dev->stats[0][0]), sizeof(dev->stats[0]));

	if (dev->type == DEVICE_NIC) {
		if (!kstat_get(ksp, "rbytes64", &dev->stats[1][0]) ||
		    !kstat_get(ksp, "ipackets64", &dev->stats[1][1]) ||
		    !kstat_get(ksp, "ierrors", &dev->stats[1][2]) ||
		    !kstat_get(ksp, "obytes64", &dev->stats[1][3]) ||
		    !kstat_get(ksp, "opackets64", &dev->stats[1][4]) ||
		    !kstat_get(ksp, "oerrors", &dev->stats[1][5]))
			return 0;

		dev->stats[1][6] = 0;
		dev->stats[1][7] = 0;
	} else {
		if (!kstat_get(ksp, "rd_reqs", &dev->stats[1][0]) ||
		    !kstat_get(ksp, "wr_reqs", &dev->stats[1][1]) ||
		    !kstat_get(ksp, "oo_reqs", &dev->stats[1][2]))
			return 0;
	}

	return 1;
}

static int init_dev(priv_data_t *priv, int type, const char *name,
    int instance, int domid)
{
	stdevice_t *dev;

	if (!(dev = malloc(sizeof(*dev))))
		return 0;

	bzero(dev, sizeof(*dev));
	dev->type = type;
	if (name != NULL)
		strcpy(dev->name, name);
	dev->instance = instance;
	dev->domid = domid;
	dev->next = priv->devs;
	priv->devs = dev;

	/*
	 * Update twice to avoid delta-since-boot.
	 */
	if (!update_dev_stats(priv, dev))
		return 0;
	return update_dev_stats(priv, dev);
}

static int update_nic(priv_data_t *priv, xenstat_domain *dom,
    xenstat_network *net, const char *name)
{
	stdevice_t *dev;

	for (dev = priv->devs; dev != NULL; dev = dev->next) {
		if (dev->type == DEVICE_NIC && dev->domid == dom->id &&
		    strcmp(name, dev->name) == 0) {
			if (!update_dev_stats(priv, dev))
				return 0;
			net->rbytes = dev->stats[1][0] - dev->stats[0][0];
			net->rpackets = dev->stats[1][1] - dev->stats[0][1];
			net->rerrs = dev->stats[1][2] - dev->stats[0][2];
			net->tbytes = dev->stats[1][3] - dev->stats[0][3];
			net->tpackets = dev->stats[1][4] - dev->stats[0][4];
			net->terrs = dev->stats[1][5] - dev->stats[0][5];
			net->rdrop = dev->stats[1][6] - dev->stats[0][6];
			net->tdrop = dev->stats[1][7] - dev->stats[0][7];
			return 1;
		}
	}

	return init_dev(priv, DEVICE_NIC, name, 0, dom->id);
}

static int
collect_dom_networks(xenstat_node *node, priv_data_t *priv, xenstat_domain *dom)
{
	char path[PATH_MAX];
	char **vifs;
	int ret = 1;
	int nr;
	int i;

	snprintf(path, sizeof(path), "/local/domain/%d/device/vif", dom->id);
	
	dom->num_networks = 0;
	free(dom->networks);
	dom->networks = NULL;

	vifs = xs_directory(node->handle->xshandle, XBT_NULL, path, &nr);
	if (vifs == NULL)
		goto out;

	dom->num_networks = nr;
	dom->networks = calloc(nr, sizeof(xenstat_network));

	for (i = 0; i < dom->num_networks; i++) {
		char *tmp;

		snprintf(path, sizeof(path),
		    "/local/domain/%d/device/vif/%d/backend", dom->id, i);

		tmp = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);

		if (tmp == NULL)
			goto out;

		snprintf(path, sizeof(path), "%s/nic", tmp);
		free(tmp);
	
		tmp = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);

		if (tmp == NULL || tmp[0] == '\0') {
			free(tmp);
			goto out;
		}

		if (!(ret = update_nic(priv, dom, &dom->networks[i], tmp))) {
			free(tmp);
			goto out;
		}

		free(tmp);
	}

	ret = 1;
out:
	free(vifs);
	return ret;
}

int xenstat_collect_networks(xenstat_node * node)
{
	int i;
	priv_data_t *priv = get_priv_data(node->handle);
	stdevice_t *dev;

	if (priv == NULL)
		return 0;

	for (dev = priv->devs; dev != NULL; dev = dev->next)
		dev->used = 0;

	for (i = 0; i < node->num_domains; i++) {
		if (node->domains[i].id == 0)
			continue;
		if (!collect_dom_networks(node, priv, &node->domains[i]))
			return 0;
	}

	gc_devs(priv, DEVICE_NIC);

	return 1;
}

void xenstat_uninit_networks(xenstat_handle *handle)
{
	xenstat_uninit_devs(handle, DEVICE_NIC);
}

static int update_xdb(priv_data_t *priv, xenstat_domain *dom,
    xenstat_vbd *vbd, int instance)
{
	stdevice_t *dev;

	for (dev = priv->devs; dev != NULL; dev = dev->next) {
		if (dev->type == DEVICE_XDB && dev->domid == dom->id &&
		    dev->instance == instance) {
			if (!update_dev_stats(priv, dev))
				return 0;
			vbd->dev = dev->instance;
			vbd->rd_reqs = dev->stats[1][0] - dev->stats[0][0];
			vbd->wr_reqs = dev->stats[1][1] - dev->stats[0][1];
			vbd->oo_reqs = dev->stats[1][2] - dev->stats[0][2];
			return 1;
		}
	}

	return init_dev(priv, DEVICE_XDB, NULL, instance, dom->id);
}

static int
collect_dom_vbds(xenstat_node *node, priv_data_t *priv, xenstat_domain *dom)
{
	char path[PATH_MAX];
	char **vbds;
	int ret = 1;
	int nr;
	int i;

	snprintf(path, sizeof(path), "/local/domain/%d/device/vbd", dom->id);
	
	dom->num_vbds = 0;
	free(dom->vbds);
	dom->vbds = NULL;

	vbds = xs_directory(node->handle->xshandle, XBT_NULL, path, &nr);
	if (vbds == NULL)
		goto out;

	dom->num_vbds = nr;
	dom->vbds = calloc(nr, sizeof(xenstat_vbd));

	for (i = 0; i < dom->num_vbds; i++) {
		char *tmp;
		int inst;

		snprintf(path, sizeof(path),
		    "/local/domain/%d/device/vbd/%s/backend", dom->id, vbds[i]);

		tmp = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);

		if (tmp == NULL)
			goto out;

		snprintf(path, sizeof(path), "%s/instance", tmp);
		free(tmp);
	
		tmp = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);

		/*
		 * Fails when connection is not completed; mark it clearly with
		 * a -1.
		 */
		if (tmp == NULL || sscanf(tmp, "%d", &inst) != 1) {
			dom->vbds[i].dev = -1;
			free(tmp);
			goto out;
		}

		free(tmp);

		if (!(ret = update_xdb(priv, dom, &dom->vbds[i], inst)))
			goto out;
	}

out:
	free(vbds);
	return ret;
}

int xenstat_collect_vbds(xenstat_node * node)
{
	int i;
	priv_data_t *priv = get_priv_data(node->handle);
	stdevice_t *dev;

	if (priv == NULL)
		return 0;

	for (dev = priv->devs; dev != NULL; dev = dev->next)
		dev->used = 0;

	for (i = 0; i < node->num_domains; i++) {
		if (node->domains[i].id == 0)
			continue;
		if (!collect_dom_vbds(node, priv, &node->domains[i]))
			return 0;
	}

	gc_devs(priv, DEVICE_XDB);

	return 1;
}

void xenstat_uninit_vbds(xenstat_handle * handle)
{
	xenstat_uninit_devs(handle, DEVICE_XDB);
}
