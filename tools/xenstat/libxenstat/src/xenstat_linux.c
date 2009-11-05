/* libxenstat: statistics-collection library for Xen
 * Copyright (C) International Business Machines Corp., 2005
 * Authors: Josh Triplett <josh@kernel.org>
 *          Judy Fischbach <jfisch@cs.pdx.edu>
 *          David Hendricks <cro_marmot@comcast.net>
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

#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xenstat_priv.h"

#define SYSFS_VBD_PATH "/sys/bus/xen-backend/devices"

struct priv_data {
	FILE *procnetdev;
	DIR *sysfsvbd;
};

static struct priv_data *
get_priv_data(xenstat_handle *handle)
{
	if (handle->priv != NULL)
		return handle->priv;

	handle->priv = malloc(sizeof(struct priv_data));
	if (handle->priv == NULL)
		return (NULL);

	((struct priv_data *)handle->priv)->procnetdev = NULL;
	((struct priv_data *)handle->priv)->sysfsvbd = NULL;

	return handle->priv;
}

/* Expected format of /proc/net/dev */
static const char PROCNETDEV_HEADER[] =
    "Inter-|   Receive                                                |"
    "  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|"
    "bytes    packets errs drop fifo colls carrier compressed\n";

/* Collect information about networks */
int xenstat_collect_networks(xenstat_node * node)
{
	struct priv_data *priv = get_priv_data(node->handle);

	if (priv == NULL) {
		perror("Allocation error");
		return 0;
	}

	/* Open and validate /proc/net/dev if we haven't already */
	if (priv->procnetdev == NULL) {
		char header[sizeof(PROCNETDEV_HEADER)];
		priv->procnetdev = fopen("/proc/net/dev", "r");
		if (priv->procnetdev == NULL) {
			perror("Error opening /proc/net/dev");
			return 0;
		}

		/* Validate the format of /proc/net/dev */
		if (fread(header, sizeof(PROCNETDEV_HEADER) - 1, 1,
			  priv->procnetdev) != 1) {
			perror("Error reading /proc/net/dev header");
			return 0;
		}
		header[sizeof(PROCNETDEV_HEADER) - 1] = '\0';
		if (strcmp(header, PROCNETDEV_HEADER) != 0) {
			fprintf(stderr,
				"Unexpected /proc/net/dev format\n");
			return 0;
		}
	}

	/* Fill in networks */
	/* FIXME: optimize this */
	fseek(priv->procnetdev, sizeof(PROCNETDEV_HEADER) - 1,
	      SEEK_SET);
	while (1) {
		xenstat_domain *domain;
		xenstat_network net;
		unsigned int domid;
		int ret = fscanf(priv->procnetdev,
				 "vif%u.%u:%llu%llu%llu%llu%*u%*u%*u%*u"
				 "%llu%llu%llu%llu%*u%*u%*u%*u\n",
				 &domid, &net.id,
				 &net.tbytes, &net.tpackets, &net.terrs,
				 &net.tdrop,
				 &net.rbytes, &net.rpackets, &net.rerrs,
				 &net.rdrop);
		if (ret == EOF)
			break;
		if (ret != 10) {
			unsigned int c;
			do {
				c = fgetc(priv->procnetdev);
			} while (c != '\n' && c != EOF);
			if (c == EOF)
				break;
			continue;
		}

		/* FIXME: this does a search for the domid */
		domain = xenstat_node_domain(node, domid);
		if (domain == NULL) {
			fprintf(stderr,
				"Found interface vif%u.%u but domain %u"
				" does not exist.\n", domid, net.id,
				domid);
			continue;
		}
		if (domain->networks == NULL) {
			domain->num_networks = 1;
			domain->networks = malloc(sizeof(xenstat_network));
		} else {
			struct xenstat_network *tmp;
			domain->num_networks++;
			tmp = realloc(domain->networks,
				      domain->num_networks *
				      sizeof(xenstat_network));
			if (tmp == NULL)
				free(domain->networks);
			domain->networks = tmp;
		}
		if (domain->networks == NULL)
			return 0;
		domain->networks[domain->num_networks - 1] = net;
	}

	return 1;
}

/* Free network information in handle */
void xenstat_uninit_networks(xenstat_handle * handle)
{
	struct priv_data *priv = get_priv_data(handle);
	if (priv != NULL && priv->procnetdev != NULL)
		fclose(priv->procnetdev);
}

static int read_attributes_vbd(const char *vbd_directory, const char *what, char *ret, int cap)
{
	static char file_name[80];
	int fd, num_read;

	snprintf(file_name, sizeof(file_name), "%s/%s/%s",
		SYSFS_VBD_PATH, vbd_directory, what);
	fd = open(file_name, O_RDONLY, 0);
	if (fd==-1) return -1;
	num_read = read(fd, ret, cap - 1);
	close(fd);
	if (num_read<=0) return -1;
	ret[num_read] = '\0';
	return num_read;
}

/* Collect information about VBDs */
int xenstat_collect_vbds(xenstat_node * node)
{
	struct dirent *dp;
	struct priv_data *priv = get_priv_data(node->handle);

	if (priv == NULL) {
		perror("Allocation error");
		return 0;
	}

	if (priv->sysfsvbd == NULL) {
		priv->sysfsvbd = opendir(SYSFS_VBD_PATH);
		if (priv->sysfsvbd == NULL) {
			perror("Error opening " SYSFS_VBD_PATH);
			return 0;
		}
	}

	rewinddir(priv->sysfsvbd);

	for(dp = readdir(priv->sysfsvbd); dp != NULL ;
	    dp = readdir(priv->sysfsvbd)) {
		xenstat_domain *domain;
		xenstat_vbd vbd;
		unsigned int domid;
		int ret;
		char buf[256];

		ret = sscanf(dp->d_name, "%3s-%u-%u", buf, &domid, &vbd.dev);
		if (ret != 3)
			continue;

		if (strcmp(buf,"vbd") == 0)
			vbd.back_type = 1;
		else if (strcmp(buf,"tap") == 0)
			vbd.back_type = 2;
		else
			continue;

		domain = xenstat_node_domain(node, domid);
		if (domain == NULL) {
			fprintf(stderr,
				"Found interface %s-%u-%u but domain %u"
				" does not exist.\n",
				buf, domid, vbd.dev, domid);
			continue;
		}

		if((read_attributes_vbd(dp->d_name, "statistics/oo_req", buf, 256)<=0)
		   || ((ret = sscanf(buf, "%llu", &vbd.oo_reqs)) != 1))
		{
			continue;
		}

		if((read_attributes_vbd(dp->d_name, "statistics/rd_req", buf, 256)<=0)
		   || ((ret = sscanf(buf, "%llu", &vbd.rd_reqs)) != 1))
		{
			continue;
		}

		if((read_attributes_vbd(dp->d_name, "statistics/wr_req", buf, 256)<=0)
		   || ((ret = sscanf(buf, "%llu", &vbd.wr_reqs)) != 1))
		{
			continue;
		}

		if((read_attributes_vbd(dp->d_name, "statistics/rd_sect", buf, 256)<=0)
		   || ((ret = sscanf(buf, "%llu", &vbd.rd_sects)) != 1))
		{
			continue;
		}

		if((read_attributes_vbd(dp->d_name, "statistics/wr_sect", buf, 256)<=0)
		   || ((ret = sscanf(buf, "%llu", &vbd.wr_sects)) != 1))
		{
			continue;
		}

		if (domain->vbds == NULL) {
			domain->num_vbds = 1;
			domain->vbds = malloc(sizeof(xenstat_vbd));
		} else {
			domain->num_vbds++;
			domain->vbds = realloc(domain->vbds,
					       domain->num_vbds *
					       sizeof(xenstat_vbd));
		}
		if (domain->vbds == NULL)
			return 0;
		domain->vbds[domain->num_vbds - 1] = vbd;
	}

	return 1;	
}

/* Free VBD information in handle */
void xenstat_uninit_vbds(xenstat_handle * handle)
{
	struct priv_data *priv = get_priv_data(handle);
	if (priv != NULL && priv->sysfsvbd != NULL)
		closedir(priv->sysfsvbd);
}
