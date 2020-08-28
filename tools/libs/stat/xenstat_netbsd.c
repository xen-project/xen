/* libxenstat: statistics-collection library for Xen
 * Copyright (C) International Business Machines Corp., 2005
 * Authors: Josh Triplett <josht@us.ibm.com>
 *          Judy Fischbach <jfisch@us.ibm.com>
 *          David Hendricks <dhendrix@us.ibm.com>
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

#define SYSFS_VBD_PATH "/sys/devices/xen-backend/"

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
	/* XXX fixme: implement code to get stats from libkvm ! */
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
	/* XXX implement */
	return 0;
}

/* Collect information about VBDs */
int xenstat_collect_vbds(xenstat_node * node)
{
	return 1;	
}

/* Free VBD information in handle */
void xenstat_uninit_vbds(xenstat_handle * handle)
{
	struct priv_data *priv = get_priv_data(handle);
	if (priv != NULL && priv->sysfsvbd != NULL)
		closedir(priv->sysfsvbd);
}
