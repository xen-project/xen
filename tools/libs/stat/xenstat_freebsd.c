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

#include "xenstat_priv.h"

/* Collect information about networks */
int xenstat_collect_networks(xenstat_node * node)
{

	return 1;
}

/* Free network information in handle */
void xenstat_uninit_networks(xenstat_handle * handle)
{
}

/* Collect information about VBDs */
int xenstat_collect_vbds(xenstat_node * node)
{

	return 1;
}

/* Free VBD information in handle */
void xenstat_uninit_vbds(xenstat_handle * handle)
{
}
