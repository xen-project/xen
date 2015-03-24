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

#ifndef XENSTAT_PRIV_H
#define XENSTAT_PRIV_H

#include <sys/types.h>
#include <xenstore.h>
#include "xenstat.h"

#include "xenctrl.h"

#define SHORT_ASC_LEN 5                 /* length of 65535 */
#define VERSION_SIZE (2 * SHORT_ASC_LEN + 1 + sizeof(xen_extraversion_t) + 1)

struct xenstat_handle {
	xc_interface *xc_handle;
	struct xs_handle *xshandle; /* xenstore handle */
	int page_size;
	void *priv;
	char xen_version[VERSION_SIZE]; /* xen version running on this node */
};

struct xenstat_node {
	xenstat_handle *handle;
	unsigned int flags;
	unsigned long long cpu_hz;
	unsigned int num_cpus;
	unsigned long long tot_mem;
	unsigned long long free_mem;
	unsigned int num_domains;
	xenstat_domain *domains;	/* Array of length num_domains */
	long freeable_mb;
};

struct xenstat_tmem {
	unsigned long long curr_eph_pages;
	unsigned long long succ_eph_gets;
	unsigned long long succ_pers_puts;
	unsigned long long succ_pers_gets;
};

struct xenstat_domain {
	unsigned int id;
	char *name;
	unsigned int state;
	unsigned long long cpu_ns;
	unsigned int num_vcpus;		/* No. vcpus configured for domain */
	xenstat_vcpu *vcpus;		/* Array of length num_vcpus */
	unsigned long long cur_mem;	/* Current memory reservation */
	unsigned long long max_mem;	/* Total memory allowed */
	unsigned int ssid;
	unsigned int num_networks;
	xenstat_network *networks;	/* Array of length num_networks */
	unsigned int num_vbds;
	xenstat_vbd *vbds;
	xenstat_tmem tmem_stats;
};

struct xenstat_vcpu {
	unsigned int online;
	unsigned long long ns;
};

struct xenstat_network {
	unsigned int id;
	/* Received */
	unsigned long long rbytes;
	unsigned long long rpackets;
	unsigned long long rerrs;
	unsigned long long rdrop;
	/* Transmitted */
	unsigned long long tbytes;
	unsigned long long tpackets;
	unsigned long long terrs;
	unsigned long long tdrop;
};

struct xenstat_vbd {
	unsigned int back_type;
	unsigned int dev;
	unsigned long long oo_reqs;
	unsigned long long rd_reqs;
	unsigned long long wr_reqs;
	unsigned long long rd_sects;
	unsigned long long wr_sects;
};

extern int xenstat_collect_networks(xenstat_node * node);
extern void xenstat_uninit_networks(xenstat_handle * handle);
extern int xenstat_collect_vbds(xenstat_node * node);
extern void xenstat_uninit_vbds(xenstat_handle * handle);
extern void read_attributes_qdisk(xenstat_node * node);
extern xenstat_vbd *xenstat_save_vbd(xenstat_domain * domain, xenstat_vbd * vbd);

#endif /* XENSTAT_PRIV_H */
