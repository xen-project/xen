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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "xenstat_priv.h"

/*
 * Data-collection types
 */
/* Called to collect the information for the node and all the domains on
 * it. When called, the domain information has already been collected. 
 * Return status is 0 if fatal error occurs, 1 for success. Collectors
 * may prune a domain from the list if it has been deleted between the
 * time the list was setup and the time the colector is called */
typedef int (*xenstat_collect_func)(xenstat_node * node);
/* Called to free the information collected by the collect function.  The free
 * function will only be called on a xenstat_node if that node includes
 * information collected by the corresponding collector. */
typedef void (*xenstat_free_func)(xenstat_node * node);
/* Called to free any information stored in the handle.  Note the lack of a
 * matching init function; the collect functions should initialize on first
 * use.  Also, the uninit function must handle the case that the collector has
 * never been initialized. */
typedef void (*xenstat_uninit_func)(xenstat_handle * handle);
typedef struct xenstat_collector {
	unsigned int flag;
	xenstat_collect_func collect;
	xenstat_free_func free;
	xenstat_uninit_func uninit;
} xenstat_collector;

static int  xenstat_collect_vcpus(xenstat_node * node);
static int  xenstat_collect_xen_version(xenstat_node * node);
static void xenstat_free_vcpus(xenstat_node * node);
static void xenstat_free_networks(xenstat_node * node);
static void xenstat_free_xen_version(xenstat_node * node);
static void xenstat_free_vbds(xenstat_node * node);
static void xenstat_uninit_vcpus(xenstat_handle * handle);
static void xenstat_uninit_xen_version(xenstat_handle * handle);
static char *xenstat_get_domain_name(xenstat_handle * handle, unsigned int domain_id);
static void xenstat_prune_domain(xenstat_node *node, unsigned int entry);

static xenstat_collector collectors[] = {
	{ XENSTAT_VCPU, xenstat_collect_vcpus,
	  xenstat_free_vcpus, xenstat_uninit_vcpus },
	{ XENSTAT_NETWORK, xenstat_collect_networks,
	  xenstat_free_networks, xenstat_uninit_networks },
	{ XENSTAT_XEN_VERSION, xenstat_collect_xen_version,
	  xenstat_free_xen_version, xenstat_uninit_xen_version },
	{ XENSTAT_VBD, xenstat_collect_vbds,
	  xenstat_free_vbds, xenstat_uninit_vbds }
};

#define NUM_COLLECTORS (sizeof(collectors)/sizeof(xenstat_collector))

/*
 * libxenstat API
 */
xenstat_handle *xenstat_init(void)
{
	xenstat_handle *handle;

	handle = (xenstat_handle *) calloc(1, sizeof(xenstat_handle));
	if (handle == NULL)
		return NULL;

#if defined(PAGESIZE)
	handle->page_size = PAGESIZE;
#elif defined(PAGE_SIZE)
	handle->page_size = PAGE_SIZE;
#else
	handle->page_size = sysconf(_SC_PAGE_SIZE);
	if (handle->page_size < 0) {
		perror("Failed to retrieve page size.");
		free(handle);
		return NULL;
	}
#endif

	handle->xc_handle = xc_interface_open(0,0,0);
	if (!handle->xc_handle) {
		perror("xc_interface_open");
		free(handle);
		return NULL;
	}

	handle->xshandle = xs_daemon_open_readonly(); /* open handle to xenstore*/
	if (handle->xshandle == NULL) {
		perror("unable to open xenstore");
		xc_interface_close(handle->xc_handle);
		free(handle);
		return NULL;
	}

	return handle;
}

void xenstat_uninit(xenstat_handle * handle)
{
	unsigned int i;
	if (handle) {
		for (i = 0; i < NUM_COLLECTORS; i++)
			collectors[i].uninit(handle);
		xc_interface_close(handle->xc_handle);
		xs_daemon_close(handle->xshandle);
		free(handle->priv);
		free(handle);
	}
}

static inline unsigned long long parse(char *s, char *match)
{
	char *s1 = strstr(s,match);
	unsigned long long ret;

	if ( s1 == NULL )
		return 0LL;
	s1 += 2;
	if ( *s1++ != ':' )
		return 0LL;
	sscanf(s1,"%llu",&ret);
	return ret;
}

void domain_get_tmem_stats(xenstat_handle * handle, xenstat_domain * domain)
{
	char buffer[4096];

	if (xc_tmem_control(handle->xc_handle,-1,XEN_SYSCTL_TMEM_OP_LIST,domain->id,
                        sizeof(buffer),-1,buffer) < 0)
		return;
	domain->tmem_stats.curr_eph_pages = parse(buffer,"Ec");
	domain->tmem_stats.succ_eph_gets = parse(buffer,"Ge");
	domain->tmem_stats.succ_pers_puts = parse(buffer,"Pp");
	domain->tmem_stats.succ_pers_gets = parse(buffer,"Gp");
}

xenstat_node *xenstat_get_node(xenstat_handle * handle, unsigned int flags)
{
#define DOMAIN_CHUNK_SIZE 256
	xenstat_node *node;
	xc_physinfo_t physinfo = { 0 };
	xc_domaininfo_t domaininfo[DOMAIN_CHUNK_SIZE];
	int new_domains;
	unsigned int i;
	int rc;

	/* Create the node */
	node = (xenstat_node *) calloc(1, sizeof(xenstat_node));
	if (node == NULL)
		return NULL;

	/* Store the handle in the node for later access */
	node->handle = handle;

	/* Get information about the physical system */
	if (xc_physinfo(handle->xc_handle, &physinfo) < 0) {
		free(node);
		return NULL;
	}


	node->cpu_hz = ((unsigned long long)physinfo.cpu_khz) * 1000ULL;
        node->num_cpus = physinfo.nr_cpus;
	node->tot_mem = ((unsigned long long)physinfo.total_pages)
	    * handle->page_size;
	node->free_mem = ((unsigned long long)physinfo.free_pages)
	    * handle->page_size;

	rc = xc_tmem_control(handle->xc_handle, -1,
                         XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB, -1, 0, 0, NULL);
	node->freeable_mb = (rc < 0) ? 0 : rc;
	/* malloc(0) is not portable, so allocate a single domain.  This will
	 * be resized below. */
	node->domains = malloc(sizeof(xenstat_domain));
	if (node->domains == NULL) {
		free(node);
		return NULL;
	}

	node->num_domains = 0;
	do {
		xenstat_domain *domain, *tmp;

		new_domains = xc_domain_getinfolist(handle->xc_handle,
						    node->num_domains, 
						    DOMAIN_CHUNK_SIZE, 
						    domaininfo);
		if (new_domains < 0)
			goto err;

		tmp = realloc(node->domains,
			      (node->num_domains + new_domains)
			      * sizeof(xenstat_domain));
		if (tmp == NULL)
			goto err;

		node->domains = tmp;

		domain = node->domains + node->num_domains;

		/* zero out newly allocated memory in case error occurs below */
		memset(domain, 0, new_domains * sizeof(xenstat_domain));

		for (i = 0; i < new_domains; i++) {
			/* Fill in domain using domaininfo[i] */
			domain->id = domaininfo[i].domain;
			domain->name = xenstat_get_domain_name(handle, 
							       domain->id);
			if (domain->name == NULL) {
				if (errno == ENOMEM) {
					/* fatal error */
					xenstat_free_node(node);
					return NULL;
				}
				else {
					/* failed to get name -- this means the
					   domain is being destroyed so simply
					   ignore this entry */
					continue;
				}
			}
			domain->state = domaininfo[i].flags;
			domain->cpu_ns = domaininfo[i].cpu_time;
			domain->num_vcpus = (domaininfo[i].max_vcpu_id+1);
			domain->vcpus = NULL;
			domain->cur_mem =
			    ((unsigned long long)domaininfo[i].tot_pages)
			    * handle->page_size;
			domain->max_mem =
			    domaininfo[i].max_pages == UINT_MAX
			    ? (unsigned long long)-1
			    : (unsigned long long)(domaininfo[i].max_pages
						   * handle->page_size);
			domain->ssid = domaininfo[i].ssidref;
			domain->num_networks = 0;
			domain->networks = NULL;
			domain->num_vbds = 0;
			domain->vbds = NULL;
			domain_get_tmem_stats(handle,domain);

			domain++;
			node->num_domains++;
		}
	} while (new_domains == DOMAIN_CHUNK_SIZE);


	/* Run all the extra data collectors requested */
	node->flags = 0;
	for (i = 0; i < NUM_COLLECTORS; i++) {
		if ((flags & collectors[i].flag) == collectors[i].flag) {
			node->flags |= collectors[i].flag;
			if(collectors[i].collect(node) == 0) {
				xenstat_free_node(node);
				return NULL;
			}
		}
	}

	return node;
err:
	free(node->domains);
	free(node);
	return NULL;
}

void xenstat_free_node(xenstat_node * node)
{
	int i;

	if (node) {
		if (node->domains) {
			for (i = 0; i < node->num_domains; i++)
				free(node->domains[i].name);

			for (i = 0; i < NUM_COLLECTORS; i++)
				if((node->flags & collectors[i].flag)
				   == collectors[i].flag)
					collectors[i].free(node);
			free(node->domains);
		}
		free(node);
	}
}

xenstat_domain *xenstat_node_domain(xenstat_node * node, unsigned int domid)
{
	unsigned int i;

	/* FIXME: binary search */
	/* Find the appropriate domain entry in the node struct. */
	for (i = 0; i < node->num_domains; i++) {
		if (node->domains[i].id == domid)
			return &(node->domains[i]);
	}
	return NULL;
}

xenstat_domain *xenstat_node_domain_by_index(xenstat_node * node,
					     unsigned int index)
{
	if (index < node->num_domains)
		return &(node->domains[index]);
	return NULL;
}

const char *xenstat_node_xen_version(xenstat_node * node)
{
	return node->handle->xen_version;
}

unsigned long long xenstat_node_tot_mem(xenstat_node * node)
{
	return node->tot_mem;
}

unsigned long long xenstat_node_free_mem(xenstat_node * node)
{
	return node->free_mem;
}

long xenstat_node_freeable_mb(xenstat_node * node)
{
	return node->freeable_mb;
}

unsigned int xenstat_node_num_domains(xenstat_node * node)
{
	return node->num_domains;
}

unsigned int xenstat_node_num_cpus(xenstat_node * node)
{
	return node->num_cpus;
}

/* Get information about the CPU speed */
unsigned long long xenstat_node_cpu_hz(xenstat_node * node)
{
	return node->cpu_hz;
}

/* Get the domain ID for this domain */
unsigned xenstat_domain_id(xenstat_domain * domain)
{
	return domain->id;
}

/* Get the domain name for the domain */
char *xenstat_domain_name(xenstat_domain * domain)
{
	return domain->name;
}

/* Get information about how much CPU time has been used */
unsigned long long xenstat_domain_cpu_ns(xenstat_domain * domain)
{
	return domain->cpu_ns;
}

/* Find the number of VCPUs for a domain */
unsigned int xenstat_domain_num_vcpus(xenstat_domain * domain)
{
	return domain->num_vcpus;
}

xenstat_vcpu *xenstat_domain_vcpu(xenstat_domain * domain, unsigned int vcpu)
{
	if (vcpu < domain->num_vcpus)
		return &(domain->vcpus[vcpu]);
	return NULL;
}

/* Find the current memory reservation for this domain */
unsigned long long xenstat_domain_cur_mem(xenstat_domain * domain)
{
	return domain->cur_mem;
}

/* Find the maximum memory reservation for this domain */
unsigned long long xenstat_domain_max_mem(xenstat_domain * domain)
{
	return domain->max_mem;
}

/* Find the domain's SSID */
unsigned int xenstat_domain_ssid(xenstat_domain * domain)
{
	return domain->ssid;
}

/* Get domain states */
unsigned int xenstat_domain_dying(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_dying) == XEN_DOMINF_dying;
}

unsigned int xenstat_domain_crashed(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) == SHUTDOWN_crash);
}

unsigned int xenstat_domain_shutdown(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) != SHUTDOWN_crash);
}

unsigned int xenstat_domain_paused(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_paused) == XEN_DOMINF_paused;
}

unsigned int xenstat_domain_blocked(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_blocked) == XEN_DOMINF_blocked;
}

unsigned int xenstat_domain_running(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_running) == XEN_DOMINF_running;
}

/* Get the number of networks for a given domain */
unsigned int xenstat_domain_num_networks(xenstat_domain * domain)
{
	return domain->num_networks;
}

/* Get the network handle to obtain network stats */
xenstat_network *xenstat_domain_network(xenstat_domain * domain,
					unsigned int network)
{
	if (domain->networks && network < domain->num_networks)
		return &(domain->networks[network]);
	return NULL;
}

/* Get the number of VBDs for a given domain */
unsigned int xenstat_domain_num_vbds(xenstat_domain * domain)
{
	return domain->num_vbds;
}

/* Get the VBD handle to obtain VBD stats */
xenstat_vbd *xenstat_domain_vbd(xenstat_domain * domain,
				unsigned int vbd)
{
	if (domain->vbds && vbd < domain->num_vbds)
		return &(domain->vbds[vbd]);
	return NULL;
}

/*
 * VCPU functions
 */
/* Collect information about VCPUs */
static int xenstat_collect_vcpus(xenstat_node * node)
{
	unsigned int i, vcpu, inc_index;

	/* Fill in VCPU information */
	for (i = 0; i < node->num_domains; i+=inc_index) {
		inc_index = 1; /* default is to increment to next domain */

		node->domains[i].vcpus = malloc(node->domains[i].num_vcpus
						* sizeof(xenstat_vcpu));
		if (node->domains[i].vcpus == NULL)
			return 0;
	
		for (vcpu = 0; vcpu < node->domains[i].num_vcpus; vcpu++) {
			/* FIXME: need to be using a more efficient mechanism*/
			xc_vcpuinfo_t info;

			if (xc_vcpu_getinfo(node->handle->xc_handle,
					    node->domains[i].id, vcpu, &info) != 0) {
				if (errno == ENOMEM) {
					/* fatal error */ 
					return 0;
				}
				else {
					/* domain is in transition - remove
					   from list */
					xenstat_prune_domain(node, i);

					/* remember not to increment index! */
					inc_index = 0;
					break;
				}
			}
			else {
				node->domains[i].vcpus[vcpu].online = info.online;
				node->domains[i].vcpus[vcpu].ns = info.cpu_time;
			}
		}
	}
	return 1;
}

/* Free VCPU information */
static void xenstat_free_vcpus(xenstat_node * node)
{
	unsigned int i;
	for (i = 0; i < node->num_domains; i++)
		free(node->domains[i].vcpus);
}

/* Free VCPU information in handle - nothing to do */
static void xenstat_uninit_vcpus(xenstat_handle * handle)
{
}

/* Get VCPU online status */
unsigned int xenstat_vcpu_online(xenstat_vcpu * vcpu)
{
	return vcpu->online;
}

/* Get VCPU usage */
unsigned long long xenstat_vcpu_ns(xenstat_vcpu * vcpu)
{
	return vcpu->ns;
}

/*
 * Network functions
 */

/* Free network information */
static void xenstat_free_networks(xenstat_node * node)
{
	unsigned int i;
	for (i = 0; i < node->num_domains; i++)
		free(node->domains[i].networks);
}

/* Get the network ID */
unsigned int xenstat_network_id(xenstat_network * network)
{
	return network->id;
}

/* Get the number of receive bytes */
unsigned long long xenstat_network_rbytes(xenstat_network * network)
{
	return network->rbytes;
}

/* Get the number of receive packets */
unsigned long long xenstat_network_rpackets(xenstat_network * network)
{
	return network->rpackets;
}

/* Get the number of receive errors */
unsigned long long xenstat_network_rerrs(xenstat_network * network)
{
	return network->rerrs;
}

/* Get the number of receive drops */
unsigned long long xenstat_network_rdrop(xenstat_network * network)
{
	return network->rdrop;
}

/* Get the number of transmit bytes */
unsigned long long xenstat_network_tbytes(xenstat_network * network)
{
	return network->tbytes;
}

/* Get the number of transmit packets */
unsigned long long xenstat_network_tpackets(xenstat_network * network)
{
	return network->tpackets;
}

/* Get the number of transmit errors */
unsigned long long xenstat_network_terrs(xenstat_network * network)
{
	return network->terrs;
}

/* Get the number of transmit dropped packets */
unsigned long long xenstat_network_tdrop(xenstat_network * network)
{
	return network->tdrop;
}

/*
 * Xen version functions
 */

/* Collect Xen version information */
static int xenstat_collect_xen_version(xenstat_node * node)
{
	long vnum = 0;
	xen_extraversion_t version;

	/* Collect Xen version information if not already collected */
	if (node->handle->xen_version[0] == '\0') {
		/* Get the Xen version number and extraversion string */
		vnum = xc_version(node->handle->xc_handle,
			XENVER_version, NULL);

		if (vnum < 0)
			return 0;

		if (xc_version(node->handle->xc_handle, XENVER_extraversion,
			&version) < 0)
			return 0;
		/* Format the version information as a string and store it */
		snprintf(node->handle->xen_version, VERSION_SIZE, "%ld.%ld%s",
			 ((vnum >> 16) & 0xFFFF), vnum & 0xFFFF, version);
	}

	return 1;
}

/* Free Xen version information in node - nothing to do */
static void xenstat_free_xen_version(xenstat_node * node)
{
}

/* Free Xen version information in handle - nothing to do */
static void xenstat_uninit_xen_version(xenstat_handle * handle)
{
}

/*
 * VBD functions
 */

/* Save VBD information */
xenstat_vbd *xenstat_save_vbd(xenstat_domain *domain, xenstat_vbd *vbd)
{
        xenstat_vbd *vbds = domain->vbds;

        domain->num_vbds++;
        domain->vbds = realloc(domain->vbds,
                               domain->num_vbds *
                               sizeof(xenstat_vbd));

        if (domain->vbds == NULL) {
                domain->num_vbds = 0;
                free(vbds);
        }
        else {
                domain->vbds[domain->num_vbds - 1] = *vbd;
        }

        return domain->vbds;
}

/* Free VBD information */
static void xenstat_free_vbds(xenstat_node * node)
{
	unsigned int i;
	for (i = 0; i < node->num_domains; i++)
		free(node->domains[i].vbds);
}

/* Get the back driver type  for Virtual Block Device */
unsigned int xenstat_vbd_type(xenstat_vbd * vbd)
{
	return vbd->back_type;
}

/* Get the major number of VBD device */
unsigned int xenstat_vbd_dev(xenstat_vbd * vbd)
{
	return vbd->dev;
}

/* Get the number of OO(Out of) requests */
unsigned long long xenstat_vbd_oo_reqs(xenstat_vbd * vbd)
{
	return vbd->oo_reqs;
}

/* Get the number of READ requests */
unsigned long long xenstat_vbd_rd_reqs(xenstat_vbd * vbd)
{
	return vbd->rd_reqs;
}

/* Get the number of WRITE requests */
unsigned long long xenstat_vbd_wr_reqs(xenstat_vbd * vbd)
{
	return vbd->wr_reqs;
}

/* Get the number of READ sectors */
unsigned long long xenstat_vbd_rd_sects(xenstat_vbd * vbd)
{
	return vbd->rd_sects;
}

/* Get the number of WRITE sectors */
unsigned long long xenstat_vbd_wr_sects(xenstat_vbd * vbd)
{
	return vbd->wr_sects;
}

/*
 * Tmem functions
 */

xenstat_tmem *xenstat_domain_tmem(xenstat_domain * domain)
{
	return &domain->tmem_stats;
}

/* Get the current number of ephemeral pages */
unsigned long long xenstat_tmem_curr_eph_pages(xenstat_tmem *tmem)
{
	return tmem->curr_eph_pages;
}

/* Get the number of successful ephemeral gets */
unsigned long long xenstat_tmem_succ_eph_gets(xenstat_tmem *tmem)
{
	return tmem->succ_eph_gets;
}

/* Get the number of successful persistent puts */
unsigned long long xenstat_tmem_succ_pers_puts(xenstat_tmem *tmem)
{
	return tmem->succ_pers_puts;
}

/* Get the number of successful persistent gets */
unsigned long long xenstat_tmem_succ_pers_gets(xenstat_tmem *tmem)
{
	return tmem->succ_pers_gets;
}


static char *xenstat_get_domain_name(xenstat_handle *handle, unsigned int domain_id)
{
	char path[80];

	snprintf(path, sizeof(path),"/local/domain/%i/name", domain_id);

	return xs_read(handle->xshandle, XBT_NULL, path, NULL);
}

/* Remove specified entry from list of domains */
static void xenstat_prune_domain(xenstat_node *node, unsigned int entry)
{
	/* nothing to do if array is empty or entry is beyond end */
	if (node->num_domains == 0 || entry >= node->num_domains)
		return;

	/* decrement count of domains */
	node->num_domains--;

	/* shift entries following specified entry up by one */
	if (entry < node->num_domains) {
		xenstat_domain *domain = &node->domains[entry];
		memmove(domain,domain+1,(node->num_domains - entry) * sizeof(xenstat_domain) );
	}

	/* zero out original last entry from node -- not
	   strictly necessary but safer! */
	memset(&node->domains[node->num_domains], 0, sizeof(xenstat_domain)); 
}
