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

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <xen-interface.h>
#include <xs.h>
#include "xenstat.h"

/*
 * Types
 */
#define SHORT_ASC_LEN 5                 /* length of 65535 */
#define VERSION_SIZE (2 * SHORT_ASC_LEN + 1 + sizeof(xen_extraversion_t) + 1)

struct xenstat_handle {
	xi_handle *xihandle;
	struct xs_handle *xshandle; /* xenstore handle */
	int page_size;
	FILE *procnetdev;
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

/*
 * Data-collection types
 */
/* Called to collect the information for the node and all the domains on
 * it. When called, the domain information has already been collected. */
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
static int  xenstat_collect_networks(xenstat_node * node);
static int  xenstat_collect_xen_version(xenstat_node * node);
static void xenstat_free_vcpus(xenstat_node * node);
static void xenstat_free_networks(xenstat_node * node);
static void xenstat_free_xen_version(xenstat_node * node);
static void xenstat_uninit_vcpus(xenstat_handle * handle);
static void xenstat_uninit_networks(xenstat_handle * handle);
static void xenstat_uninit_xen_version(xenstat_handle * handle);
static char *xenstat_get_domain_name(xenstat_handle * handle, unsigned int domain_id);

static xenstat_collector collectors[] = {
	{ XENSTAT_VCPU, xenstat_collect_vcpus,
	  xenstat_free_vcpus, xenstat_uninit_vcpus },
	{ XENSTAT_NETWORK, xenstat_collect_networks,
	  xenstat_free_networks, xenstat_uninit_networks },
	{ XENSTAT_XEN_VERSION, xenstat_collect_xen_version,
	  xenstat_free_xen_version, xenstat_uninit_xen_version }
};

#define NUM_COLLECTORS (sizeof(collectors)/sizeof(xenstat_collector))

/*
 * libxenstat API
 */
xenstat_handle *xenstat_init()
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

	handle->xihandle = xi_init();
	if (handle->xihandle == NULL) {
		perror("xi_init");
		free(handle);
		return NULL;
	}

	handle->xshandle = xs_daemon_open_readonly(); /* open handle to xenstore*/
	if (handle->xshandle == NULL) {
		perror("unable to open xenstore\n");
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
		xi_uninit(handle->xihandle);
		xs_daemon_close(handle->xshandle);
		free(handle);
	}
}

xenstat_node *xenstat_get_node(xenstat_handle * handle, unsigned int flags)
{
#define DOMAIN_CHUNK_SIZE 256
	xenstat_node *node;
	dom0_physinfo_t physinfo;
	dom0_getdomaininfo_t domaininfo[DOMAIN_CHUNK_SIZE];
	unsigned int num_domains, new_domains;
	unsigned int i;

	/* Create the node */
	node = (xenstat_node *) calloc(1, sizeof(xenstat_node));
	if (node == NULL)
		return NULL;

	/* Store the handle in the node for later access */
	node->handle = handle;

	/* Get information about the physical system */
	if (xi_get_physinfo(handle->xihandle, &physinfo) < 0) {
		free(node);
		return NULL;
	}

	node->cpu_hz = ((unsigned long long)physinfo.cpu_khz) * 1000ULL;
	node->num_cpus =
	    (physinfo.threads_per_core * physinfo.cores_per_socket *
	     physinfo.sockets_per_node * physinfo.nr_nodes);
	node->tot_mem = ((unsigned long long)physinfo.total_pages)
	    * handle->page_size;
	node->free_mem = ((unsigned long long)physinfo.free_pages)
	    * handle->page_size;

	/* malloc(0) is not portable, so allocate a single domain.  This will
	 * be resized below. */
	node->domains = malloc(sizeof(xenstat_domain));
	if (node->domains == NULL) {
		free(node);
		return NULL;
	}

	num_domains = 0;
	do {
		xenstat_domain *domain;

		new_domains = xi_get_domaininfolist(handle->xihandle,
		                                    domaininfo, num_domains,
		                                    DOMAIN_CHUNK_SIZE);

		node->domains = realloc(node->domains,
					(num_domains + new_domains)
					* sizeof(xenstat_domain));
		if (node->domains == NULL) {
			free(node);
			return NULL;
		}

		domain = node->domains + num_domains;

		for (i = 0; i < new_domains; i++) {
			/* Fill in domain using domaininfo[i] */
			domain->id = domaininfo[i].domain;
			domain->name = xenstat_get_domain_name(handle, domaininfo[i].domain);
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

			domain++;
		}
		num_domains += new_domains;
	} while (new_domains == DOMAIN_CHUNK_SIZE);
	node->num_domains = num_domains;

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
	if (0 <= index && index < node->num_domains)
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
	if (0 <= vcpu && vcpu < domain->num_vcpus)
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
	return (domain->state & DOMFLAGS_DYING) == DOMFLAGS_DYING;
}

unsigned int xenstat_domain_crashed(xenstat_domain * domain)
{
	return ((domain->state & DOMFLAGS_SHUTDOWN) == DOMFLAGS_SHUTDOWN)
	    && (((domain->state >> DOMFLAGS_SHUTDOWNSHIFT)
		 & DOMFLAGS_SHUTDOWNMASK) == SHUTDOWN_crash);
}

unsigned int xenstat_domain_shutdown(xenstat_domain * domain)
{
	return ((domain->state & DOMFLAGS_SHUTDOWN) == DOMFLAGS_SHUTDOWN)
	    && (((domain->state >> DOMFLAGS_SHUTDOWNSHIFT)
		 & DOMFLAGS_SHUTDOWNMASK) != SHUTDOWN_crash);
}

unsigned int xenstat_domain_paused(xenstat_domain * domain)
{
	return (domain->state & DOMFLAGS_PAUSED) == DOMFLAGS_PAUSED;
}

unsigned int xenstat_domain_blocked(xenstat_domain * domain)
{
	return (domain->state & DOMFLAGS_BLOCKED) == DOMFLAGS_BLOCKED;
}

unsigned int xenstat_domain_running(xenstat_domain * domain)
{
	return (domain->state & DOMFLAGS_RUNNING) == DOMFLAGS_RUNNING;
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
	if (domain->networks && 0 <= network && network < domain->num_networks)
		return &(domain->networks[network]);
	return NULL;
}

/*
 * VCPU functions
 */
/* Collect information about VCPUs */
static int xenstat_collect_vcpus(xenstat_node * node)
{
	unsigned int i, vcpu;

	/* Fill in VCPU information */
	for (i = 0; i < node->num_domains; i++) {
		node->domains[i].vcpus = malloc(node->domains[i].num_vcpus
						* sizeof(xenstat_vcpu));
		if (node->domains[i].vcpus == NULL)
			return 0;
	
		for (vcpu = 0; vcpu < node->domains[i].num_vcpus; vcpu++) {
			/* FIXME: need to be using a more efficient mechanism*/
			dom0_getvcpuinfo_t info;

			if (xi_get_domain_vcpu_info(node->handle->xihandle,
			    node->domains[i].id, vcpu, &info) != 0)
				return 0;

			node->domains[i].vcpus[vcpu].online = info.online;
			node->domains[i].vcpus[vcpu].ns = info.cpu_time;
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

/* Expected format of /proc/net/dev */
static const char PROCNETDEV_HEADER[] =
    "Inter-|   Receive                                                |"
    "  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|"
    "bytes    packets errs drop fifo colls carrier compressed\n";

/* Collect information about networks */
static int xenstat_collect_networks(xenstat_node * node)
{
	/* Open and validate /proc/net/dev if we haven't already */
	if (node->handle->procnetdev == NULL) {
		char header[sizeof(PROCNETDEV_HEADER)];
		node->handle->procnetdev = fopen("/proc/net/dev", "r");
		if (node->handle->procnetdev == NULL) {
			perror("Error opening /proc/net/dev");
			return 0;
		}

		/* Validate the format of /proc/net/dev */
		if (fread(header, sizeof(PROCNETDEV_HEADER) - 1, 1,
			  node->handle->procnetdev) != 1) {
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
	fseek(node->handle->procnetdev, sizeof(PROCNETDEV_HEADER) - 1,
	      SEEK_SET);
	while (1) {
		xenstat_domain *domain;
		xenstat_network net;
		unsigned int domid;
		int ret = fscanf(node->handle->procnetdev,
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
				c = fgetc(node->handle->procnetdev);
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
			domain->num_networks++;
			domain->networks =
			    realloc(domain->networks,
				    domain->num_networks *
				    sizeof(xenstat_network));
		}
		if (domain->networks == NULL)
			return 0;
		domain->networks[domain->num_networks - 1] = net;
	}

	return 1;
}

/* Free network information */
static void xenstat_free_networks(xenstat_node * node)
{
	unsigned int i;
	for (i = 0; i < node->num_domains; i++)
		free(node->domains[i].networks);
}

/* Free network information in handle */
static void xenstat_uninit_networks(xenstat_handle * handle)
{
	if(handle->procnetdev)
		fclose(handle->procnetdev);
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
		if (xi_get_xen_version(node->handle->xihandle,
				       &vnum, &version) < 0)
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

static char *xenstat_get_domain_name(xenstat_handle *handle, unsigned int domain_id)
{
	char path[80];
	char *name;
	struct xs_transaction_handle *xstranshandle;

	snprintf(path, sizeof(path),"/local/domain/%i/name", domain_id);
	
	xstranshandle = xs_transaction_start(handle->xshandle);
	if (xstranshandle == NULL) {
		perror("Unable to get transcation handle from xenstore\n");
		exit(1); /* Change this */
	}

	name = (char *) xs_read(handle->xshandle, xstranshandle, path, NULL);
	
	xs_transaction_end(handle->xshandle, xstranshandle, false);

	return name;
}	
