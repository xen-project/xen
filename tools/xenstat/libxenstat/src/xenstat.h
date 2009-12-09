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

/* libxenstat API */

#ifndef XENSTAT_H
#define XENSTAT_H

/* Opaque handles */
typedef struct xenstat_handle xenstat_handle;
typedef struct xenstat_domain xenstat_domain;
typedef struct xenstat_node xenstat_node;
typedef struct xenstat_vcpu xenstat_vcpu;
typedef struct xenstat_network xenstat_network;
typedef struct xenstat_vbd xenstat_vbd;
typedef struct xenstat_tmem xenstat_tmem;

/* Initialize the xenstat library.  Returns a handle to be used with
 * subsequent calls to the xenstat library, or NULL if an error occurs. */
xenstat_handle *xenstat_init(void);

/* Release the handle to libxc, free resources, etc. */
void xenstat_uninit(xenstat_handle * handle);

/* Flags for types of information to collect in xenstat_get_node */
#define XENSTAT_VCPU 0x1
#define XENSTAT_NETWORK 0x2
#define XENSTAT_XEN_VERSION 0x4
#define XENSTAT_VBD 0x8
#define XENSTAT_ALL (XENSTAT_VCPU|XENSTAT_NETWORK|XENSTAT_XEN_VERSION|XENSTAT_VBD)

/* Get all available information about a node */
xenstat_node *xenstat_get_node(xenstat_handle * handle, unsigned int flags);

/* Free the information */
void xenstat_free_node(xenstat_node * node);

/*
 * Node functions - extract information from a xenstat_node
 */

/* Get information about the domain with the given domain ID */
xenstat_domain *xenstat_node_domain(xenstat_node * node,
				    unsigned int domid);

/* Get the domain with the given index; used to loop over all domains. */
xenstat_domain *xenstat_node_domain_by_index(xenstat_node * node,
					     unsigned index);

/* Get xen version of the node */
const char *xenstat_node_xen_version(xenstat_node * node);

/* Get amount of total memory on a node */
unsigned long long xenstat_node_tot_mem(xenstat_node * node);

/* Get amount of free memory on a node */
unsigned long long xenstat_node_free_mem(xenstat_node * node);

/* Get amount of tmem freeable memory (in MiB) on a node */
long xenstat_node_freeable_mb(xenstat_node * node);

/* Find the number of domains existing on a node */
unsigned int xenstat_node_num_domains(xenstat_node * node);

/* Find the number of CPUs existing on a node */
unsigned int xenstat_node_num_cpus(xenstat_node * node);

/* Get information about the CPU speed */
unsigned long long xenstat_node_cpu_hz(xenstat_node * node);

/*
 * Domain functions - extract information from a xenstat_domain
 */

/* Get the domain ID for this domain */
unsigned xenstat_domain_id(xenstat_domain * domain);

/* Set the domain name for the domain */
char *xenstat_domain_name(xenstat_domain * domain);

/* Get information about how much CPU time has been used */
unsigned long long xenstat_domain_cpu_ns(xenstat_domain * domain);

/* Find the number of VCPUs allocated to a domain */
unsigned int xenstat_domain_num_vcpus(xenstat_domain * domain);

/* Get the VCPU handle to obtain VCPU stats */
xenstat_vcpu *xenstat_domain_vcpu(xenstat_domain * domain,
				  unsigned int vcpu);

/* Find the current memory reservation for this domain */
unsigned long long xenstat_domain_cur_mem(xenstat_domain * domain);

/* Find the maximum memory reservation for this domain */
unsigned long long xenstat_domain_max_mem(xenstat_domain * domain);

/* Find the domain's SSID */
unsigned int xenstat_domain_ssid(xenstat_domain * domain);

/* Get domain states */
unsigned int xenstat_domain_dying(xenstat_domain * domain);
unsigned int xenstat_domain_crashed(xenstat_domain * domain);
unsigned int xenstat_domain_shutdown(xenstat_domain * domain);
unsigned int xenstat_domain_paused(xenstat_domain * domain);
unsigned int xenstat_domain_blocked(xenstat_domain * domain);
unsigned int xenstat_domain_running(xenstat_domain * domain);

/* Get the number of networks for a given domain */
unsigned int xenstat_domain_num_networks(xenstat_domain *);

/* Get the network handle to obtain network stats */
xenstat_network *xenstat_domain_network(xenstat_domain * domain,
					unsigned int network);

/* Get the number of VBDs for a given domain */
unsigned int xenstat_domain_num_vbds(xenstat_domain *);

/* Get the VBD handle to obtain VBD stats */
xenstat_vbd *xenstat_domain_vbd(xenstat_domain * domain,
				    unsigned int vbd);

/* Get the tmem information for a given domain */
xenstat_tmem *xenstat_domain_tmem(xenstat_domain * domain);

/*
 * VCPU functions - extract information from a xenstat_vcpu
 */

/* Get VCPU usage */
unsigned int xenstat_vcpu_online(xenstat_vcpu * vcpu);
unsigned long long xenstat_vcpu_ns(xenstat_vcpu * vcpu);


/*
 * Network functions - extract information from a xenstat_network
 */

/* Get the ID for this network */
unsigned int xenstat_network_id(xenstat_network * network);

/* Get the number of receive bytes for this network */
unsigned long long xenstat_network_rbytes(xenstat_network * network);

/* Get the number of receive packets for this network */
unsigned long long xenstat_network_rpackets(xenstat_network * network);

/* Get the number of receive errors for this network */
unsigned long long xenstat_network_rerrs(xenstat_network * network);

/* Get the number of receive drops for this network */
unsigned long long xenstat_network_rdrop(xenstat_network * network);

/* Get the number of transmit bytes for this network */
unsigned long long xenstat_network_tbytes(xenstat_network * network);

/* Get the number of transmit packets for this network */
unsigned long long xenstat_network_tpackets(xenstat_network * network);

/* Get the number of transmit errors for this network */
unsigned long long xenstat_network_terrs(xenstat_network * network);

/* Get the number of transmit drops for this network */
unsigned long long xenstat_network_tdrop(xenstat_network * network);

/*
 * VBD functions - extract information from a xen_vbd
 */

/* Get the back driver type  for Virtual Block Device */
unsigned int xenstat_vbd_type(xenstat_vbd * vbd);

/* Get the device number for Virtual Block Device */
unsigned int xenstat_vbd_dev(xenstat_vbd * vbd);

/* Get the number of OO/RD/WR requests for vbd */
unsigned long long xenstat_vbd_oo_reqs(xenstat_vbd * vbd);
unsigned long long xenstat_vbd_rd_reqs(xenstat_vbd * vbd);
unsigned long long xenstat_vbd_wr_reqs(xenstat_vbd * vbd);
unsigned long long xenstat_vbd_rd_sects(xenstat_vbd * vbd);
unsigned long long xenstat_vbd_wr_sects(xenstat_vbd * vbd);

/*
 * Tmem functions - extract tmem information
 */
unsigned long long xenstat_tmem_curr_eph_pages(xenstat_tmem *tmem);
unsigned long long xenstat_tmem_succ_eph_gets(xenstat_tmem *tmem);
unsigned long long xenstat_tmem_succ_pers_puts(xenstat_tmem *tmem);
unsigned long long xenstat_tmem_succ_pers_gets(xenstat_tmem *tmem);

#endif /* XENSTAT_H */
