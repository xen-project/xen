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
#include <regex.h>

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

/* We need to get the name of the bridge interface for use with bonding interfaces */
/* Use excludeName parameter to avoid adding bridges we don't care about, eg. virbr0 */
char *getBridge(char *excludeName)
{
	struct dirent *de;
	DIR *d;

	char tmp[256] = { 0 }, *bridge;

	bridge = (char *)malloc(16 * sizeof(char));

	d = opendir("/sys/class/net");
	while ((de = readdir(d)) != NULL) {
		if ((strlen(de->d_name) > 0) && (de->d_name[0] != '.')
			&& (strstr(de->d_name, excludeName) == NULL)) {
				sprintf(tmp, "/sys/class/net/%s/bridge", de->d_name);

				if (access(tmp, F_OK) == 0)
					bridge = de->d_name;
		}
	}

	closedir(d);

	return bridge;
}

/* parseNetLine provides regular expression based parsing for lines from /proc/net/dev, all the */
/* information are parsed but not all are used in our case, ie. for xenstat */
int parseNetDevLine(char *line, char *iface, unsigned long long *rxBytes, unsigned long long *rxPackets,
		unsigned long long *rxErrs, unsigned long long *rxDrops, unsigned long long *rxFifo,
		unsigned long long *rxFrames, unsigned long long *rxComp, unsigned long long *rxMcast,
		unsigned long long *txBytes, unsigned long long *txPackets, unsigned long long *txErrs,
		unsigned long long *txDrops, unsigned long long *txFifo, unsigned long long *txColls,
		unsigned long long *txCarrier, unsigned long long *txComp)
{
	/* Temporary/helper variables */
	int ret;
	char *tmp;
	int i = 0, x = 0, col = 0;
	regex_t r;
	regmatch_t matches[19];
	int num = 19;

	/* Regular exception to parse all the information from /proc/net/dev line */
	char *regex = "([^:]*):([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)"
			"[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*"
			"([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)";

	/* Initialize all variables called has passed as non-NULL to zeros */
	if (iface != NULL)
		memset(iface, 0, sizeof(*iface));
	if (rxBytes != NULL)
		*rxBytes = 0;
	if (rxPackets != NULL)
		*rxPackets = 0;
	if (rxErrs != NULL)
		*rxErrs = 0;
	if (rxDrops != NULL)
		*rxDrops = 0;
	if (rxFifo != NULL)
		*rxFifo = 0;
	if (rxFrames != NULL)
		*rxFrames = 0;
	if (rxPackets != NULL)
		*rxPackets = 0;
	if (rxComp != NULL)
		*rxComp = 0;
	if (txBytes != NULL)
		*txBytes = 0;
	if (txPackets != NULL)
		*txPackets = 0;
	if (txErrs != NULL)
		*txErrs = 0;
	if (txDrops != NULL)
		*txDrops = 0;
	if (txFifo != NULL)
		*txFifo = 0;
	if (txColls != NULL)
		*txColls = 0;
	if (txCarrier != NULL)
		*txCarrier = 0;
	if (txComp != NULL)
		*txComp = 0;

	if ((ret = regcomp(&r, regex, REG_EXTENDED))) {
		regfree(&r);
		return ret;
	}

	tmp = (char *)malloc( sizeof(char) );
	if (regexec (&r, line, num, matches, REG_EXTENDED) == 0){
		for (i = 1; i < num; i++) {
			/* The expression matches are empty sometimes so we need to check it first */
			if (matches[i].rm_eo - matches[i].rm_so > 0) {
				/* Col variable contains current id of non-empty match */
				col++;
				tmp = (char *)realloc(tmp, (matches[i].rm_eo - 
							matches[i].rm_so + 1) * sizeof(char));
				for (x = matches[i].rm_so; x < matches[i].rm_eo; x++)
					tmp[x - matches[i].rm_so] = line[x];

				/* We populate all the fields from /proc/net/dev line */
				if (i > 1) {
					unsigned long long ullTmp = strtoull(tmp, NULL, 10);

					switch (col) {
						case 2: if (rxBytes != NULL)
								*rxBytes = ullTmp;
							break;
						case 3: if (rxPackets != NULL)
								*rxPackets = ullTmp;
							break;
						case 4: if (rxErrs != NULL)
								*rxErrs = ullTmp;
							break;
						case 5: if (rxDrops != NULL)
								*rxDrops = ullTmp;
							break;
						case 6: if (rxFifo != NULL)
								*rxFifo = ullTmp;
							break;
						case 7: if (rxFrames != NULL)
								*rxFrames = ullTmp;
							break;
						case 8: if (rxComp != NULL)
								*rxComp = ullTmp;
							break;
						case 9: if (rxMcast != NULL)
								*rxMcast = ullTmp;
							break;
						case 10: if (txBytes != NULL)
								*txBytes = ullTmp;
							break;
						case 11: if (txPackets != NULL)
								*txPackets = ullTmp;
							break;
						case 12: if (txErrs != NULL)
								*txErrs = ullTmp;
							break;
						case 13: if (txDrops != NULL)
								*txDrops = ullTmp;
							break;
						case 14: if (txFifo != NULL)
								*txFifo = ullTmp;
							break;
						case 15: if (txColls != NULL)
								*txColls = ullTmp;
							break;
						case 16: if (txCarrier != NULL)
								*txCarrier = ullTmp;
							break;
						case 17: if (txComp != NULL)
								*txComp = ullTmp;
							break;
					}
				}
				else
				/* There were errors when parsing this directly in RE. strpbrk() helps */
				if (iface != NULL)
					strcpy(iface, strpbrk(tmp, "abcdefghijklmnopqrstvuwxyz0123456789"));

				memset(tmp, 0, matches[i].rm_eo - matches[i].rm_so);
			}
		}
	}

	free(tmp);
	regfree(&r);

	return 0;
}

/* Collect information about networks */
int xenstat_collect_networks(xenstat_node * node)
{
	/* Helper variables for parseNetDevLine() function defined above */
	int i;
	char line[512] = { 0 }, iface[16] = { 0 }, devBridge[16] = { 0 }, devNoBridge[16] = { 0 };
	unsigned long long rxBytes, rxPackets, rxErrs, rxDrops, txBytes, txPackets, txErrs, txDrops;

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

	/* We get the bridge devices for use with bonding interface to get bonding interface stats */
	snprintf(devBridge, 16, "%s", getBridge("vir"));
	snprintf(devNoBridge, 16, "p%s", devBridge);

	while (fgets(line, 512, priv->procnetdev)) {
		xenstat_domain *domain;
		xenstat_network net;
		unsigned int domid;

		parseNetDevLine(line, iface, &rxBytes, &rxPackets, &rxErrs, &rxDrops, NULL, NULL, NULL,
				NULL, &txBytes, &txPackets, &txErrs, &txDrops, NULL, NULL, NULL, NULL);

		/* If the device parsed is network bridge and both tx & rx packets are zero, we are most */
		/* likely using bonding so we alter the configuration for dom0 to have bridge stats */
		if ((strstr(iface, devBridge) != NULL) &&
		    (strstr(iface, devNoBridge) == NULL) &&
		    ((domain = xenstat_node_domain(node, 0)) != NULL)) {
			for (i = 0; i < domain->num_networks; i++) {
				if ((domain->networks[i].id != 0) ||
				    (domain->networks[i].tbytes != 0) ||
				    (domain->networks[i].rbytes != 0))
					continue;
				domain->networks[i].tbytes = txBytes;
				domain->networks[i].tpackets = txPackets;
				domain->networks[i].terrs = txErrs;
				domain->networks[i].tdrop = txDrops;
				domain->networks[i].rbytes = rxBytes;
				domain->networks[i].rpackets = rxPackets;
				domain->networks[i].rerrs = rxErrs;
				domain->networks[i].rdrop = rxDrops;
			}
		}
		else /* Otherwise we need to preserve old behaviour */
		if (strstr(iface, "vif") != NULL) {
			sscanf(iface, "vif%u.%u", &domid, &net.id);

			net.tbytes = txBytes;
			net.tpackets = txPackets;
			net.terrs = txErrs;
			net.tdrop = txDrops;
			net.rbytes = rxBytes;
			net.rpackets = rxPackets;
			net.rerrs = rxErrs;
			net.rdrop = rxDrops;

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
