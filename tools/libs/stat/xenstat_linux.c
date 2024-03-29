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

#define _GNU_SOURCE
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <xen-tools/common-macros.h>

#include "xenstat_priv.h"

#define SYSFS_VBD_PATH "/sys/bus/xen-backend/devices"
#define XENSTAT_VBD_TYPE_VBD3 3

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
static void getBridge(const char *excludeName, char *result, size_t resultLen)
{
	struct dirent *de;
	DIR *d;

	char tmp[512] = { 0 };

	d = opendir("/sys/class/net");
	while ((de = readdir(d)) != NULL) {
		if ((strlen(de->d_name) > 0) && (de->d_name[0] != '.')
			&& (strstr(de->d_name, excludeName) == NULL)) {
				sprintf(tmp, "/sys/class/net/%s/bridge", de->d_name);

				if (access(tmp, F_OK) == 0) {
					/*
					 * Do not use strncpy to prevent compiler warning with
					 * gcc >= 10.0
					 * If de->d_name is longer then resultLen we truncate it
					 */
					memset(result, 0, resultLen);
					memcpy(result, de->d_name, MIN(strnlen(de->d_name,
									NAME_MAX),resultLen - 1));
				}
		}
	}

	closedir(d);
}

/* parseNetLine provides regular expression based parsing for lines from /proc/net/dev, all the */
/* information are parsed but not all are used in our case, ie. for xenstat */
static int parseNetDevLine(char *line, char *iface, unsigned long long *rxBytes, unsigned long long *rxPackets,
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
	const char *regex = "([^:]*):([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)[ ]*([^ ]*)"
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
				tmp[x - matches[i].rm_so] = 0;

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
				else if (iface != NULL) {
					char *tmp2 = strpbrk(tmp, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
					if (tmp2 != NULL)
						strcpy(iface, tmp2);
				}
			}
		}
	}

	free(tmp);
	regfree(&r);

	return 0;
}

/* Find out the domid and network number given an interface name.
 * Return 0 if the iface cannot be recognized as a Xen VIF. */
static int get_iface_domid_network(const char *iface, unsigned int *domid_p, unsigned int *netid_p)
{
	char nodename_path[48];
	FILE * nodename_file;
	int ret;

	snprintf(nodename_path, 48, "/sys/class/net/%s/device/nodename", iface);
	nodename_file = fopen(nodename_path, "r");
	if (nodename_file != NULL) {
		ret = fscanf(nodename_file, "backend/vif/%u/%u", domid_p, netid_p);
		fclose(nodename_file);
		if (ret == 2)
			return 1;
	}

	if (sscanf(iface, "vif%u.%u", domid_p, netid_p) == 2)
		return 1;

	return 0;
}

/* Collect information about networks */
int xenstat_collect_networks(xenstat_node * node)
{
	/* Helper variables for parseNetDevLine() function defined above */
	int i;
	char line[512] = { 0 }, iface[16] = { 0 }, devBridge[16] = { 0 }, devNoBridge[17] = { 0 };
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
	getBridge("vir", devBridge, sizeof(devBridge));
	snprintf(devNoBridge, sizeof(devNoBridge), "p%s", devBridge);

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
		if (get_iface_domid_network(iface, &domid, &net.id)) {

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

static int read_attributes_vbd3(const char *vbd3_path, xenstat_vbd *vbd)
{
	FILE *fp;
	struct vbd3_stats vbd3_stats;

	fp = fopen(vbd3_path, "rb");

	if (fp == NULL) {
		return -1;
	}

	if (fread(&vbd3_stats, sizeof(struct vbd3_stats), 1, fp) != 1) {
		fclose(fp);
		return -1;
	}

	if (vbd3_stats.version != 1) {
		fclose(fp);
		return -1;
	}

	vbd->oo_reqs = vbd3_stats.oo_reqs;
	vbd->rd_reqs = vbd3_stats.read_reqs_submitted;
	vbd->rd_sects = vbd3_stats.read_sectors;
	vbd->wr_reqs = vbd3_stats.write_reqs_submitted;
	vbd->wr_sects = vbd3_stats.write_sectors;

	fclose(fp);

	return 0;
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

	/* Get qdisk statistics */
	read_attributes_qdisk(node);

	rewinddir(priv->sysfsvbd);

	for(dp = readdir(priv->sysfsvbd); dp != NULL ;
	    dp = readdir(priv->sysfsvbd)) {
		xenstat_domain *domain;
		xenstat_vbd vbd;
		unsigned int domid;
		int ret;
		char buf[256];

		ret = sscanf(dp->d_name, "%255[^-]-%u-%u", buf, &domid, &vbd.dev);
		if (ret != 3)
			continue;
		if (!(strstr(buf, "vbd")) && !(strstr(buf, "tap")))
			continue;

		if (strcmp(buf,"vbd") == 0)
			vbd.back_type = 1;
		else if (strcmp(buf,"tap") == 0)
			vbd.back_type = 2;
		else if (strcmp(buf,"vbd3") == 0)
			vbd.back_type = XENSTAT_VBD_TYPE_VBD3;
		else
			vbd.back_type = 0;

		domain = xenstat_node_domain(node, domid);
		if (domain == NULL) {
			fprintf(stderr,
				"Found interface %s-%u-%u but domain %u"
				" does not exist.\n",
				buf, domid, vbd.dev, domid);
			continue;
		}

		if (vbd.back_type == 1 || vbd.back_type == 2)
		{

			vbd.error = 0;

			if ((read_attributes_vbd(dp->d_name, "statistics/oo_req", buf, 256)<=0) ||
				((ret = sscanf(buf, "%llu", &vbd.oo_reqs)) != 1) ||
				(read_attributes_vbd(dp->d_name, "statistics/rd_req", buf, 256)<=0) ||
				((ret = sscanf(buf, "%llu", &vbd.rd_reqs)) != 1) ||
				(read_attributes_vbd(dp->d_name, "statistics/wr_req", buf, 256)<=0) ||
				((ret = sscanf(buf, "%llu", &vbd.wr_reqs)) != 1) ||
				(read_attributes_vbd(dp->d_name, "statistics/rd_sect", buf, 256)<=0) ||
				((ret = sscanf(buf, "%llu", &vbd.rd_sects)) != 1) ||
				(read_attributes_vbd(dp->d_name, "statistics/wr_sect", buf, 256)<=0) ||
				((ret = sscanf(buf, "%llu", &vbd.wr_sects)) != 1))
			{
				vbd.error = 1;
			}
		}
		else if (vbd.back_type == XENSTAT_VBD_TYPE_VBD3)
		{
			char *td3_pid;
			char *path;

			vbd.error = 0;

			if (asprintf(&path, "/local/domain/0/backend/vbd3/%u/%u/kthread-pid", domid, vbd.dev) < 0)
				continue;

			td3_pid = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);

			free(path);

			if (td3_pid == NULL)
				continue;

			if (asprintf(&path, "/dev/shm/td3-%s/vbd-%u-%u", td3_pid, domid, vbd.dev) < 0) {
				free(td3_pid);
				continue;
			}

			if (read_attributes_vbd3(path, &vbd) < 0)
				vbd.error = 1;

			free(td3_pid);
			free(path);
		}
		else
		{
			vbd.error = 1;
		}
		if ((xenstat_save_vbd(domain, &vbd)) == NULL) {
			perror("Allocation error");
			return 0;
		}
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
