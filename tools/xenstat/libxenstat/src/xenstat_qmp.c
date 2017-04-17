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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xenctrl.h>

#include "xenstat_priv.h"
#include "_paths.h"

#ifdef HAVE_YAJL_YAJL_VERSION_H
#  include <yajl/yajl_version.h>
#endif

/* YAJL version check */
#if defined(YAJL_MAJOR) && (YAJL_MAJOR > 1)
#  define HAVE_YAJL_V2 1
#endif

#ifdef HAVE_YAJL_V2

#include <yajl/yajl_tree.h>

static unsigned char *qmp_query(int, char *);

enum query_blockstats {
    QMP_STATS_RETURN  = 0,
    QMP_STATS_DEVICE  = 1,
    QMP_STATS         = 2,
    QMP_RD_BYTES      = 3,
    QMP_WR_BYTES      = 4,
    QMP_RD_OPERATIONS = 5,
    QMP_WR_OPERATIONS = 6,
};

enum query_block {
    QMP_BLOCK_RETURN  = 0,
    QMP_BLOCK_DEVICE  = 1,
    QMP_INSERTED      = 2,
    QMP_FILE          = 3,
};


/* Given the qmp device name, get the image filename associated with it
   QMP Syntax for querying block infomation:
     In: { "execute": "query-block" }
     Out: {"return": [{
            "device": 'str, "locked": 'bool', "removable": bool,
            "inserted": {
              "iops_rd": 'int',
              "image": {
                "virtual-size": 'int', "filename": 'str', "cluster-size": 'int',
                "format": 'str', "actual-size": 'int', "dirty-flag": 'bool'
              },
              "iops_wr": 'int', "ro": 'bool', "backing_file_depth": 'int',
              "drv": 'str', "iops": 'int', "bps_wr": 'int', "encrypted": 'bool',
              "bps": 'int', "bps_rd": 'int',
              "file": 'str', "encryption_key_missing": 'bool'
            },
            "type": 'str'
          }]}
*/
static char *qmp_get_block_image(xenstat_node *node, char *qmp_devname, int qfd)
{
	char *tmp, *file = NULL;
	char *query_block_cmd = "{ \"execute\": \"query-block\" }";
	static const char *const qblock[] = {
		[ QMP_BLOCK_RETURN  ] = "return",
		[ QMP_BLOCK_DEVICE  ] = "device",
		[ QMP_INSERTED      ] = "inserted",
		[ QMP_FILE          ] = "file",
	};
	const char *ptr[] = {0, 0};
	unsigned char *qmp_stats;
	yajl_val info, ret_obj, dev_obj, n;
	int i;

	if ((qmp_stats = qmp_query(qfd, query_block_cmd)) == NULL)
		return NULL;

	/* Use libyajl version 2.0.3 or newer for the tree parser feature with bug fixes */
	info = yajl_tree_parse((char *)qmp_stats, NULL, 0);
	free(qmp_stats);
	if (info == NULL)
		return NULL;

	ptr[0] = qblock[QMP_BLOCK_RETURN]; /* "return" */
	if ((ret_obj = yajl_tree_get(info, ptr, yajl_t_array)) == NULL)
		goto done;

	for (i=0; i<YAJL_GET_ARRAY(ret_obj)->len; i++) {
		n = YAJL_GET_ARRAY(ret_obj)->values[i];

		ptr[0] = qblock[QMP_BLOCK_DEVICE]; /* "device" */
		if ((dev_obj = yajl_tree_get(n, ptr, yajl_t_any)) != NULL) {
			tmp = YAJL_GET_STRING(dev_obj);
			if (!tmp || strcmp(qmp_devname, tmp))
				continue;
		}
		else
			continue;

		ptr[0] = qblock[QMP_INSERTED]; /* "inserted" */
		n = yajl_tree_get(n, ptr, yajl_t_any);
		if (n) {
			ptr[0] = qblock[QMP_FILE]; /* "file" */
			n = yajl_tree_get(n, ptr, yajl_t_any);
			if (n && YAJL_IS_STRING(n)) {
				tmp = YAJL_GET_STRING(n);
				file = malloc(strlen(tmp)+1);
				if (file != NULL)
					strcpy(file, tmp);
				goto done;
			}
		}
	}
done:
	yajl_tree_free(info);
	return file;
}


/* Given a QMP device name, lookup the associated xenstore qdisk device id */
static void lookup_xenstore_devid(xenstat_node * node, unsigned int domid, char *qmp_devname,
	int qfd, unsigned int *dev, unsigned int *sector_size)
{
	char **dev_ids, *tmp, *ptr, *image, path[80];
	unsigned int num_dev_ids;
	int i, devid;

	/* Get all the qdisk dev IDs associated with the this VM */
	snprintf(path, sizeof(path),"/local/domain/0/backend/qdisk/%i", domid);
	dev_ids = xs_directory(node->handle->xshandle, XBT_NULL, path, &num_dev_ids);
	if (dev_ids == NULL) {
		return;
	}

	/* Get the filename of the image associated with this QMP device */
	image = qmp_get_block_image(node, qmp_devname, qfd);
	if (image == NULL) {
		free(dev_ids);
		return;
	}

	/* Look for a matching image in xenstore */
	for (i=0; i<num_dev_ids; i++) {
		devid = atoi(dev_ids[i]);
		/* Get the xenstore name of the image */
		snprintf(path, sizeof(path),"/local/domain/0/backend/qdisk/%i/%i/params", domid, devid);
		if ((ptr = xs_read(node->handle->xshandle, XBT_NULL, path, NULL)) == NULL)
			continue;

		/* Get to actual path in string */
		if ((tmp = strchr(ptr, '/')) == NULL)
			tmp = ptr;
		if (!strcmp(tmp,image)) {
			*dev = devid;
			free(ptr);

			/* Get the xenstore sector size of the image while we're here */
			snprintf(path, sizeof(path),"/local/domain/0/backend/qdisk/%i/%i/sector-size", domid, devid);
			if ((ptr = xs_read(node->handle->xshandle, XBT_NULL, path, NULL)) != NULL) {
				*sector_size = atoi((char *)ptr);
				free(ptr);
			}
			break;
		}
		free(ptr);
	}

	free(image);
	free(dev_ids);
}

/* Parse the stats buffer which contains I/O data for all the disks belonging to domid */
static void qmp_parse_stats(xenstat_node *node, unsigned int domid, unsigned char *stats_buf, int qfd)
{
	char *qmp_devname;
	static const char *const qstats[] = {
		[ QMP_STATS_RETURN  ] = "return",
		[ QMP_STATS_DEVICE  ] = "device",
		[ QMP_STATS         ] = "stats",
		[ QMP_RD_BYTES      ] = "rd_bytes",
		[ QMP_WR_BYTES      ] = "wr_bytes",
		[ QMP_RD_OPERATIONS ] = "rd_operations",
		[ QMP_WR_OPERATIONS ] = "wr_operations",
	};
	const char *ptr[] = {0, 0};
	yajl_val info, ret_obj, stats_obj, n;
	xenstat_vbd vbd;
	xenstat_domain *domain;
	unsigned int sector_size = 512;
	int i, j;

	/* Use libyajl version 2.0.3 or newer for the tree parser feature */
	if ((info = yajl_tree_parse((char *)stats_buf, NULL, 0)) == NULL)
		return;

	ptr[0] = qstats[QMP_STATS_RETURN]; /* "return" */
	if ((ret_obj = yajl_tree_get(info, ptr, yajl_t_array)) == NULL)
		goto done;

	/* Array of devices */
	for (i=0; i<YAJL_GET_ARRAY(ret_obj)->len; i++) {
		memset(&vbd, 0, sizeof(xenstat_vbd));
		qmp_devname = NULL;
		stats_obj = YAJL_GET_ARRAY(ret_obj)->values[i];

		ptr[0] = qstats[QMP_STATS_DEVICE]; /* "device" */
		if ((n = yajl_tree_get(stats_obj, ptr, yajl_t_any)) != NULL)
			qmp_devname = YAJL_GET_STRING(n);

		ptr[0] = qstats[QMP_STATS]; /* "stats" */
		stats_obj = yajl_tree_get(stats_obj, ptr, yajl_t_object);
		if (stats_obj && YAJL_IS_OBJECT(stats_obj)) {
			for (j=3; j<7; j++) {
				ptr[0] = qstats[j];
				n = yajl_tree_get(stats_obj, ptr, yajl_t_number);
				if (n && YAJL_IS_NUMBER(n)) {
					switch(j) {
					case QMP_RD_BYTES: /* "rd_bytes" */
						vbd.rd_sects = YAJL_GET_INTEGER(n) / sector_size;
						break;
					case QMP_WR_BYTES: /* "wr_bytes" */
						vbd.wr_sects = YAJL_GET_INTEGER(n) / sector_size;
						break;
					case QMP_RD_OPERATIONS: /* "rd_operations" */
						vbd.rd_reqs = YAJL_GET_INTEGER(n);
						break;
					case QMP_WR_OPERATIONS: /* "wr_operations" */
						vbd.wr_reqs = YAJL_GET_INTEGER(n);
						break;
					}
				}
			}
			/* With the QMP device name, lookup the xenstore qdisk device ID and set vdb.dev */
			if (qmp_devname)
				lookup_xenstore_devid(node, domid, qmp_devname, qfd, &vbd.dev, &sector_size);
			if ((domain = xenstat_node_domain(node, domid)) == NULL)
				continue;
			if ((xenstat_save_vbd(domain, &vbd)) == NULL)
				goto done;
		}
	}
done:
	yajl_tree_free(info);
}

/* Write a command via the QMP. Returns number of bytes written */
static size_t qmp_write(int qfd, char *cmd, size_t cmd_len)
{
	size_t pos = 0;
	ssize_t res;

	while (cmd_len > pos) {
		res = write(qfd, cmd + pos, cmd_len - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return 0;
		case 0:
			errno = EPIPE;
			return pos;
		default:
			pos += (size_t)res;
		}
	}
	return pos;
}

/* Read the data sent in response to a QMP execute query. Returns 1 for success */
static int qmp_read(int qfd, unsigned char **qstats)
{
	unsigned char buf[1024], *ptr;
	struct pollfd pfd[1];
	int n, qsize = 0;

	*qstats = NULL;
	pfd[0].fd = qfd;
	pfd[0].events = POLLIN;
	while ((n = poll(pfd, 1, 10)) > 0) {
		if (pfd[0].revents & POLLIN) {
			if ((n = read(qfd, buf, sizeof(buf))) < 0) {
				free(*qstats);
				return 0;
			}
			ptr = realloc(*qstats, qsize+n+1);
			if (ptr == NULL) {
				free(*qstats);
				return 0;
			}
			memcpy(&ptr[qsize], buf, n);
			qsize += n;
			ptr[qsize] = 0;
			*qstats = ptr;
		}
	}
	return 1;
}

/* With the given cmd, query QMP for requested data. Returns allocated buffer containing data or NULL */
static unsigned char *qmp_query(int qfd, char *cmd)
{
	unsigned char *qstats = NULL;
	int n;

	n = strlen(cmd);
	if (qmp_write(qfd, cmd, n) != n)
		return NULL;
	if (!qmp_read(qfd, &qstats))
		return NULL;
	return qstats;
}

/* Returns a socket connected to the QMP socket. Returns -1 on failure. */
static int qmp_connect(char *path)
{
	struct sockaddr_un sun;
	int s;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;
	(void)fcntl(s, F_SETFD, 1);

	memset(&sun, 0, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;

	if (strlen(path) >= sizeof(sun.sun_path)) {
		close(s);
		return -1;
	}

	strcpy(sun.sun_path, path);
	if (connect(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
		close(s);
		return -1;
	}

	return s;
}

/* Gather the qdisk statistics by querying QMP
   Resources: http://wiki.qemu.org/QMP and qmp-commands.hx from the qemu code
   QMP Syntax for entering command mode. This command must be issued before
   issuing any other command:
     In: {"execute": "qmp_capabilities"}
     Out: {"return": {}}
   QMP Syntax for querying block statistics:
     In: { "execute": "query-blockstats" }
     Out: {"return": [{
            "device": 'str',
            "parent": {
              "stats": {
                "flush_total_time_ns": 'int', "wr_highest_offset": 'int',
                "wr_total_time_ns": 'int', "wr_bytes": 'int',
                "rd_total_time_ns": 'int', "flush_operations": 'int',
                "wr_operations": 'int', "rd_bytes": 'int', "rd_operations": 'int'
              }
            },
            "stats": {
              "flush_total_time_ns": 'int', "wr_highest_offset": 'int',
              "wr_total_time_ns": 'int', "wr_bytes": 'int',
              "rd_total_time_ns": 'int', "flush_operations": 'int',
              "wr_operations": 'int', "rd_bytes": 'int', "rd_operations": 'int'
            }
          }]}
*/
static void read_attributes_qdisk_dom(xenstat_node *node, domid_t domain)
{
	char *cmd_mode = "{ \"execute\": \"qmp_capabilities\" }";
	char *query_blockstats_cmd = "{ \"execute\": \"query-blockstats\" }";
	unsigned char *qmp_stats, *val;
	char path[80];
	int qfd;

	/* Verify that qdisk disks are used with this VM */
	snprintf(path, sizeof(path),"/local/domain/0/backend/qdisk/%i", domain);
	val = xs_read(node->handle->xshandle, XBT_NULL, path, NULL);
	if (val == NULL)
		return;
	free(val);

	/* Connect to this VMs QMP socket */
	snprintf(path, sizeof(path), XEN_RUN_DIR "/qmp-libxenstat-%i", domain);
	if ((qfd = qmp_connect(path)) < 0)
		return;

	/* First enable QMP capabilities so that we can query for data */
	if ((qmp_stats = qmp_query(qfd, cmd_mode)) != NULL) {
		free(qmp_stats);
		/* Query QMP for this VMs blockstats */
		qmp_stats = qmp_query(qfd, query_blockstats_cmd);
		if (qmp_stats != NULL) {
			qmp_parse_stats(node, domain, qmp_stats, qfd);
			free(qmp_stats);
		}
	}
	close(qfd);
}

void read_attributes_qdisk(xenstat_node * node)
{
	xc_domaininfo_t dominfo[1024];
	int i, num_doms;
	domid_t next_domid = 0;

	for (;;) {
		num_doms = xc_domain_getinfolist(node->handle->xc_handle,
						 next_domid, 1024, dominfo);
		if (num_doms <= 0)
			return;

		for (i = 0; i < num_doms; i++)
			if (dominfo[i].domain > 0)
				read_attributes_qdisk_dom(node, dominfo[i].domain);

		next_domid = dominfo[num_doms - 1].domain + 1;
	}
}

#else /* !HAVE_YAJL_V2 */

/* Statistics gathering for qdisks requires at least yajl v2 */
void read_attributes_qdisk(xenstat_node * node)
{
}

#endif /* !HAVE_YAJL_V2 */
