/*
 * Copyright (C) 2016 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef LIBXL_COLO_H
#define LIBXL_COLO_H

#include <linux/netlink.h>

struct libxl__ao;
struct libxl__egc;
struct libxl__colo_save_state;
struct libxl__checkpoint_devices_state;

/* Consistent with the new COLO netlink channel in kernel side */
#define NETLINK_COLO 28

enum {
    LIBXL_COLO_SETUPED,
    LIBXL_COLO_SUSPENDED,
    LIBXL_COLO_RESUMED,
};

enum colo_netlink_op {
    COLO_QUERY_CHECKPOINT = (NLMSG_MIN_TYPE + 1),
    COLO_CHECKPOINT,
    COLO_FAILOVER,
    COLO_PROXY_INIT,
    COLO_PROXY_RESET, /* UNUSED, will be used for continuous FT */
};

typedef struct libxl__colo_qdisk {
    bool setuped;
} libxl__colo_qdisk;

typedef struct libxl__colo_proxy_state libxl__colo_proxy_state;
struct libxl__colo_proxy_state {
    /* set by caller of colo_proxy_setup */
    struct libxl__ao *ao;

    int sock_fd;
    int index;
};

typedef struct libxl__domain_create_state libxl__domain_create_state;
typedef void libxl__domain_create_cb(struct libxl__egc *egc,
                                     libxl__domain_create_state *dcs,
                                     int rc, uint32_t domid);

typedef struct libxl__colo_restore_state libxl__colo_restore_state;
typedef void libxl__colo_callback(struct libxl__egc *egc,
                                  libxl__colo_restore_state *crs, int rc);

struct libxl__colo_restore_state {
    /* must set by caller of libxl__colo_(setup|teardown) */
    struct libxl__ao *ao;
    uint32_t domid;
    int send_back_fd;
    int recv_fd;
    int hvm;
    libxl__colo_callback *callback;

    /* private, colo restore checkpoint state */
    libxl__domain_create_cb *saved_cb;
    void *crcs;

    /* private, used by qdisk block replication */
    bool qdisk_used;
    bool qdisk_setuped;
    const char *host;
    const char *port;

    /* private, used by colo-proxy */
    libxl__colo_proxy_state cps;
};

int init_subkind_qdisk(struct libxl__checkpoint_devices_state *cds);

void cleanup_subkind_qdisk(struct libxl__checkpoint_devices_state *cds);

extern void libxl__colo_restore_setup(struct libxl__egc *egc,
                                      libxl__colo_restore_state *crs);
extern void libxl__colo_restore_teardown(struct libxl__egc *egc, void *dcs_void,
                                         int ret, int retval, int errnoval);
extern void libxl__colo_save_setup(struct libxl__egc *egc,
                                   struct libxl__colo_save_state *css);
extern void libxl__colo_save_teardown(struct libxl__egc *egc,
                                      struct libxl__colo_save_state *css,
                                      int rc);
extern int colo_proxy_setup(libxl__colo_proxy_state *cps);
extern void colo_proxy_teardown(libxl__colo_proxy_state *cps);
extern void colo_proxy_preresume(libxl__colo_proxy_state *cps);
extern void colo_proxy_postresume(libxl__colo_proxy_state *cps);
extern int colo_proxy_checkpoint(libxl__colo_proxy_state *cps,
                                 unsigned int timeout_us);

#endif
