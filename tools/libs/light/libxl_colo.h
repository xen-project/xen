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

#include "libxl_internal.h"

/* Maximum time(5s) to wait for colo proxy checkpoit */
#define COLO_PROXY_CHECKPOINT_TIMEOUT 5000000

#define ASYNC_CALL(egc, ao, child, param, func, callback) do {          \
    int pid = -1;                                                       \
    STATE_AO_GC(ao);                                                    \
                                                                        \
    pid = libxl__ev_child_fork(gc, child, callback);                    \
    if (pid == -1) {                                                    \
        LOGD(ERROR, ao->domid, "unable to fork");                       \
        goto out;                                                       \
    }                                                                   \
                                                                        \
    if (!pid) {                                                         \
        /* child */                                                     \
        func(param);                                                    \
        /* notreached */                                                \
        abort();                                                        \
    }                                                                   \
                                                                        \
    return;                                                             \
out:                                                                    \
    callback(egc, child, -1, 1);                                        \
} while (0)

enum {
    LIBXL_COLO_SETUPED,
    LIBXL_COLO_SUSPENDED,
    LIBXL_COLO_RESUMED,
};

struct libxl__colo_device_nic {
    int devid;
    const char *vif;
};

struct libxl__colo_qdisk {
    bool setuped;
};

struct libxl__colo_proxy_state {
    /* set by caller of colo_proxy_setup */
    struct libxl__ao *ao;

    int sock_fd;
    int index;
    /*
     * Private, True means use userspace colo proxy
     *          False means use kernel colo proxy.
     */
    bool is_userspace_proxy;
    const char *checkpoint_host;
    const char *checkpoint_port;
};

struct libxl__colo_save_state {
    int send_fd;
    int recv_fd;
    char *colo_proxy_script;

    /* private */
    libxl__stream_read_state srs;
    void (*callback)(libxl__egc *, libxl__colo_save_state *, int);
    bool svm_running;
    bool paused;

    /* private, used by qdisk block replication */
    bool qdisk_used;
    bool qdisk_setuped;

    /* private, used by colo-proxy */
    libxl__colo_proxy_state cps;
    libxl__ev_child child;
};


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
    char *colo_proxy_script;

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

int init_subkind_colo_nic(struct libxl__checkpoint_devices_state *cds);

void cleanup_subkind_colo_nic(struct libxl__checkpoint_devices_state *cds);

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
