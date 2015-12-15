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

struct libxl__ao;
struct libxl__egc;
struct libxl__colo_save_state;

enum {
    LIBXL_COLO_SETUPED,
    LIBXL_COLO_SUSPENDED,
    LIBXL_COLO_RESUMED,
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
};

extern void libxl__colo_restore_setup(struct libxl__egc *egc,
                                      libxl__colo_restore_state *crs);
extern void libxl__colo_restore_teardown(struct libxl__egc *egc, void *dcs_void,
                                         int ret, int retval, int errnoval);
extern void libxl__colo_save_setup(struct libxl__egc *egc,
                                   struct libxl__colo_save_state *css);
extern void libxl__colo_save_teardown(struct libxl__egc *egc,
                                      struct libxl__colo_save_state *css,
                                      int rc);
#endif
