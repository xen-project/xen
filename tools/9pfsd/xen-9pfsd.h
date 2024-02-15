/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef XEN_9PFSD_H
#define XEN_9PFSD_H

#include <pthread.h>
#include <stdbool.h>
#include <xenevtchn.h>
#include <xen_list.h>
#include <xen/xen.h>
#include <xen/io/xenbus.h>
#include <xen/io/9pfs.h>

#define MAX_RINGS                4
#define MAX_RING_ORDER           9
#define MAX_OPEN_FILES_DEFAULT   5

typedef struct device device;

struct ring {
    device *device;
    pthread_t thread;
    bool thread_active;
    bool stop_thread;
    pthread_cond_t cond;
    pthread_mutex_t mutex;

    evtchn_port_t evtchn;
    struct xen_9pfs_data_intf *intf;
    unsigned int ring_order;
    RING_IDX ring_size;
    struct xen_9pfs_data data;
};

struct device {
    /* Admin data. */
    XEN_TAILQ_ENTRY(device) list;
    unsigned int last_seen;    /* Set in scan_backend(). */
    unsigned int domid;
    unsigned int devid;

    /* Tool side configuration data. */
    char *host_path;
    unsigned int max_space;
    unsigned int max_files;
    unsigned int max_open_files;
    bool auto_delete;

    /* Connection data. */
    enum xenbus_state backend_state;
    enum xenbus_state frontend_state;
    unsigned int num_rings;
    struct ring *ring[MAX_RINGS];
    int root_fd;
};

extern xenevtchn_handle *xe;

void *io_thread(void *arg);

#endif /* XEN_9PFSD_H */
