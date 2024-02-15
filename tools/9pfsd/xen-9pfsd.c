/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * xen-9pfsd - Xen 9pfs daemon
 *
 * Copyright (C) 2024 Juergen Gross <jgross@suse.com>
 *
 * Daemon to enable guests to access a directory of the dom0 file system.
 * Access is made via the 9pfs protocol (xen-9pfsd acts as a PV 9pfs backend).
 *
 * Usage: xen-9pfsd
 *
 * xen-9pfsd does NOT support writing any links (neither soft links nor hard
 * links), and it is accepting only canonicalized file paths in order to
 * avoid the possibility to "escape" from the guest specific directory.
 *
 * The backend device string is "xen_9pfs", the tag used for mounting the
 * 9pfs device is "Xen".
 *
 * As an additional security measure the maximum file space used by the guest
 * can be limited by the backend Xenstore node "max-size" specifying the size
 * in MBytes. This size includes the size of the root directory of the guest.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xengnttab.h>
#include <xenstore.h>

#include "xen-9pfsd.h"

/*
 * List of currently known devices.
 * The list itself is modified only in the main thread. When a device is being
 * removed its memory needs to be freed after the I/O thread (if existing)
 * has stopped.
 */
static XEN_TAILQ_HEAD(devhead, device) devs = XEN_TAILQ_HEAD_INITIALIZER(devs);

struct path {
    char path[100];
};

static volatile bool stop_me;
static bool daemon_running;
static struct xs_handle *xs;
static xengnttab_handle *xg;
static unsigned int now;

xenevtchn_handle *xe;

static void handle_stop(int sig)
{
    stop_me = true;
}

static int check_host_path(device *device)
{
    struct stat statbuf;
    char *path, *p;
    int ret = 1;

    if ( !device->host_path )
        return 1;

    /* Path must be absolute. */
    if ( device->host_path[0] != '/' )
        return 1;

    /* No double "/". */
    if ( strstr(device->host_path, "//") )
        return 1;

    /* No trailing "/" (includes refusing to share "/"). */
    if ( device->host_path[strlen(device->host_path) - 1] == '/' )
        return 1;

    path = strdup(device->host_path);
    if ( !path )
    {
        syslog(LOG_CRIT, "memory allocation failure!");
        return 1;
    }

    for ( p = path; p; )
    {
        p = strchr(p + 1, '/');
        if ( p )
            *p = 0;
        if ( !stat(path, &statbuf) )
        {
            if ( !(statbuf.st_mode & S_IFDIR) )
                break;
            if ( !p )
            {
                ret = 0;
                break;
            }
            *p = '/';
            continue;
        }
        if ( mkdir(path, 0777) )
            break;
        if ( p )
            *p = '/';
    }

    free(path);
    return ret;
}

static void construct_frontend_path(device *device, const char *node,
                                    struct path *p)
{
    snprintf(p->path, sizeof(p->path), "/local/domain/%u/device/9pfs/%u/%s",
             device->domid, device->devid, node);
}

static void construct_backend_path(device *device, const char *node,
                                   struct path *p)
{
    snprintf(p->path, sizeof(p->path), "backend/xen_9pfs/%u/%u/%s",
             device->domid, device->devid, node);
}

static char *read_backend_node(device *device, const char *node)
{
    struct path p;
    char *val;
    unsigned int len;

    construct_backend_path(device, node, &p);
    val = xs_read(xs, XBT_NULL, p.path, &len);

    return val;
}

static unsigned int uint_from_string(char *string, unsigned int def)
{
    unsigned long val;
    char *end;

    if ( !string )
        return def;

    val = strtoul(string, &end, 10);
    if ( *end || val > UINT_MAX )
        val = def;
    free(string);

    return val;
}

static unsigned int read_backend_node_uint(device *device, const char *node,
                                           unsigned int def)
{
    return uint_from_string(read_backend_node(device, node), def);
}

static unsigned int read_frontend_node_uint(device *device, const char *node,
                                            unsigned int def)
{
    struct path p;
    unsigned int len;

    construct_frontend_path(device, node, &p);

    return uint_from_string(xs_read(xs, XBT_NULL, p.path, &len), def);
}

static bool write_backend_node(device *device, const char *node,
                               const char *val)
{
    struct path p;
    unsigned int num_perms;
    struct xs_permissions *old_perms;
    struct xs_permissions perms[2] = {
        { .id = 0, .perms = XS_PERM_NONE },
        { .id = device->domid, .perms = XS_PERM_READ }
    };

    construct_backend_path(device, node, &p);
    if ( !xs_write(xs, XBT_NULL, p.path, val, strlen(val)) )
    {
        syslog(LOG_ERR, "error writing bacḱend node \"%s\" for device %u/%u",
               node, device->domid, device->devid);
        return false;
    }

    old_perms = xs_get_permissions(xs, XBT_NULL, p.path, &num_perms);
    if ( !old_perms )
    {
        syslog(LOG_ERR, "error getting permissions for \"%s\"", p.path);
        return false;
    }

    perms[0] = old_perms[0];
    free(old_perms);
    if ( !xs_set_permissions(xs, XBT_NULL, p.path, perms, 2) )
    {
        syslog(LOG_ERR, "error setting permissions for \"%s\"", p.path);
        return false;
    }

    return true;
}

static bool write_backend_node_uint(device *device, const char *node,
                                   unsigned int val)
{
    char str[12];

    snprintf(str, sizeof(str), "%u", val);

    return write_backend_node(device, node, str);
}

static bool write_backend_state(device *device, enum xenbus_state state)
{
    struct path p;
    char val[2];

    snprintf(val, sizeof(val), "%u", state);
    construct_backend_path(device, "state", &p);
    if ( !xs_write(xs, XBT_NULL, p.path, val, 1) )
    {
        syslog(LOG_ERR, "error writing backend state %u for device %u/%u",
               state, device->domid, device->devid);
        return false;
    }

    device->backend_state = state;

    return true;
}

static device *find_device(unsigned int domid, unsigned int devid)
{
    device *device;

    XEN_TAILQ_FOREACH( device, &devs, list )
    {
        if ( domid == device->domid && devid == device->devid )
            return device;
    }

    return NULL;
}

static void free_device(device *device)
{
    char token[20];
    struct path p;

    construct_frontend_path(device, "state", &p);
    snprintf(token, sizeof(token), "%u/%u", device->domid, device->devid);
    xs_unwatch(xs, p.path, token);

    if ( device->root_fd >= 0 )
        close(device->root_fd);

    free(device->host_path);
    free(device);
}

static device *new_device(unsigned int domid, unsigned int devid)
{
    device *device;
    char token[20];
    struct path p;
    char *val;

    device = calloc(1, sizeof(*device));
    if ( !device )
    {
        syslog(LOG_CRIT, "Got no memory for new device %u/%u", domid, devid);
        return NULL;
    }

    device->domid = domid;
    device->devid = devid;
    device->root_fd = -1;

    construct_frontend_path(device, "state", &p);
    snprintf(token, sizeof(token), "%u/%u", domid, devid);
    if ( !xs_watch(xs, p.path, token) )
    {
        syslog(LOG_ERR, "Setting up watch for device %u/%u failed",
               domid, devid);
        free(device);
        return NULL;
    }

    pthread_mutex_init(&device->fid_mutex, NULL);
    XEN_TAILQ_INIT(&device->fids);

    val = read_backend_node(device, "security_model");
    if ( !val || strcmp(val, "none") )
    {
        syslog(LOG_ERR, "Security model \"%s\" for device %u/%u invalid.",
               val, domid, devid);
        free(val);
        goto err;
    }
    free(val);

    device->max_space = read_backend_node_uint(device, "max-space", 0);
    device->max_files = read_backend_node_uint(device, "max-files", 0);
    device->max_open_files =
        read_backend_node_uint(device, "max-open-files", 0)
        ?: MAX_OPEN_FILES_DEFAULT;
    device->auto_delete = read_backend_node_uint(device, "auto-delete", 0);

    device->host_path = read_backend_node(device, "path");
    if ( check_host_path(device) )
    {
        syslog(LOG_ERR, "Host path \"%s\" for device %u/%u invalid.",
               device->host_path, domid, devid);
        goto err;
    }
    device->root_fd = open(device->host_path, O_RDONLY | O_DIRECTORY);
    if ( device->root_fd < 0 )
        goto err;

    if ( !write_backend_node(device, "versions", "1") )
        goto err;
    if ( !write_backend_node_uint(device, "max-rings", MAX_RINGS) )
        goto err;
    if ( !write_backend_node_uint(device, "max-ring-page-order",
                                 MAX_RING_ORDER) )
        goto err;

    if ( !write_backend_state(device, XenbusStateInitWait) )
        goto err;

    XEN_TAILQ_INSERT_TAIL(&devs, device, list);
    syslog(LOG_INFO, "New device %u/%u added", domid, devid);

    return device;

 err:
    free_device(device);
    return NULL;
}

static void disconnect_ring(struct ring *ring)
{
    if ( !ring )
        return;

    if ( ring->thread_active )
    {
        ring->stop_thread = true;
        pthread_cond_signal(&ring->cond);
        pthread_join(ring->thread, NULL);
        ring->stop_thread = false;
    }

    if ( ring->data.in )
    {
        xengnttab_unmap(xg, ring->data.in, 1 << ring->ring_order);
        ring->data.in = NULL;
    }
    if ( ring->intf )
    {
        xengnttab_unmap(xg, ring->intf, 1 );
        ring->intf = NULL;
    }

    if ( ring->evtchn )
    {
        xenevtchn_unbind(xe, ring->evtchn);
        ring->evtchn = 0;
    }

    pthread_mutex_destroy(&ring->mutex);
    pthread_cond_destroy(&ring->cond);
}

static void disconnect_guest(device *device)
{
    unsigned int ring_idx;

    for ( ring_idx = 0; ring_idx < device->num_rings; ring_idx++ )
    {
        disconnect_ring(device->ring[ring_idx]);
        free(device->ring[ring_idx]);
        device->ring[ring_idx] = NULL;
    }

    device->num_rings = 0;

    free_fids(device);
}

static void close_device(device *device, enum xenbus_state state)
{
    disconnect_guest(device);
    write_backend_state(device, state);
}

static void connect_err(device *device, const char *msg)
{
    syslog(LOG_WARNING, "%s", msg);
    close_device(device, XenbusStateClosed);
}

static void connect_device(device *device)
{
    unsigned int val;
    unsigned int ring_idx;
    char node[20];
    struct ring *ring;
    xenevtchn_port_or_error_t evtchn;

    val = read_frontend_node_uint(device, "version", 0);
    if ( val != 1 )
        return connect_err(device, "frontend specifies illegal version");
    device->num_rings = read_frontend_node_uint(device, "num-rings", 0);
    if ( device->num_rings < 1 || device->num_rings > MAX_RINGS )
        return connect_err(device, "frontend specifies illegal ring number");

    for ( ring_idx = 0; ring_idx < device->num_rings; ring_idx++ )
    {
        ring = calloc(1, sizeof(*ring));
        if ( !ring )
            return connect_err(device, "could not allocate ring memory");
        device->ring[ring_idx] = ring;
        ring->device = device;
        pthread_cond_init(&ring->cond, NULL);
        pthread_mutex_init(&ring->mutex, NULL);

        snprintf(node, sizeof(node), "event-channel-%u", ring_idx);
        val = read_frontend_node_uint(device, node, 0);
        if ( val == 0 )
            return connect_err(device, "frontend specifies illegal evtchn");
        evtchn = xenevtchn_bind_interdomain(xe, device->domid, val);
        if ( evtchn < 0 )
            return connect_err(device, "could not bind to event channel");
        ring->evtchn = evtchn;

        snprintf(node, sizeof(node), "ring-ref%u", ring_idx);
        val = read_frontend_node_uint(device, node, 0);
        if ( val == 0 )
            return connect_err(device,
                               "frontend specifies illegal grant for ring");
        ring->intf = xengnttab_map_grant_ref(xg, device->domid, val,
                                             PROT_READ | PROT_WRITE);
        if ( !ring->intf )
            return connect_err(device, "could not map interface page");
        ring->ring_order = ring->intf->ring_order;
        if ( ring->ring_order > MAX_RING_ORDER || ring->ring_order < 1 )
            return connect_err(device, "frontend specifies illegal ring order");
        ring->ring_size = XEN_FLEX_RING_SIZE(ring->ring_order);
        ring->data.in = xengnttab_map_domain_grant_refs(xg,
                                                        1 << ring->ring_order,
                                                        device->domid,
                                                        ring->intf->ref,
                                                        PROT_READ | PROT_WRITE);
        if ( !ring->data.in )
            return connect_err(device, "could not map ring pages");
        ring->data.out = ring->data.in + ring->ring_size;

        if ( pthread_create(&ring->thread, NULL, io_thread, ring) )
            return connect_err(device, "could not start I/O thread");
        ring->thread_active = true;
    }

    write_backend_state(device, XenbusStateConnected);
}

static void remove_device(device *device)
{
    XEN_TAILQ_REMOVE(&devs, device, list);

    disconnect_guest(device);
    pthread_mutex_destroy(&device->fid_mutex);
    free_device(device);
}

static void remove_all_devices(void)
{
    device *device, *tmp;

    XEN_TAILQ_FOREACH_SAFE( device, &devs, list, tmp )
        remove_device(device);
}

static void frontend_changed(device *device)
{
    struct path p;
    char *state, *end;
    unsigned int len;
    unsigned long new_state;

    construct_frontend_path(device, "state", &p);
    state = xs_read(xs, XBT_NULL, p.path, &len);
    if ( !state )
    {
        close_device(device, XenbusStateClosed);
        return;
    }

    new_state = strtoul(state, &end, 10);
    if ( *end || new_state > XenbusStateReconfigured )
    {
        syslog(LOG_WARNING, "unknown state \"%s\" seen for device %u/%u", state,
               device->domid, device->devid);
        new_state = XenbusStateUnknown;
    }
    free(state);

    if ( new_state == device->frontend_state )
        return;

    switch ( new_state )
    {
    case XenbusStateInitialising:
        break;

    case XenbusStateInitialised:
        connect_device(device);
        break;

    case XenbusStateConnected:
        break;

    case XenbusStateClosing:
        close_device(device, XenbusStateClosing);
        break;

    case XenbusStateClosed:
        close_device(device, XenbusStateClosed);
        break;

    default:
        syslog(LOG_WARNING, "not handled frontend state %lu for device %u/%u",
               new_state, device->domid, device->devid);
        break;
    }

    device->frontend_state = new_state;
}

static void check_device(unsigned int domid, unsigned int devid)
{
    device *device;

    device = find_device(domid, devid);
    if ( !device )
    {
        device = new_device(domid, devid);
        if ( !device )
            return;
    }

    device->last_seen = now;
}

static void scan_backend(void)
{
    char **doms;
    unsigned int n_doms, dom;
    char **devices;
    unsigned int n_devs, dev;
    char dom_path[24];
    unsigned long domid, devid;
    char *end;
    device *device, *tmp;

    now++;

    doms = xs_directory(xs, XBT_NULL, "backend/xen_9pfs", &n_doms);
    if ( doms == NULL )
        return;

    for ( dom = 0; dom < n_doms; dom++ )
    {
        errno = 0;
        domid = strtoul(doms[dom], &end, 10);
        if ( errno || *end || domid >= DOMID_FIRST_RESERVED )
            continue;

        snprintf(dom_path, sizeof(dom_path), "backend/xen_9pfs/%lu", domid);
        devices = xs_directory(xs, XBT_NULL, dom_path, &n_devs);

        for ( dev = 0; dev < n_devs; dev++ )
        {
            errno = 0;
            devid = strtoul(devices[dev], &end, 10);
            if ( errno || *end || devid > UINT_MAX )
                continue;

            check_device(domid, devid);
        }

        free(devices);
    }

    free(doms);

    XEN_TAILQ_FOREACH_SAFE( device, &devs, list, tmp )
    {
        if ( device->last_seen != now )
            remove_device(device);
    }
}

static void handle_watch(char *path, char *token)
{
    unsigned int domid, devid;
    device *device;

    if ( !strcmp(token, "main") )
    {
        scan_backend();
        return;
    }

    if ( sscanf(token, "%u/%u", &domid, &devid) != 2 )
    {
        syslog(LOG_WARNING, "unknown watch event %s %s", path, token);
        return;
    }

    device = find_device(domid, devid);
    if ( !device )
    {
        syslog(LOG_WARNING, "watch event for unknown device %u/%u",
               domid, devid);
        return;
    }

    frontend_changed(device);
}

static void close_all(void)
{
    if ( daemon_running )
    {
        xs_rm(xs, XBT_NULL, "libxl/xen-9pfs");
        xs_unwatch(xs, "backend/xen_9pfs", "main");

        remove_all_devices();
    }
    if ( xe )
        xenevtchn_close(xe);
    if ( xg )
        xengnttab_close(xg);
    if ( xs )
        xs_close(xs);
    closelog();
}

static void do_err(const char *msg)
{
    syslog(LOG_ALERT, "%s, errno = %d, %s", msg, errno, strerror(errno));
    close_all();
    exit(1);
}

static void handle_event(void)
{
    xenevtchn_port_or_error_t evtchn;
    device *device;
    struct ring *ring;
    unsigned int ring_idx;

    evtchn = xenevtchn_pending(xe);
    if ( evtchn < 0 )
        do_err("xenevtchn_pending() failed");

    XEN_TAILQ_FOREACH( device, &devs, list )
    {
        for ( ring_idx = 0; ring_idx < device->num_rings; ring_idx++ )
        {
            ring = device->ring[ring_idx];
            if ( ring && ring->evtchn == evtchn )
            {
                pthread_mutex_lock(&ring->mutex);
                pthread_cond_signal(&ring->cond);
                pthread_mutex_unlock(&ring->mutex);
                return;
            }
        }
    }
}

static void xen_connect(void)
{
    xs_transaction_t t;
    char *val;
    unsigned int len;

    xs = xs_open(0);
    if ( xs == NULL )
        do_err("xs_open() failed");

    xg = xengnttab_open(NULL, 0);
    if ( xg == NULL )
        do_err("xengnttab_open() failed");

    xe = xenevtchn_open(NULL, 0);
    if ( xe == NULL )
        do_err("xenevtchn_open() failed");

    while ( true )
    {
        t = xs_transaction_start(xs);
        if ( t == XBT_NULL )
            do_err("xs_transaction_start() failed");

        val = xs_read(xs, t, "libxl/xen-9pfs/state", &len);
        if ( val )
        {
            free(val);
            xs_transaction_end(xs, t, true);
            syslog(LOG_INFO, "daemon already running");
            close_all();
            exit(0);
        }

        if ( !xs_write(xs, t, "libxl/xen-9pfs/state", "running",
                       strlen("running")) )
        {
            xs_transaction_end(xs, t, true);
            do_err("xs_write() failed writing state");
        }

        if ( xs_transaction_end(xs, t, false) )
            break;
        if ( errno != EAGAIN )
            do_err("xs_transaction_end() failed");
    }

    daemon_running = true;
}

int main(int argc, char *argv[])
{
    struct sigaction act = { .sa_handler = handle_stop, };
    int syslog_mask = LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_ERR) |
                      LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ALERT) |
                      LOG_MASK(LOG_EMERG);
    char **watch;
    struct pollfd p[2] = {
        { .events = POLLIN },
        { .events = POLLIN }
    };

    umask(027);
    if ( getenv("XEN_9PFSD_VERBOSE") )
        syslog_mask |= LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_INFO);
    openlog("xen-9pfsd", LOG_CONS, LOG_DAEMON);
    setlogmask(syslog_mask);

    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);

    xen_connect();

    if ( !xs_watch(xs, "backend/xen_9pfs", "main") )
        do_err("xs_watch() in main thread failed");
    p[0].fd = xs_fileno(xs);
    p[1].fd = xenevtchn_fd(xe);

    scan_backend();

    while ( !stop_me )
    {
        while ( (p[0].revents & POLLIN) &&
                (watch = xs_check_watch(xs)) != NULL )
        {
            handle_watch(watch[XS_WATCH_PATH], watch[XS_WATCH_TOKEN]);
            free(watch);
        }

        if ( p[1].revents & POLLIN )
            handle_event();

        poll(p, 2, -1);
    }

    close_all();

    return 0;
}
