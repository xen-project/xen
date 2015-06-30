/*
 * Copyright (C) 2014
 * Author Shriram Rajagopalan <rshriram@cs.ubc.ca>
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

#include <netlink/cache.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/plug.h>

typedef struct libxl__remus_device_nic {
    int devid;

    const char *vif;
    const char *ifb;
    struct rtnl_qdisc *qdisc;
} libxl__remus_device_nic;

int libxl__netbuffer_enabled(libxl__gc *gc)
{
    return 1;
}

int init_subkind_nic(libxl__remus_devices_state *rds)
{
    int rc, ret;
    libxl__domain_suspend_state *dss = CONTAINER_OF(rds, *dss, rds);

    STATE_AO_GC(rds->ao);

    rds->nlsock = nl_socket_alloc();
    if (!rds->nlsock) {
        LOG(ERROR, "cannot allocate nl socket");
        rc = ERROR_FAIL;
        goto out;
    }

    ret = nl_connect(rds->nlsock, NETLINK_ROUTE);
    if (ret) {
        LOG(ERROR, "failed to open netlink socket: %s",
            nl_geterror(ret));
        rc = ERROR_FAIL;
        goto out;
    }

    /* get list of all qdiscs installed on network devs. */
    ret = rtnl_qdisc_alloc_cache(rds->nlsock, &rds->qdisc_cache);
    if (ret) {
        LOG(ERROR, "failed to allocate qdisc cache: %s",
            nl_geterror(ret));
        rc = ERROR_FAIL;
        goto out;
    }

    if (dss->remus->netbufscript) {
        rds->netbufscript = libxl__strdup(gc, dss->remus->netbufscript);
    } else {
        rds->netbufscript = GCSPRINTF("%s/remus-netbuf-setup",
                                      libxl__xen_script_dir_path());
    }

    rc = 0;

out:
    return rc;
}

void cleanup_subkind_nic(libxl__remus_devices_state *rds)
{
    STATE_AO_GC(rds->ao);

    /* free qdisc cache */
    if (rds->qdisc_cache) {
        nl_cache_clear(rds->qdisc_cache);
        nl_cache_free(rds->qdisc_cache);
        rds->qdisc_cache = NULL;
    }

    /* close & free nlsock */
    if (rds->nlsock) {
        nl_close(rds->nlsock);
        nl_socket_free(rds->nlsock);
        rds->nlsock = NULL;
    }
}

/*----- setup() and teardown() -----*/

/* helper functions */

/*
 * If the device has a vifname, then use that instead of
 * the vifX.Y format.
 * it must ONLY be used for remus because if driver domains
 * were in use it would constitute a security vulnerability.
 */
static const char *get_vifname(libxl__remus_device *dev,
                               const libxl_device_nic *nic)
{
    const char *vifname = NULL;
    const char *path;
    int rc;

    STATE_AO_GC(dev->rds->ao);

    /* Convenience aliases */
    const uint32_t domid = dev->rds->domid;

    path = GCSPRINTF("%s/backend/vif/%d/%d/vifname",
                     libxl__xs_get_dompath(gc, 0), domid, nic->devid);
    rc = libxl__xs_read_checked(gc, XBT_NULL, path, &vifname);
    if (!rc && !vifname) {
        vifname = libxl__device_nic_devname(gc, domid,
                                            nic->devid,
                                            nic->nictype);
    }

    return vifname;
}

static void free_qdisc(libxl__remus_device_nic *remus_nic)
{
    if (remus_nic->qdisc == NULL)
        return;

    nl_object_put((struct nl_object *)(remus_nic->qdisc));
    remus_nic->qdisc = NULL;
}

static int init_qdisc(libxl__remus_devices_state *rds,
                      libxl__remus_device_nic *remus_nic)
{
    int rc, ret, ifindex;
    struct rtnl_link *ifb = NULL;
    struct rtnl_qdisc *qdisc = NULL;

    STATE_AO_GC(rds->ao);

    /* Now that we have brought up REMUS_IFB device with plug qdisc for
     * this vif, so we need to refill the qdisc cache.
     */
    ret = nl_cache_refill(rds->nlsock, rds->qdisc_cache);
    if (ret) {
        LOG(ERROR, "cannot refill qdisc cache: %s", nl_geterror(ret));
        rc = ERROR_FAIL;
        goto out;
    }

    /* get a handle to the REMUS_IFB interface */
    ret = rtnl_link_get_kernel(rds->nlsock, 0, remus_nic->ifb, &ifb);
    if (ret) {
        LOG(ERROR, "cannot obtain handle for %s: %s", remus_nic->ifb,
            nl_geterror(ret));
        rc = ERROR_FAIL;
        goto out;
    }

    ifindex = rtnl_link_get_ifindex(ifb);
    if (!ifindex) {
        LOG(ERROR, "interface %s has no index", remus_nic->ifb);
        rc = ERROR_FAIL;
        goto out;
    }

    /* Get a reference to the root qdisc installed on the REMUS_IFB, by
     * querying the qdisc list we obtained earlier. The netbufscript
     * sets up the plug qdisc as the root qdisc, so we don't have to
     * search the entire qdisc tree on the REMUS_IFB dev.

     * There is no need to explicitly free this qdisc as its just a
     * reference from the qdisc cache we allocated earlier.
     */
    qdisc = rtnl_qdisc_get_by_parent(rds->qdisc_cache, ifindex, TC_H_ROOT);
    if (qdisc) {
        const char *tc_kind = rtnl_tc_get_kind(TC_CAST(qdisc));
        /* Sanity check: Ensure that the root qdisc is a plug qdisc. */
        if (!tc_kind || strcmp(tc_kind, "plug")) {
            LOG(ERROR, "plug qdisc is not installed on %s", remus_nic->ifb);
            rc = ERROR_FAIL;
            goto out;
        }
        remus_nic->qdisc = qdisc;
    } else {
        LOG(ERROR, "Cannot get qdisc handle from ifb %s", remus_nic->ifb);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    if (ifb)
        rtnl_link_put(ifb);

    if (rc && qdisc)
        nl_object_put((struct nl_object *)qdisc);

    return rc;
}

/* callbacks */

static void netbuf_setup_script_cb(libxl__egc *egc,
                                   libxl__async_exec_state *aes,
                                   int rc, int status);
static void netbuf_teardown_script_cb(libxl__egc *egc,
                                      libxl__async_exec_state *aes,
                                      int rc, int status);

/*
 * the script needs the following env & args
 * $vifname
 * $XENBUS_PATH (/libxl/<domid>/remus/netbuf/<devid>/)
 * $REMUS_IFB (for teardown)
 * setup/teardown as command line arg.
 */
static void setup_async_exec(libxl__remus_device *dev, char *op)
{
    int arraysize, nr = 0;
    char **env = NULL, **args = NULL;
    libxl__remus_device_nic *remus_nic = dev->concrete_data;
    libxl__remus_devices_state *rds = dev->rds;
    libxl__async_exec_state *aes = &dev->aodev.aes;

    STATE_AO_GC(rds->ao);

    /* Convenience aliases */
    char *const script = libxl__strdup(gc, rds->netbufscript);
    const uint32_t domid = rds->domid;
    const int dev_id = remus_nic->devid;
    const char *const vif = remus_nic->vif;
    const char *const ifb = remus_nic->ifb;

    arraysize = 7;
    GCNEW_ARRAY(env, arraysize);
    env[nr++] = "vifname";
    env[nr++] = libxl__strdup(gc, vif);
    env[nr++] = "XENBUS_PATH";
    env[nr++] = GCSPRINTF("%s/remus/netbuf/%d",
                          libxl__xs_libxl_path(gc, domid), dev_id);
    if (!strcmp(op, "teardown") && ifb) {
        env[nr++] = "REMUS_IFB";
        env[nr++] = libxl__strdup(gc, ifb);
    }
    env[nr++] = NULL;
    assert(nr <= arraysize);

    arraysize = 3; nr = 0;
    GCNEW_ARRAY(args, arraysize);
    args[nr++] = script;
    args[nr++] = op;
    args[nr++] = NULL;
    assert(nr == arraysize);

    aes->ao = dev->rds->ao;
    aes->what = GCSPRINTF("%s %s", args[0], args[1]);
    aes->env = env;
    aes->args = args;
    aes->timeout_ms = LIBXL_HOTPLUG_TIMEOUT * 1000;
    aes->stdfds[0] = -1;
    aes->stdfds[1] = -1;
    aes->stdfds[2] = -1;

    if (!strcmp(op, "teardown"))
        aes->callback = netbuf_teardown_script_cb;
    else
        aes->callback = netbuf_setup_script_cb;
}

/* setup() and teardown() */

static void nic_setup(libxl__egc *egc, libxl__remus_device *dev)
{
    int rc;
    libxl__remus_device_nic *remus_nic;
    const libxl_device_nic *nic = dev->backend_dev;

    STATE_AO_GC(dev->rds->ao);

    /*
     * thers's no subkind of nic devices, so nic ops is always matched
     * with nic devices
     */
    dev->matched = true;

    GCNEW(remus_nic);
    dev->concrete_data = remus_nic;
    remus_nic->devid = nic->devid;
    remus_nic->vif = get_vifname(dev, nic);
    if (!remus_nic->vif) {
        rc = ERROR_FAIL;
        goto out;
    }

    setup_async_exec(dev, "setup");
    rc = libxl__async_exec_start(&dev->aodev.aes);
    if (rc)
        goto out;

    return;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

/*
 * In return, the script writes the name of REMUS_IFB device (during setup)
 * to be used for output buffering into XENBUS_PATH/ifb
 */
static void netbuf_setup_script_cb(libxl__egc *egc,
                                   libxl__async_exec_state *aes,
                                   int rc, int status)
{
    libxl__ao_device *aodev = CONTAINER_OF(aes, *aodev, aes);
    libxl__remus_device *dev = CONTAINER_OF(aodev, *dev, aodev);
    libxl__remus_device_nic *remus_nic = dev->concrete_data;
    libxl__remus_devices_state *rds = dev->rds;
    const char *out_path_base, *hotplug_error = NULL;

    STATE_AO_GC(rds->ao);

    /* Convenience aliases */
    const uint32_t domid = rds->domid;
    const int devid = remus_nic->devid;
    const char *const vif = remus_nic->vif;
    const char **const ifb = &remus_nic->ifb;

    if (status && !rc)
        rc = ERROR_FAIL;
    if (rc)
        goto out;

    /*
     * we need to get ifb first because it's needed for teardown
     */
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/remus/netbuf/%d/ifb",
                                          libxl__xs_libxl_path(gc, domid),
                                          devid),
                                ifb);
    if (rc)
        goto out;

    if (!(*ifb)) {
        LOG(ERROR, "Cannot get ifb dev name for domain %u dev %s",
            domid, vif);
        rc = ERROR_FAIL;
        goto out;
    }

    out_path_base = GCSPRINTF("%s/remus/netbuf/%d",
                              libxl__xs_libxl_path(gc, domid), devid);

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/hotplug-error", out_path_base),
                                &hotplug_error);
    if (rc)
        goto out;

    if (hotplug_error) {
        LOG(ERROR, "netbuf script %s setup failed for vif %s: %s",
            rds->netbufscript, vif, hotplug_error);
        rc = ERROR_FAIL;
        goto out;
    }

    if (status) {
        rc = ERROR_FAIL;
        goto out;
    }

    LOG(DEBUG, "%s will buffer packets from vif %s", *ifb, vif);
    rc = init_qdisc(rds, remus_nic);

out:
    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

static void nic_teardown(libxl__egc *egc, libxl__remus_device *dev)
{
    int rc;
    STATE_AO_GC(dev->rds->ao);

    setup_async_exec(dev, "teardown");

    rc = libxl__async_exec_start(&dev->aodev.aes);
    if (rc)
        goto out;

    return;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

static void netbuf_teardown_script_cb(libxl__egc *egc,
                                      libxl__async_exec_state *aes,
                                      int rc, int status)
{
    libxl__ao_device *aodev = CONTAINER_OF(aes, *aodev, aes);
    libxl__remus_device *dev = CONTAINER_OF(aodev, *dev, aodev);
    libxl__remus_device_nic *remus_nic = dev->concrete_data;

    if (status && !rc)
        rc = ERROR_FAIL;

    free_qdisc(remus_nic);

    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

/*----- checkpointing APIs -----*/

/* The value of buffer_op, not the value passed to kernel */
enum {
    tc_buffer_start,
    tc_buffer_release
};

/* API implementations */

static int remus_netbuf_op(libxl__remus_device_nic *remus_nic,
                           libxl__remus_devices_state *rds,
                           int buffer_op)
{
    int rc, ret;

    STATE_AO_GC(rds->ao);

    if (buffer_op == tc_buffer_start)
        ret = rtnl_qdisc_plug_buffer(remus_nic->qdisc);
    else
        ret = rtnl_qdisc_plug_release_one(remus_nic->qdisc);

    if (ret) {
        rc = ERROR_FAIL;
        goto out;
    }

    ret = rtnl_qdisc_add(rds->nlsock, remus_nic->qdisc, NLM_F_REQUEST);
    if (ret) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    if (rc)
        LOG(ERROR, "Remus: cannot do netbuf op %s on %s:%s",
            ((buffer_op == tc_buffer_start) ?
            "start_new_epoch" : "release_prev_epoch"),
            remus_nic->ifb, nl_geterror(ret));
    return rc;
}

static void nic_postsuspend(libxl__egc *egc, libxl__remus_device *dev)
{
    int rc;
    libxl__remus_device_nic *remus_nic = dev->concrete_data;

    STATE_AO_GC(dev->rds->ao);

    rc = remus_netbuf_op(remus_nic, dev->rds, tc_buffer_start);

    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

static void nic_commit(libxl__egc *egc, libxl__remus_device *dev)
{
    int rc;
    libxl__remus_device_nic *remus_nic = dev->concrete_data;

    STATE_AO_GC(dev->rds->ao);

    rc = remus_netbuf_op(remus_nic, dev->rds, tc_buffer_release);

    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

const libxl__remus_device_instance_ops remus_device_nic = {
    .kind = LIBXL__DEVICE_KIND_VIF,
    .setup = nic_setup,
    .teardown = nic_teardown,
    .postsuspend = nic_postsuspend,
    .commit = nic_commit,
};

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
