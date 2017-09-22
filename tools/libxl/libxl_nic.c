/*
 * Copyright (C) 2016      SUSE Linux GmbH
 * Author Juergen Gross <jgross@suse.com>
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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

int libxl_mac_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                            const char *mac, libxl_device_nic *nic)
{
    GC_INIT(ctx);
    libxl_device_nic *nics;
    int nb, rc, i;
    libxl_mac mac_n;

    rc = libxl__parse_mac(mac, mac_n);
    if (rc)
        return rc;

    nics = libxl__device_list(gc, &libxl__nic_devtype, domid, &nb);
    if (!nics)
        return ERROR_FAIL;

    memset(nic, 0, sizeof (libxl_device_nic));

    rc = ERROR_INVAL;
    for (i = 0; i < nb; ++i) {
        if (!libxl__compare_macs(&mac_n, &nics[i].mac)) {
            *nic = nics[i];
            rc = 0;
            i++; /* Do not dispose this NIC on exit path */
            break;
        }
        libxl_device_nic_dispose(&nics[i]);
    }

    for (; i<nb; i++)
        libxl_device_nic_dispose(&nics[i]);

    free(nics);
    return rc;
}

static int libxl__device_nic_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_nic *nic, bool hotplug)
{
    int rc;

    if (!nic->mtu)
        nic->mtu = 1492;
    if (!nic->model) {
        nic->model = strdup("rtl8139");
        if (!nic->model) return ERROR_NOMEM;
    }
    if (libxl__mac_is_default(&nic->mac)) {
        const uint8_t *r;
        libxl_uuid uuid;

        libxl_uuid_generate(&uuid);
        r = libxl_uuid_bytearray(&uuid);

        nic->mac[0] = 0x00;
        nic->mac[1] = 0x16;
        nic->mac[2] = 0x3e;
        nic->mac[3] = r[0] & 0x7f;
        nic->mac[4] = r[1];
        nic->mac[5] = r[2];
    }
    if (!nic->bridge) {
        nic->bridge = strdup("xenbr0");
        if (!nic->bridge) return ERROR_NOMEM;
    }
    if ( !nic->script && asprintf(&nic->script, "%s/vif-bridge",
                                  libxl__xen_script_dir_path()) < 0 )
        return ERROR_FAIL;

    rc = libxl__resolve_domid(gc, nic->backend_domname, &nic->backend_domid);
    if (rc < 0) return rc;

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        if (!nic->nictype) {
            if (hotplug)
                nic->nictype = LIBXL_NIC_TYPE_VIF;
            else
                nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
        }
        break;
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_PV:
        if (nic->nictype == LIBXL_NIC_TYPE_VIF_IOEMU) {
            LOGD(ERROR, domid,
            "trying to create PV or PVH guest with an emulated interface");
            return ERROR_INVAL;
        }
        nic->nictype = LIBXL_NIC_TYPE_VIF;
        break;
    case LIBXL_DOMAIN_TYPE_INVALID:
        return ERROR_FAIL;
    default:
        abort();
    }

    return rc;
}

static int libxl__device_from_nic(libxl__gc *gc, uint32_t domid,
                                  libxl_device_nic *nic,
                                  libxl__device *device)
{
    device->backend_devid    = nic->devid;
    device->backend_domid    = nic->backend_domid;
    device->backend_kind     = LIBXL__DEVICE_KIND_VIF;
    device->devid            = nic->devid;
    device->domid            = domid;
    device->kind             = LIBXL__DEVICE_KIND_VIF;

    return 0;
}

static void libxl__update_config_nic(libxl__gc *gc, libxl_device_nic *dst,
                                     const libxl_device_nic *src)
{
    dst->devid = src->devid;
    dst->nictype = src->nictype;
    libxl_mac_copy(CTX, &dst->mac, &src->mac);
}

static LIBXL_DEFINE_UPDATE_DEVID(nic, "vif")

static int libxl__set_xenstore_nic(libxl__gc *gc, uint32_t domid,
                                   libxl_device_nic *nic,
                                   flexarray_t *back, flexarray_t *front,
                                   flexarray_t *ro_front)
{
    flexarray_grow(back, 2);

    if (nic->script)
        flexarray_append_pair(back, "script",
                              libxl__abs_path(gc, nic->script,
                                              libxl__xen_script_dir_path()));

    if (nic->ifname) {
        flexarray_append(back, "vifname");
        flexarray_append(back, nic->ifname);
    }

    if (nic->coloft_forwarddev) {
        flexarray_append(back, "forwarddev");
        flexarray_append(back, nic->coloft_forwarddev);
    }

#define MAYBE_ADD_COLO_ARGS(arg) ({                                       \
    if (nic->colo_##arg) {                                                \
        flexarray_append(back, "colo_"#arg);                              \
        flexarray_append(back, nic->colo_##arg);                          \
    }                                                                     \
})

    MAYBE_ADD_COLO_ARGS(sock_mirror_id);
    MAYBE_ADD_COLO_ARGS(sock_mirror_ip);
    MAYBE_ADD_COLO_ARGS(sock_mirror_port);
    MAYBE_ADD_COLO_ARGS(sock_compare_pri_in_id);
    MAYBE_ADD_COLO_ARGS(sock_compare_pri_in_ip);
    MAYBE_ADD_COLO_ARGS(sock_compare_pri_in_port);
    MAYBE_ADD_COLO_ARGS(sock_compare_sec_in_id);
    MAYBE_ADD_COLO_ARGS(sock_compare_sec_in_ip);
    MAYBE_ADD_COLO_ARGS(sock_compare_sec_in_port);
    MAYBE_ADD_COLO_ARGS(sock_compare_notify_id);
    MAYBE_ADD_COLO_ARGS(sock_compare_notify_ip);
    MAYBE_ADD_COLO_ARGS(sock_compare_notify_port);
    MAYBE_ADD_COLO_ARGS(sock_redirector0_id);
    MAYBE_ADD_COLO_ARGS(sock_redirector0_ip);
    MAYBE_ADD_COLO_ARGS(sock_redirector0_port);
    MAYBE_ADD_COLO_ARGS(sock_redirector1_id);
    MAYBE_ADD_COLO_ARGS(sock_redirector1_ip);
    MAYBE_ADD_COLO_ARGS(sock_redirector1_port);
    MAYBE_ADD_COLO_ARGS(sock_redirector2_id);
    MAYBE_ADD_COLO_ARGS(sock_redirector2_ip);
    MAYBE_ADD_COLO_ARGS(sock_redirector2_port);
    MAYBE_ADD_COLO_ARGS(filter_mirror_queue);
    MAYBE_ADD_COLO_ARGS(filter_mirror_outdev);
    MAYBE_ADD_COLO_ARGS(filter_redirector0_queue);
    MAYBE_ADD_COLO_ARGS(filter_redirector0_indev);
    MAYBE_ADD_COLO_ARGS(filter_redirector0_outdev);
    MAYBE_ADD_COLO_ARGS(filter_redirector1_queue);
    MAYBE_ADD_COLO_ARGS(filter_redirector1_indev);
    MAYBE_ADD_COLO_ARGS(filter_redirector1_outdev);
    MAYBE_ADD_COLO_ARGS(compare_pri_in);
    MAYBE_ADD_COLO_ARGS(compare_sec_in);
    MAYBE_ADD_COLO_ARGS(compare_out);
    MAYBE_ADD_COLO_ARGS(compare_notify_dev);

    MAYBE_ADD_COLO_ARGS(sock_sec_redirector0_id);
    MAYBE_ADD_COLO_ARGS(sock_sec_redirector0_ip);
    MAYBE_ADD_COLO_ARGS(sock_sec_redirector0_port);
    MAYBE_ADD_COLO_ARGS(sock_sec_redirector1_id);
    MAYBE_ADD_COLO_ARGS(sock_sec_redirector1_ip);
    MAYBE_ADD_COLO_ARGS(sock_sec_redirector1_port);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector0_queue);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector0_indev);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector0_outdev);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector1_queue);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector1_indev);
    MAYBE_ADD_COLO_ARGS(filter_sec_redirector1_outdev);
    MAYBE_ADD_COLO_ARGS(filter_sec_rewriter0_queue);
    MAYBE_ADD_COLO_ARGS(checkpoint_host);
    MAYBE_ADD_COLO_ARGS(checkpoint_port);

#undef MAYBE_ADD_COLO_ARGS

    flexarray_append(back, "mac");
    flexarray_append(back,GCSPRINTF(LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nic->mac)));
    if (nic->ip) {
        flexarray_append(back, "ip");
        flexarray_append(back, libxl__strdup(gc, nic->ip));
    }
    if (nic->gatewaydev) {
        flexarray_append(back, "gatewaydev");
        flexarray_append(back, libxl__strdup(gc, nic->gatewaydev));
    }

    if (nic->rate_interval_usecs > 0) {
        flexarray_append(back, "rate");
        flexarray_append(back, GCSPRINTF("%"PRIu64",%"PRIu32"",
                            nic->rate_bytes_per_interval,
                            nic->rate_interval_usecs));
    }

    flexarray_append(back, "bridge");
    flexarray_append(back, libxl__strdup(gc, nic->bridge));
    flexarray_append(back, "handle");
    flexarray_append(back, GCSPRINTF("%d", nic->devid));
    flexarray_append(back, "type");
    flexarray_append(back, libxl__strdup(gc,
                                     libxl_nic_type_to_string(nic->nictype)));

    flexarray_append(front, "handle");
    flexarray_append(front, GCSPRINTF("%d", nic->devid));
    flexarray_append(front, "mac");
    flexarray_append(front, GCSPRINTF(
                                    LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nic->mac)));

    return 0;
}

static void libxl__device_nic_add(libxl__egc *egc, uint32_t domid,
                                  libxl_device_nic *nic,
                                  libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__nic_devtype, nic, aodev);
}

static int libxl__nic_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                    libxl_devid devid, libxl_device_nic *nic)
{
    const char *tmp;
    int rc;

    libxl_device_nic_init(nic);

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/handle", libxl_path), &tmp);
    if (rc) goto out;
    if (tmp)
        nic->devid = atoi(tmp);
    else
        nic->devid = 0;

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path), &tmp);
    if (rc) goto out;

    if (!tmp) {
        LOG(ERROR, "nic %s does not exist (no backend path)", libxl_path);
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl__backendpath_parse_domid(gc, tmp, &nic->backend_domid);
    if (rc) goto out;

    /* nic->mtu = */

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/mac", libxl_path), &tmp);
    if (rc) goto out;
    if (tmp) {
        rc = libxl__parse_mac(tmp, nic->mac);
        if (rc) goto out;
    } else {
        memset(nic->mac, 0, sizeof(nic->mac));
    }

    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/ip", libxl_path),
                                (const char **)(&nic->ip));
    if (rc) goto out;
    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/bridge", libxl_path),
                                (const char **)(&nic->bridge));
    if (rc) goto out;
    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/script", libxl_path),
                                (const char **)(&nic->script));
    if (rc) goto out;
    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/forwarddev", libxl_path),
                                (const char **)(&nic->coloft_forwarddev));
    if (rc) goto out;

#define CHECK_COLO_ARGS(arg) ({                                           \
    rc = libxl__xs_read_checked(NOGC, XBT_NULL,                           \
                                GCSPRINTF("%s/colo_"#arg, libxl_path),    \
                                (const char **)(&nic->colo_##arg));       \
    if (rc) goto out;                                                     \
})

    CHECK_COLO_ARGS(sock_mirror_id);
    CHECK_COLO_ARGS(sock_mirror_ip);
    CHECK_COLO_ARGS(sock_mirror_port);
    CHECK_COLO_ARGS(sock_compare_pri_in_id);
    CHECK_COLO_ARGS(sock_compare_pri_in_ip);
    CHECK_COLO_ARGS(sock_compare_pri_in_port);
    CHECK_COLO_ARGS(sock_compare_sec_in_id);
    CHECK_COLO_ARGS(sock_compare_sec_in_ip);
    CHECK_COLO_ARGS(sock_compare_sec_in_port);
    CHECK_COLO_ARGS(sock_compare_notify_id);
    CHECK_COLO_ARGS(sock_compare_notify_ip);
    CHECK_COLO_ARGS(sock_compare_notify_port);
    CHECK_COLO_ARGS(sock_redirector0_id);
    CHECK_COLO_ARGS(sock_redirector0_ip);
    CHECK_COLO_ARGS(sock_redirector0_port);
    CHECK_COLO_ARGS(sock_redirector1_id);
    CHECK_COLO_ARGS(sock_redirector1_ip);
    CHECK_COLO_ARGS(sock_redirector1_port);
    CHECK_COLO_ARGS(sock_redirector2_id);
    CHECK_COLO_ARGS(sock_redirector2_ip);
    CHECK_COLO_ARGS(sock_redirector2_port);
    CHECK_COLO_ARGS(filter_mirror_queue);
    CHECK_COLO_ARGS(filter_mirror_outdev);
    CHECK_COLO_ARGS(filter_redirector0_queue);
    CHECK_COLO_ARGS(filter_redirector0_indev);
    CHECK_COLO_ARGS(filter_redirector0_outdev);
    CHECK_COLO_ARGS(filter_redirector1_queue);
    CHECK_COLO_ARGS(filter_redirector1_indev);
    CHECK_COLO_ARGS(filter_redirector1_outdev);
    CHECK_COLO_ARGS(compare_pri_in);
    CHECK_COLO_ARGS(compare_sec_in);
    CHECK_COLO_ARGS(compare_out);
    CHECK_COLO_ARGS(compare_notify_dev);
    CHECK_COLO_ARGS(sock_sec_redirector0_id);
    CHECK_COLO_ARGS(sock_sec_redirector0_ip);
    CHECK_COLO_ARGS(sock_sec_redirector0_port);
    CHECK_COLO_ARGS(sock_sec_redirector1_id);
    CHECK_COLO_ARGS(sock_sec_redirector1_ip);
    CHECK_COLO_ARGS(sock_sec_redirector1_port);
    CHECK_COLO_ARGS(filter_sec_redirector0_queue);
    CHECK_COLO_ARGS(filter_sec_redirector0_indev);
    CHECK_COLO_ARGS(filter_sec_redirector0_outdev);
    CHECK_COLO_ARGS(filter_sec_redirector1_queue);
    CHECK_COLO_ARGS(filter_sec_redirector1_indev);
    CHECK_COLO_ARGS(filter_sec_redirector1_outdev);
    CHECK_COLO_ARGS(filter_sec_rewriter0_queue);
    CHECK_COLO_ARGS(checkpoint_host);
    CHECK_COLO_ARGS(checkpoint_port);

#undef CHECK_COLO_ARGS

    /* vif_ioemu nics use the same xenstore entries as vif interfaces */
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/type", libxl_path), &tmp);
    if (rc) goto out;
    if (tmp) {
        rc = libxl_nic_type_from_string(tmp, &nic->nictype);
        if (rc) goto out;
    } else {
        nic->nictype = LIBXL_NIC_TYPE_VIF;
    }
    nic->model = NULL; /* XXX Only for TYPE_IOEMU */
    nic->ifname = NULL; /* XXX Only for TYPE_IOEMU */

    rc = 0;
 out:
    return rc;
}

int libxl_devid_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                              int devid, libxl_device_nic *nic)
{
    GC_INIT(ctx);
    char *libxl_dom_path, *libxl_path;
    int rc = ERROR_FAIL;

    libxl_device_nic_init(nic);
    libxl_dom_path = libxl__xs_libxl_path(gc, domid);
    if (!libxl_dom_path)
        goto out;

    libxl_path = GCSPRINTF("%s/device/vif/%d", libxl_dom_path, devid);

    rc = libxl__nic_from_xenstore(gc, libxl_path, devid, nic);
    if (rc) goto out;

    rc = 0;
out:
    GC_FREE;
    return rc;
}

libxl_device_nic *libxl_device_nic_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    libxl_device_nic *r;

    GC_INIT(ctx);

    r = libxl__device_list(gc, &libxl__nic_devtype, domid, num);

    GC_FREE;

    return r;
}

void libxl_device_nic_list_free(libxl_device_nic* list, int num)
{
    libxl__device_list_free(&libxl__nic_devtype, list, num);
}

int libxl_device_nic_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_nic *nic, libxl_nicinfo *nicinfo)
{
    GC_INIT(ctx);
    char *dompath, *nicpath, *libxl_path;
    char *val;
    int rc;

    dompath = libxl__xs_get_dompath(gc, domid);
    nicinfo->devid = nic->devid;

    nicpath = GCSPRINTF("%s/device/vif/%d", dompath, nicinfo->devid);
    libxl_path = GCSPRINTF("%s/device/vif/%d",
                           libxl__xs_libxl_path(gc, domid), nicinfo->devid);
    nicinfo->backend = xs_read(ctx->xsh, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!nicinfo->backend) {
        GC_FREE;
        return ERROR_FAIL;
    }
    rc = libxl__backendpath_parse_domid(gc, nicinfo->backend,
                                        &nicinfo->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", nicpath));
    nicinfo->state = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/event-channel", nicpath));
    nicinfo->evtch = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/tx-ring-ref", nicpath));
    nicinfo->rref_tx = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/rx-ring-ref", nicpath));
    nicinfo->rref_rx = val ? strtoul(val, NULL, 10) : -1;
    nicinfo->frontend = libxl__strdup(NOGC, nicpath);
    nicinfo->frontend_id = domid;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

const char *libxl__device_nic_devname(libxl__gc *gc,
                                      uint32_t domid,
                                      uint32_t devid,
                                      libxl_nic_type type)
{
    switch (type) {
    case LIBXL_NIC_TYPE_VIF:
        return GCSPRINTF(NETBACK_NIC_NAME, domid, devid);
    case LIBXL_NIC_TYPE_VIF_IOEMU:
        return GCSPRINTF(NETBACK_NIC_NAME TAP_DEVICE_SUFFIX, domid, devid);
    default:
        abort();
    }
}

static int libxl_device_nic_compare(libxl_device_nic *d1,
                                    libxl_device_nic *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl_device_nic_update_config(libxl__gc *gc, void *d, void *s)
{
    libxl__update_config_nic(gc, d, s);
}

int libxl__device_nic_set_devids(libxl__gc *gc, libxl_domain_config *d_config,
                                 uint32_t domid)
{
    int ret = 0;
    int i;
    size_t last_devid = -1;

    for (i = 0; i < d_config->num_nics; i++) {
        /* We have to init the nic here, because we still haven't
         * called libxl_device_nic_add when domcreate_launch_dm gets called,
         * but qemu needs the nic information to be complete.
         */
        ret = libxl__device_nic_setdefault(gc, domid, &d_config->nics[i],
                                           false);
        if (ret) {
            LOGD(ERROR, domid, "Unable to set nic defaults for nic %d", i);
            goto out;
        }

        if (d_config->nics[i].devid > last_devid)
            last_devid = d_config->nics[i].devid;
    }
    for (i = 0; i < d_config->num_nics; i++) {
        if (d_config->nics[i].devid < 0)
            d_config->nics[i].devid = ++last_devid;
    }

out:
    return ret;
}

LIBXL_DEFINE_DEVICE_ADD(nic)
LIBXL_DEFINE_DEVICES_ADD(nic)
LIBXL_DEFINE_DEVICE_REMOVE(nic)

DEFINE_DEVICE_TYPE_STRUCT_X(nic, nic, vif,
    .update_config = libxl_device_nic_update_config,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__nic_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_nic,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
