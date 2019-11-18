/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <xen/errno.h>

/*========================= Domain save ============================*/

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *sws, int rc);
static void domain_save_done(libxl__egc *egc,
                             libxl__domain_save_state *dss, int rc);

/*----- complicated callback, called by xc_domain_save -----*/

/*
 * We implement the other end of protocol for controlling qemu-dm's
 * logdirty.  There is no documentation for this protocol, but our
 * counterparty's implementation is in
 * qemu-xen-traditional.git:xenstore.c in the function
 * xenstore_process_logdirty_event
 */

static void domain_suspend_switch_qemu_xen_traditional_logdirty
                               (libxl__egc *egc, int domid, unsigned enable,
                                libxl__logdirty_switch *lds);
static void switch_logdirty_xswatch(libxl__egc *egc, libxl__ev_xswatch*,
                            const char *watch_path, const char *event_path);
static void domain_suspend_switch_qemu_xen_logdirty
                               (libxl__egc *egc, int domid, unsigned enable,
                                libxl__logdirty_switch *lds);
static void switch_qemu_xen_logdirty_done(libxl__egc *egc,
                                          libxl__ev_qmp *qmp,
                                          const libxl__json_object *,
                                          int rc);
static void switch_logdirty_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                    const struct timeval *requested_abs,
                                    int rc);
static void switch_logdirty_done(libxl__egc *egc,
                                 libxl__logdirty_switch *lds, int rc);

void libxl__logdirty_init(libxl__logdirty_switch *lds)
{
    lds->cmd_path = 0;
    libxl__ev_xswatch_init(&lds->watch);
    libxl__ev_time_init(&lds->timeout);
    libxl__ev_qmp_init(&lds->qmp);
}

void libxl__domain_common_switch_qemu_logdirty(libxl__egc *egc,
                                               int domid, unsigned enable,
                                               libxl__logdirty_switch *lds)
{
    STATE_AO_GC(lds->ao);

    switch (libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        domain_suspend_switch_qemu_xen_traditional_logdirty(egc, domid, enable,
                                                            lds);
        break;
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        domain_suspend_switch_qemu_xen_logdirty(egc, domid, enable, lds);
        break;
    default:
        LOGD(ERROR, domid, "logdirty switch failed"
             ", no valid device model version found, abandoning suspend");
        lds->callback(egc, lds, ERROR_FAIL);
    }
}

static void domain_suspend_switch_qemu_xen_traditional_logdirty
                               (libxl__egc *egc, int domid, unsigned enable,
                                libxl__logdirty_switch *lds)
{
    STATE_AO_GC(lds->ao);
    int rc;
    xs_transaction_t t = 0;
    const char *got;

    if (!lds->cmd_path) {
        uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
        lds->cmd_path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid,
                                             "/logdirty/cmd");
        lds->ret_path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid,
                                             "/logdirty/ret");
    }
    lds->cmd = enable ? "enable" : "disable";

    rc = libxl__ev_xswatch_register(gc, &lds->watch,
                                switch_logdirty_xswatch, lds->ret_path);
    if (rc) goto out;

    rc = libxl__ev_time_register_rel(ao, &lds->timeout,
                                switch_logdirty_timeout, 10*1000);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__xs_read_checked(gc, t, lds->cmd_path, &got);
        if (rc) goto out;

        if (got) {
            const char *got_ret;
            rc = libxl__xs_read_checked(gc, t, lds->ret_path, &got_ret);
            if (rc) goto out;

            if (!got_ret || strcmp(got, got_ret)) {
                LOGD(ERROR, domid, "controlling logdirty: qemu was already sent"
                     " command `%s' (xenstore path `%s') but result is `%s'",
                     got, lds->cmd_path, got_ret ? got_ret : "<none>");
                rc = ERROR_FAIL;
                goto out;
            }
            rc = libxl__xs_rm_checked(gc, t, lds->cmd_path);
            if (rc) goto out;
        }

        rc = libxl__xs_rm_checked(gc, t, lds->ret_path);
        if (rc) goto out;

        rc = libxl__xs_write_checked(gc, t, lds->cmd_path, lds->cmd);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc<0) goto out;
    }

    /* OK, wait for some callback */
    return;

 out:
    LOGD(ERROR, domid, "logdirty switch failed (rc=%d), abandoning suspend",rc);
    libxl__xs_transaction_abort(gc, &t);
    switch_logdirty_done(egc,lds,rc);
}

static void switch_logdirty_xswatch(libxl__egc *egc, libxl__ev_xswatch *watch,
                            const char *watch_path, const char *event_path)
{
    libxl__logdirty_switch *lds = CONTAINER_OF(watch, *lds, watch);
    STATE_AO_GC(lds->ao);
    const char *got;
    xs_transaction_t t = 0;
    int rc;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__xs_read_checked(gc, t, lds->ret_path, &got);
        if (rc) goto out;

        if (!got) {
            rc = +1;
            goto out;
        }

        if (strcmp(got, lds->cmd)) {
            LOG(ERROR,"logdirty switch: sent command `%s' but got reply `%s'"
                " (xenstore paths `%s' / `%s')", lds->cmd, got,
                lds->cmd_path, lds->ret_path);
            rc = ERROR_FAIL;
            goto out;
        }

        rc = libxl__xs_rm_checked(gc, t, lds->cmd_path);
        if (rc) goto out;

        rc = libxl__xs_rm_checked(gc, t, lds->ret_path);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc<0) goto out;
    }

 out:
    /* rc < 0: error
     * rc == 0: ok, we are done
     * rc == +1: need to keep waiting
     */
    libxl__xs_transaction_abort(gc, &t);

    if (rc <= 0) {
        if (rc < 0)
            LOG(ERROR,"logdirty switch: failed (rc=%d)",rc);
        switch_logdirty_done(egc,lds,rc);
    }
}

static void domain_suspend_switch_qemu_xen_logdirty
                               (libxl__egc *egc, int domid, unsigned enable,
                                libxl__logdirty_switch *lds)
{
    STATE_AO_GC(lds->ao);
    int rc;
    libxl__json_object *args = NULL;

    /* Convenience aliases. */
    libxl__ev_qmp *const qmp = &lds->qmp;

    rc = libxl__ev_time_register_rel(ao, &lds->timeout,
                                     switch_logdirty_timeout, 10 * 1000);
    if (rc) goto out;

    qmp->ao = ao;
    qmp->domid = domid;
    qmp->payload_fd = -1;
    qmp->callback = switch_qemu_xen_logdirty_done;
    libxl__qmp_param_add_bool(gc, &args, "enable", enable);
    rc = libxl__ev_qmp_send(egc, qmp, "xen-set-global-dirty-log", args);
    if (rc) goto out;

    return;
out:
    switch_qemu_xen_logdirty_done(egc, qmp, NULL, rc);
}

static void switch_qemu_xen_logdirty_done(libxl__egc *egc,
                                          libxl__ev_qmp *qmp,
                                          const libxl__json_object *r,
                                          int rc)
{
    EGC_GC;
    libxl__logdirty_switch *lds = CONTAINER_OF(qmp, *lds, qmp);

    if (rc)
        LOGD(ERROR, qmp->domid,
             "logdirty switch failed (rc=%d), abandoning suspend",rc);
    switch_logdirty_done(egc, lds, rc);
}

static void switch_logdirty_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                    const struct timeval *requested_abs,
                                    int rc)
{
    libxl__logdirty_switch *lds = CONTAINER_OF(ev, *lds, timeout);
    STATE_AO_GC(lds->ao);
    LOG(ERROR,"logdirty switch: wait for device model timed out");
    switch_logdirty_done(egc,lds,ERROR_FAIL);
}

static void switch_logdirty_done(libxl__egc *egc,
                                 libxl__logdirty_switch *lds,
                                 int rc)
{
    STATE_AO_GC(lds->ao);

    libxl__ev_xswatch_deregister(gc, &lds->watch);
    libxl__ev_time_deregister(gc, &lds->timeout);
    libxl__ev_qmp_dispose(gc, &lds->qmp);

    lds->callback(egc, lds, rc);
}

static void domain_suspend_switch_qemu_logdirty_done
                        (libxl__egc *egc, libxl__logdirty_switch *lds, int rc);

void libxl__domain_suspend_common_switch_qemu_logdirty
                               (uint32_t domid, unsigned enable, void *user)
{
    libxl__save_helper_state *shs = user;
    libxl__egc *egc = shs->egc;
    libxl__domain_save_state *dss = shs->caller_state;

    /* Convenience aliases. */
    libxl__logdirty_switch *const lds = &dss->logdirty;

    if (dss->type == LIBXL_DOMAIN_TYPE_PVH) {
        domain_suspend_switch_qemu_logdirty_done(egc, lds, 0);
        return;
    }

    lds->callback = domain_suspend_switch_qemu_logdirty_done;
    libxl__domain_common_switch_qemu_logdirty(egc, domid, enable, lds);
}

static void domain_suspend_switch_qemu_logdirty_done
                        (libxl__egc *egc, libxl__logdirty_switch *lds, int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(lds, *dss, logdirty);

    if (rc) {
        dss->rc = rc;
        libxl__xc_domain_saverestore_async_callback_done(egc,
                                                         &dss->sws.shs, -1);
    } else
        libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

/*----- callbacks, called by xc_domain_save -----*/

/*
 * Expand the buffer 'buf' of length 'len', to append 'str' including its NUL
 * terminator.
 */
static void append_string(libxl__gc *gc, char **buf, uint32_t *len,
                          const char *str)
{
    size_t extralen = strlen(str) + 1;
    char *new = libxl__realloc(gc, *buf, *len + extralen);

    *buf = new;
    memcpy(new + *len, str, extralen);
    *len += extralen;
}

int libxl__save_emulator_xenstore_data(libxl__domain_save_state *dss,
                                       char **callee_buf,
                                       uint32_t *callee_len)
{
    STATE_AO_GC(dss->ao);
    const char *xs_root;
    char **entries, *buf = NULL;
    unsigned int nr_entries, i, j, len = 0;
    int rc;

    const uint32_t domid = dss->domid;
    const uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);

    xs_root = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "");

    entries = libxl__xs_directory(gc, 0, GCSPRINTF("%s/physmap", xs_root),
                                  &nr_entries);
    if (!entries || nr_entries == 0) { rc = 0; goto out; }

    for (i = 0; i < nr_entries; ++i) {
        static const char *const physmap_subkeys[] = {
            "start_addr", "size", "name"
        };

        for (j = 0; j < ARRAY_SIZE(physmap_subkeys); ++j) {
            const char *key = GCSPRINTF("physmap/%s/%s",
                                        entries[i], physmap_subkeys[j]);

            const char *val =
                libxl__xs_read(gc, XBT_NULL,
                               GCSPRINTF("%s/%s", xs_root, key));

            if (!val) { rc = ERROR_FAIL; goto out; }

            append_string(gc, &buf, &len, key);
            append_string(gc, &buf, &len, val);
        }
    }

    rc = 0;

 out:
    if (!rc) {
        *callee_buf = buf;
        *callee_len = len;
    }

    return rc;
}

/*----- main code for saving, in order of execution -----*/

void libxl__domain_save(libxl__egc *egc, libxl__domain_save_state *dss)
{
    STATE_AO_GC(dss->ao);
    int rc, ret;

    /* Convenience aliases */
    const uint32_t domid = dss->domid;
    const libxl_domain_type type = dss->type;
    const int live = dss->live;
    const int debug = dss->debug;
    const libxl_domain_remus_info *const r_info = dss->remus;
    libxl__srm_save_autogen_callbacks *const callbacks =
        &dss->sws.shs.callbacks.save.a;
    unsigned int nr_vnodes = 0, nr_vmemranges = 0, nr_vcpus = 0;
    libxl__domain_suspend_state *dsps = &dss->dsps;

    if (dss->checkpointed_stream != LIBXL_CHECKPOINTED_STREAM_NONE && !r_info) {
        LOGD(ERROR, domid, "Migration stream is checkpointed, but there's no "
                           "checkpoint info!");
        rc = ERROR_INVAL;
        goto out;
    }

    dss->rc = 0;
    libxl__logdirty_init(&dss->logdirty);
    dss->logdirty.ao = ao;

    dsps->ao = ao;
    dsps->domid = domid;
    dsps->live = !!live;
    rc = libxl__domain_suspend_init(egc, dsps, type);
    if (rc) goto out;

    switch (type) {
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_HVM: {
        dss->hvm = 1;
        break;
    }
    case LIBXL_DOMAIN_TYPE_PV:
        dss->hvm = 0;
        break;
    default:
        abort();
    }

    dss->xcflags = (live ? XCFLAGS_LIVE : 0)
          | (debug ? XCFLAGS_DEBUG : 0)
          | (dss->hvm ? XCFLAGS_HVM : 0);

    /* Disallow saving a guest with vNUMA configured because migration
     * stream does not preserve node information.
     *
     * Reject any domain which has vnuma enabled, even if the
     * configuration is empty. Only domains which have no vnuma
     * configuration at all are supported.
     */
    ret = xc_domain_getvnuma(CTX->xch, domid, &nr_vnodes, &nr_vmemranges,
                             &nr_vcpus, NULL, NULL, NULL);
    if (ret != -1 || errno != EOPNOTSUPP) {
        LOGD(ERROR, domid, "Cannot save a guest with vNUMA configured");
        rc = ERROR_FAIL;
        goto out;
    }

    if (dss->checkpointed_stream == LIBXL_CHECKPOINTED_STREAM_REMUS) {
        if (libxl_defbool_val(r_info->compression))
            dss->xcflags |= XCFLAGS_CHECKPOINT_COMPRESS;
    }

    if (dss->checkpointed_stream == LIBXL_CHECKPOINTED_STREAM_NONE)
        callbacks->suspend = libxl__domain_suspend_callback;

    callbacks->switch_qemu_logdirty = libxl__domain_suspend_common_switch_qemu_logdirty;

    dss->sws.ao  = dss->ao;
    dss->sws.dss = dss;
    dss->sws.fd  = dss->fd;
    dss->sws.back_channel = false;
    dss->sws.completion_callback = stream_done;

    libxl__stream_write_start(egc, &dss->sws);
    return;

 out:
    domain_save_done(egc, dss, rc);
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *sws, int rc)
{
    domain_save_done(egc, sws->dss, rc);
}

static void domain_save_done(libxl__egc *egc,
                             libxl__domain_save_state *dss, int rc)
{
    STATE_AO_GC(dss->ao);

    /* Convenience aliases */
    const uint32_t domid = dss->domid;
    libxl__domain_suspend_state *dsps = &dss->dsps;

    libxl__ev_evtchn_cancel(gc, &dsps->guest_evtchn);

    if (dsps->guest_evtchn.port > 0)
        xc_suspend_evtchn_release(CTX->xch, CTX->xce, domid,
                        dsps->guest_evtchn.port, &dsps->guest_evtchn_lockfd);

    if (dss->remus) {
        /*
         * With Remus/COLO, if we reach this point, it means either
         * backup died or some network error occurred preventing us
         * from sending checkpoints. Teardown the network buffers and
         * release netlink resources.  This is an async op.
         */
        if (libxl_defbool_val(dss->remus->colo))
            libxl__colo_save_teardown(egc, &dss->css, rc);
        else
            libxl__remus_teardown(egc, &dss->rs, rc);
        return;
    }

    dss->callback(egc, dss, rc);
}

/*========================= Domain restore ============================*/

/*
 * Inspect the buffer between start and end, and return a pointer to the
 * character following the NUL terminator of start, or NULL if start is not
 * terminated before end.
 */
static const char *next_string(const char *start, const char *end)
{
    if (start >= end) return NULL;

    size_t total_len = end - start;
    size_t len = strnlen(start, total_len);

    if (len == total_len)
        return NULL;
    else
        return start + len + 1;
}

int libxl__restore_emulator_xenstore_data(libxl__domain_create_state *dcs,
                                          const char *ptr, uint32_t size)
{
    STATE_AO_GC(dcs->ao);
    const char *next = ptr, *end = ptr + size, *key, *val;
    int rc;

    const uint32_t domid = dcs->guest_domid;
    const uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
    const char *xs_root = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "");

    while (next < end) {
        key = next;
        next = next_string(next, end);

        /* Sanitise 'key'. */
        if (!next) {
            rc = ERROR_FAIL;
            LOGD(ERROR, domid, "Key in xenstore data not NUL terminated");
            goto out;
        }
        if (key[0] == '\0') {
            rc = ERROR_FAIL;
            LOGD(ERROR, domid, "empty key found in xenstore data");
            goto out;
        }
        if (key[0] == '/') {
            rc = ERROR_FAIL;
            LOGD(ERROR, domid, "Key in xenstore data not relative");
            goto out;
        }

        val = next;
        next = next_string(next, end);

        /* Sanitise 'val'. */
        if (!next) {
            rc = ERROR_FAIL;
            LOGD(ERROR, domid, "Val in xenstore data not NUL terminated");
            goto out;
        }

        libxl__xs_printf(gc, XBT_NULL,
                         GCSPRINTF("%s/%s", xs_root, key),
                         "%s", val);
    }

    rc = 0;

 out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
