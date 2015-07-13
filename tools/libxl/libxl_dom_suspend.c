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

/*====================== Domain suspend =======================*/

/*----- callbacks, called by xc_domain_save -----*/

int libxl__domain_suspend_device_model(libxl__gc *gc,
                                       libxl__domain_suspend_state *dss)
{
    int ret = 0;
    uint32_t const domid = dss->domid;
    const char *const filename = dss->dm_savefile;

    switch (libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL: {
        LOG(DEBUG, "Saving device model state to %s", filename);
        libxl__qemu_traditional_cmd(gc, domid, "save");
        libxl__wait_for_device_model_deprecated(gc, domid, "paused", NULL, NULL, NULL);
        break;
    }
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        if (libxl__qmp_stop(gc, domid))
            return ERROR_FAIL;
        /* Save DM state into filename */
        ret = libxl__qmp_save(gc, domid, filename);
        if (ret)
            unlink(filename);
        break;
    default:
        return ERROR_INVAL;
    }

    return ret;
}

static void domain_suspend_common_wait_guest(libxl__egc *egc,
                                             libxl__domain_suspend_state *dss);
static void domain_suspend_common_guest_suspended(libxl__egc *egc,
                                         libxl__domain_suspend_state *dss);

static void domain_suspend_common_pvcontrol_suspending(libxl__egc *egc,
      libxl__xswait_state *xswa, int rc, const char *state);
static void domain_suspend_common_wait_guest_evtchn(libxl__egc *egc,
        libxl__ev_evtchn *evev);
static void suspend_common_wait_guest_watch(libxl__egc *egc,
      libxl__ev_xswatch *xsw, const char *watch_path, const char *event_path);
static void suspend_common_wait_guest_check(libxl__egc *egc,
        libxl__domain_suspend_state *dss);
static void suspend_common_wait_guest_timeout(libxl__egc *egc,
      libxl__ev_time *ev, const struct timeval *requested_abs, int rc);

static void domain_suspend_common_done(libxl__egc *egc,
                                       libxl__domain_suspend_state *dss,
                                       int rc);

static void domain_suspend_callback_common(libxl__egc *egc,
                                           libxl__domain_suspend_state *dss);
static void domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dss, int rc);

/* calls dss->callback_common_done when done */
void libxl__domain_suspend(libxl__egc *egc,
                           libxl__domain_suspend_state *dss)
{
    domain_suspend_callback_common(egc, dss);
}

static bool domain_suspend_pvcontrol_acked(const char *state) {
    /* any value other than "suspend", including ENOENT (i.e. !state), is OK */
    if (!state) return 1;
    return strcmp(state,"suspend");
}

/* calls dss->callback_common_done when done */
static void domain_suspend_callback_common(libxl__egc *egc,
                                           libxl__domain_suspend_state *dss)
{
    STATE_AO_GC(dss->ao);
    uint64_t hvm_s_state = 0, hvm_pvdrv = 0;
    int ret, rc;

    /* Convenience aliases */
    const uint32_t domid = dss->domid;

    if (dss->hvm) {
        xc_hvm_param_get(CTX->xch, domid, HVM_PARAM_CALLBACK_IRQ, &hvm_pvdrv);
        xc_hvm_param_get(CTX->xch, domid, HVM_PARAM_ACPI_S_STATE, &hvm_s_state);
    }

    if ((hvm_s_state == 0) && (dss->guest_evtchn.port >= 0)) {
        LOG(DEBUG, "issuing %s suspend request via event channel",
            dss->hvm ? "PVHVM" : "PV");
        ret = xc_evtchn_notify(CTX->xce, dss->guest_evtchn.port);
        if (ret < 0) {
            LOG(ERROR, "xc_evtchn_notify failed ret=%d", ret);
            rc = ERROR_FAIL;
            goto err;
        }

        dss->guest_evtchn.callback = domain_suspend_common_wait_guest_evtchn;
        rc = libxl__ev_evtchn_wait(gc, &dss->guest_evtchn);
        if (rc) goto err;

        rc = libxl__ev_time_register_rel(ao, &dss->guest_timeout,
                                         suspend_common_wait_guest_timeout,
                                         60*1000);
        if (rc) goto err;

        return;
    }

    if (dss->hvm && (!hvm_pvdrv || hvm_s_state)) {
        LOG(DEBUG, "Calling xc_domain_shutdown on HVM domain");
        ret = xc_domain_shutdown(CTX->xch, domid, SHUTDOWN_suspend);
        if (ret < 0) {
            LOGE(ERROR, "xc_domain_shutdown failed");
            rc = ERROR_FAIL;
            goto err;
        }
        /* The guest does not (need to) respond to this sort of request. */
        dss->guest_responded = 1;
        domain_suspend_common_wait_guest(egc, dss);
        return;
    }

    LOG(DEBUG, "issuing %s suspend request via XenBus control node",
        dss->hvm ? "PVHVM" : "PV");

    libxl__domain_pvcontrol_write(gc, XBT_NULL, domid, "suspend");

    dss->pvcontrol.path = libxl__domain_pvcontrol_xspath(gc, domid);
    if (!dss->pvcontrol.path) { rc = ERROR_FAIL; goto err; }

    dss->pvcontrol.ao = ao;
    dss->pvcontrol.what = "guest acknowledgement of suspend request";
    dss->pvcontrol.timeout_ms = 60 * 1000;
    dss->pvcontrol.callback = domain_suspend_common_pvcontrol_suspending;
    libxl__xswait_start(gc, &dss->pvcontrol);
    return;

 err:
    domain_suspend_common_done(egc, dss, rc);
}

static void domain_suspend_common_wait_guest_evtchn(libxl__egc *egc,
        libxl__ev_evtchn *evev)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(evev, *dss, guest_evtchn);
    STATE_AO_GC(dss->ao);
    /* If we should be done waiting, suspend_common_wait_guest_check
     * will end up calling domain_suspend_common_guest_suspended or
     * domain_suspend_common_done, both of which cancel the evtchn
     * wait as needed.  So re-enable it now. */
    libxl__ev_evtchn_wait(gc, &dss->guest_evtchn);
    suspend_common_wait_guest_check(egc, dss);
}

static void domain_suspend_common_pvcontrol_suspending(libxl__egc *egc,
      libxl__xswait_state *xswa, int rc, const char *state)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(xswa, *dss, pvcontrol);
    STATE_AO_GC(dss->ao);
    xs_transaction_t t = 0;

    if (!rc && !domain_suspend_pvcontrol_acked(state))
        /* keep waiting */
        return;

    libxl__xswait_stop(gc, &dss->pvcontrol);

    if (rc == ERROR_TIMEDOUT) {
        /*
         * Guest appears to not be responding. Cancel the suspend
         * request.
         *
         * We re-read the suspend node and clear it within a
         * transaction in order to handle the case where we race
         * against the guest catching up and acknowledging the request
         * at the last minute.
         */
        for (;;) {
            rc = libxl__xs_transaction_start(gc, &t);
            if (rc) goto err;

            rc = libxl__xs_read_checked(gc, t, xswa->path, &state);
            if (rc) goto err;

            if (domain_suspend_pvcontrol_acked(state))
                /* last minute ack */
                break;

            rc = libxl__xs_write_checked(gc, t, xswa->path, "");
            if (rc) goto err;

            rc = libxl__xs_transaction_commit(gc, &t);
            if (!rc) {
                LOG(ERROR,
                    "guest didn't acknowledge suspend, cancelling request");
                goto err;
            }
            if (rc<0) goto err;
        }
    } else if (rc) {
        /* some error in xswait's read of xenstore, already logged */
        goto err;
    }

    assert(domain_suspend_pvcontrol_acked(state));
    LOG(DEBUG, "guest acknowledged suspend request");

    libxl__xs_transaction_abort(gc, &t);
    dss->guest_responded = 1;
    domain_suspend_common_wait_guest(egc,dss);
    return;

 err:
    libxl__xs_transaction_abort(gc, &t);
    domain_suspend_common_done(egc, dss, rc);
    return;
}

static void domain_suspend_common_wait_guest(libxl__egc *egc,
                                             libxl__domain_suspend_state *dss)
{
    STATE_AO_GC(dss->ao);
    int rc;

    LOG(DEBUG, "wait for the guest to suspend");

    rc = libxl__ev_xswatch_register(gc, &dss->guest_watch,
                                    suspend_common_wait_guest_watch,
                                    "@releaseDomain");
    if (rc) goto err;

    rc = libxl__ev_time_register_rel(ao, &dss->guest_timeout,
                                     suspend_common_wait_guest_timeout,
                                     60*1000);
    if (rc) goto err;
    return;

 err:
    domain_suspend_common_done(egc, dss, rc);
}

static void suspend_common_wait_guest_watch(libxl__egc *egc,
      libxl__ev_xswatch *xsw, const char *watch_path, const char *event_path)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(xsw, *dss, guest_watch);
    suspend_common_wait_guest_check(egc, dss);
}

static void suspend_common_wait_guest_check(libxl__egc *egc,
        libxl__domain_suspend_state *dss)
{
    STATE_AO_GC(dss->ao);
    xc_domaininfo_t info;
    int ret;
    int shutdown_reason;

    /* Convenience aliases */
    const uint32_t domid = dss->domid;

    ret = xc_domain_getinfolist(CTX->xch, domid, 1, &info);
    if (ret < 0) {
        LOGE(ERROR, "unable to check for status of guest %"PRId32"", domid);
        goto err;
    }

    if (!(ret == 1 && info.domain == domid)) {
        LOGE(ERROR, "guest %"PRId32" we were suspending has been destroyed",
             domid);
        goto err;
    }

    if (!(info.flags & XEN_DOMINF_shutdown))
        /* keep waiting */
        return;

    shutdown_reason = (info.flags >> XEN_DOMINF_shutdownshift)
        & XEN_DOMINF_shutdownmask;
    if (shutdown_reason != SHUTDOWN_suspend) {
        LOG(DEBUG, "guest %"PRId32" we were suspending has shut down"
            " with unexpected reason code %d", domid, shutdown_reason);
        goto err;
    }

    LOG(DEBUG, "guest has suspended");
    domain_suspend_common_guest_suspended(egc, dss);
    return;

 err:
    domain_suspend_common_done(egc, dss, ERROR_FAIL);
}

static void suspend_common_wait_guest_timeout(libxl__egc *egc,
      libxl__ev_time *ev, const struct timeval *requested_abs, int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(ev, *dss, guest_timeout);
    STATE_AO_GC(dss->ao);
    if (rc == ERROR_TIMEDOUT) {
        LOG(ERROR, "guest did not suspend, timed out");
        rc = ERROR_GUEST_TIMEDOUT;
    }
    domain_suspend_common_done(egc, dss, rc);
}

static void domain_suspend_common_guest_suspended(libxl__egc *egc,
                                         libxl__domain_suspend_state *dss)
{
    STATE_AO_GC(dss->ao);
    int rc;

    libxl__ev_evtchn_cancel(gc, &dss->guest_evtchn);
    libxl__ev_xswatch_deregister(gc, &dss->guest_watch);
    libxl__ev_time_deregister(gc, &dss->guest_timeout);

    if (dss->hvm) {
        rc = libxl__domain_suspend_device_model(gc, dss);
        if (rc) {
            LOG(ERROR, "libxl__domain_suspend_device_model failed ret=%d", rc);
            domain_suspend_common_done(egc, dss, rc);
            return;
        }
    }
    domain_suspend_common_done(egc, dss, 0);
}

static void domain_suspend_common_done(libxl__egc *egc,
                                       libxl__domain_suspend_state *dss,
                                       int rc)
{
    EGC_GC;
    assert(!libxl__xswait_inuse(&dss->pvcontrol));
    libxl__ev_evtchn_cancel(gc, &dss->guest_evtchn);
    libxl__ev_xswatch_deregister(gc, &dss->guest_watch);
    libxl__ev_time_deregister(gc, &dss->guest_timeout);
    dss->callback_common_done(egc, dss, rc);
}

void libxl__domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;

    dss->callback_common_done = domain_suspend_callback_common_done;
    domain_suspend_callback_common(egc, dss);
}

static void domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dss, int rc)
{
    dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

/*======================= Domain resume ========================*/

int libxl__domain_resume_device_model(libxl__gc *gc, uint32_t domid)
{
    const char *path, *state;

    switch (libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL: {
        uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);

        path = libxl__device_model_xs_path(gc, dm_domid, domid, "/state");
        state = libxl__xs_read(gc, XBT_NULL, path);
        if (state != NULL && !strcmp(state, "paused")) {
            libxl__qemu_traditional_cmd(gc, domid, "continue");
            libxl__wait_for_device_model_deprecated(gc, domid, "running",
                                                    NULL, NULL, NULL);
        }
        break;
    }
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        if (libxl__qmp_resume(gc, domid))
            return ERROR_FAIL;
        break;
    default:
        return ERROR_INVAL;
    }

    return 0;
}

int libxl__domain_resume(libxl__gc *gc, uint32_t domid, int suspend_cancel)
{
    int rc = 0;

    if (xc_domain_resume(CTX->xch, domid, suspend_cancel)) {
        LOGE(ERROR, "xc_domain_resume failed for domain %u", domid);
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        rc = libxl__domain_resume_device_model(gc, domid);
        if (rc) {
            LOG(ERROR, "failed to resume device model for domain %u:%d",
                domid, rc);
            goto out;
        }
    }

    if (!xs_resume_domain(CTX->xsh, domid)) {
        LOGE(ERROR, "xs_resume_domain failed for domain %u", domid);
        rc = ERROR_FAIL;
    }
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
