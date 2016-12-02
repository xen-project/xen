/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *        Yang Hongyang <hongyang.yang@easystack.cn>
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

extern const libxl__checkpoint_device_instance_ops remus_device_nic;
extern const libxl__checkpoint_device_instance_ops remus_device_drbd_disk;
static const libxl__checkpoint_device_instance_ops *remus_ops[] = {
    &remus_device_nic,
    &remus_device_drbd_disk,
    NULL,
};

/*----- helper functions -----*/

static int init_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* init device subkind-specific state in the libxl ctx */
    int rc;
    STATE_AO_GC(cds->ao);

    if (libxl__netbuffer_enabled(gc)) {
        rc = init_subkind_nic(cds);
        if (rc) goto out;
    }

    rc = init_subkind_drbd_disk(cds);
    if (rc) goto out;

    rc = 0;
out:
    return rc;
}

static void cleanup_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* cleanup device subkind-specific state in the libxl ctx */
    STATE_AO_GC(cds->ao);

    if (libxl__netbuffer_enabled(gc))
        cleanup_subkind_nic(cds);

    cleanup_subkind_drbd_disk(cds);
}

/*-------------------- Remus setup and teardown ---------------------*/

static void remus_setup_done(libxl__egc *egc,
                             libxl__checkpoint_devices_state *cds, int rc);
static void remus_setup_failed(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds, int rc);
static void remus_checkpoint_stream_written(
    libxl__egc *egc, libxl__stream_write_state *sws, int rc);
static void libxl__remus_domain_suspend_callback(void *data);
static void libxl__remus_domain_resume_callback(void *data);
static void libxl__remus_domain_save_checkpoint_callback(void *data);

void libxl__remus_setup(libxl__egc *egc, libxl__remus_state *rs)
{
    libxl__domain_save_state *dss = CONTAINER_OF(rs, *dss, rs);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;
    const libxl_domain_remus_info *const info = dss->remus;
    libxl__srm_save_autogen_callbacks *const callbacks =
        &dss->sws.shs.callbacks.save.a;

    STATE_AO_GC(dss->ao);

    if (libxl_defbool_val(info->netbuf)) {
        if (!libxl__netbuffer_enabled(gc)) {
            LOGD(ERROR, dss->domid,
                 "Remus: No support for network buffering");
            goto out;
        }
        cds->device_kind_flags |= (1 << LIBXL__DEVICE_KIND_VIF);
    }

    if (libxl_defbool_val(info->diskbuf))
        cds->device_kind_flags |= (1 << LIBXL__DEVICE_KIND_VBD);

    cds->ao = ao;
    cds->domid = dss->domid;
    cds->callback = remus_setup_done;
    cds->ops = remus_ops;
    cds->concrete_data = rs;
    rs->interval = info->interval;

    if (init_device_subkind(cds)) {
        LOGD(ERROR, dss->domid,
             "Remus: failed to init device subkind");
        goto out;
    }

    dss->sws.checkpoint_callback = remus_checkpoint_stream_written;

    callbacks->suspend = libxl__remus_domain_suspend_callback;
    callbacks->postcopy = libxl__remus_domain_resume_callback;
    callbacks->checkpoint = libxl__remus_domain_save_checkpoint_callback;

    libxl__checkpoint_devices_setup(egc, cds);
    return;

out:
    dss->callback(egc, dss, ERROR_FAIL);
}

static void remus_setup_done(libxl__egc *egc,
                             libxl__checkpoint_devices_state *cds, int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (!rc) {
        libxl__domain_save(egc, dss);
        return;
    }

    LOGD(ERROR, dss->domid, "Remus: failed to setup device, rc %d", rc);
    cds->callback = remus_setup_failed;
    libxl__checkpoint_devices_teardown(egc, cds);
}

static void remus_setup_failed(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds, int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        LOGD(ERROR, dss->domid,
             "Remus: failed to teardown device after setup failed, rc %d", rc);

    cleanup_device_subkind(cds);

    dss->callback(egc, dss, rc);
}

static void remus_teardown_done(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc);
void libxl__remus_teardown(libxl__egc *egc,
                           libxl__remus_state *rs,
                           int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(rs, *dss, rs);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    EGC_GC;

    LOGD(WARN, dss->domid, "Remus: Domain suspend terminated with rc %d,"
         " teardown Remus devices...", rc);
    cds->callback = remus_teardown_done;
    libxl__checkpoint_devices_teardown(egc, cds);
}

static void remus_teardown_done(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        LOGD(ERROR, dss->domid, "Remus: failed to teardown device,"
            " rc %d", rc);

    cleanup_device_subkind(cds);

    dss->callback(egc, dss, rc);
}

/*---------------------- remus callbacks (save) -----------------------*/

static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dsps, int ok);
static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__checkpoint_devices_state *cds,
                                         int rc);
static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__checkpoint_devices_state *cds,
                                       int rc);

static void libxl__remus_domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_save_state *dss = shs->caller_state;
    libxl__domain_suspend_state *dsps = &dss->dsps;

    dsps->callback_common_done = remus_domain_suspend_callback_common_done;
    libxl__domain_suspend(egc, dsps);
}

static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dsps, int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(dsps, *dss, dsps);

    if (rc)
        goto out;

    libxl__checkpoint_devices_state *const cds = &dss->cds;
    cds->callback = remus_devices_postsuspend_cb;
    libxl__checkpoint_devices_postsuspend(egc, cds);
    return;

out:
    dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__checkpoint_devices_state *cds,
                                         int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);

    if (rc)
        goto out;

    rc = 0;

out:
    if (rc)
        dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void libxl__remus_domain_resume_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_save_state *dss = shs->caller_state;
    STATE_AO_GC(dss->ao);

    libxl__checkpoint_devices_state *const cds = &dss->cds;
    cds->callback = remus_devices_preresume_cb;
    libxl__checkpoint_devices_preresume(egc, cds);
}

static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__checkpoint_devices_state *cds,
                                       int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        goto out;

    /* Resumes the domain and the device model */
    rc = libxl__domain_resume(gc, dss->domid, /* Fast Suspend */1);
    if (rc)
        goto out;

    rc = 0;

out:
    if (rc)
        dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

/*----- remus asynchronous checkpoint callback -----*/

static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc);
static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs,
                                  int rc);

static void libxl__remus_domain_save_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__domain_save_state *dss = shs->caller_state;
    libxl__egc *egc = shs->egc;
    STATE_AO_GC(dss->ao);

    libxl__stream_write_start_checkpoint(egc, &dss->sws);
}

static void remus_checkpoint_stream_written(
    libxl__egc *egc, libxl__stream_write_state *sws, int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(sws, *dss, sws);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOGD(ERROR, dss->domid, "Failed to save device model."
             " Terminating Remus..");
        goto out;
    }

    cds->callback = remus_devices_commit_cb;
    libxl__checkpoint_devices_commit(egc, cds);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(cds, *dss, cds);

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOGD(ERROR, dss->domid, "Failed to do device commit op."
            " Terminating Remus..");
        goto out;
    }

    /*
     * At this point, we have successfully checkpointed the guest and
     * committed it at the backup. We'll come back after the checkpoint
     * interval to checkpoint the guest again. Until then, let the guest
     * continue execution.
     */

    /* Set checkpoint interval timeout */
    rc = libxl__ev_time_register_rel(ao, &dss->rs.checkpoint_timeout,
                                     remus_next_checkpoint,
                                     dss->rs.interval);

    if (rc)
        goto out;

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs,
                                  int rc)
{
    libxl__domain_save_state *dss =
                            CONTAINER_OF(ev, *dss, rs.checkpoint_timeout);

    STATE_AO_GC(dss->ao);

    if (rc == ERROR_TIMEDOUT) /* As intended */
        rc = 0;

    /*
     * Time to checkpoint the guest again. We return 1 to libxc
     * (xc_domain_save.c). in order to continue executing the infinite loop
     * (suspend, checkpoint, resume) in xc_domain_save().
     */

    if (rc)
        dss->rc = rc;

    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

/*---------------------- remus callbacks (restore) -----------------------*/

/*----- remus asynchronous checkpoint callback -----*/

static void remus_checkpoint_stream_done(
    libxl__egc *egc, libxl__stream_read_state *srs, int rc);

static void libxl__remus_domain_restore_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__domain_create_state *dcs = shs->caller_state;
    libxl__egc *egc = shs->egc;
    STATE_AO_GC(dcs->ao);

    libxl__stream_read_start_checkpoint(egc, &dcs->srs);
}

static void remus_checkpoint_stream_done(
    libxl__egc *egc, libxl__stream_read_state *stream, int rc)
{
    libxl__xc_domain_saverestore_async_callback_done(egc, &stream->shs, rc);
}

void libxl__remus_restore_setup(libxl__egc *egc,
                                libxl__domain_create_state *dcs)
{
    /* Convenience aliases */
    libxl__srm_restore_autogen_callbacks *const callbacks =
        &dcs->srs.shs.callbacks.restore.a;

    callbacks->checkpoint = libxl__remus_domain_restore_checkpoint_callback;
    dcs->srs.checkpoint_callback = remus_checkpoint_stream_done;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
