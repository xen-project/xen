/*
 * Copyright (C) 2016 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *         Yang Hongyang <hongyang.yang@easystack.cn>
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

extern const libxl__checkpoint_device_instance_ops colo_save_device_nic;
extern const libxl__checkpoint_device_instance_ops colo_save_device_qdisk;

static const libxl__checkpoint_device_instance_ops *colo_ops[] = {
    &colo_save_device_nic,
    &colo_save_device_qdisk,
    NULL,
};

/* ================= helper functions ================= */

static int init_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* init device subkind-specific state in the libxl ctx */
    int rc;
    STATE_AO_GC(cds->ao);

    rc = init_subkind_colo_nic(cds);
    if (rc) goto out;

    rc = init_subkind_qdisk(cds);
    if (rc) {
        cleanup_subkind_colo_nic(cds);
        goto out;
    }

    rc = 0;
out:
    return rc;
}

static void cleanup_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* cleanup device subkind-specific state in the libxl ctx */
    STATE_AO_GC(cds->ao);

    cleanup_subkind_colo_nic(cds);
    cleanup_subkind_qdisk(cds);
}

/* ================= colo: setup save environment ================= */

static void colo_save_setup_done(libxl__egc *egc,
                                 libxl__checkpoint_devices_state *cds,
                                 int rc);
static void colo_save_setup_failed(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds,
                                   int rc);
/*
 * checkpoint callbacks are called in the following order:
 * 1. suspend
 * 2. checkpoint
 * 3. resume
 * 4. wait checkpoint
 */
static void libxl__colo_save_domain_suspend_callback(void *data);
static void libxl__colo_save_domain_checkpoint_callback(void *data);
static void libxl__colo_save_domain_resume_callback(void *data);
static void libxl__colo_save_domain_wait_checkpoint_callback(void *data);

void libxl__colo_save_setup(libxl__egc *egc, libxl__colo_save_state *css)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;
    libxl__srm_save_autogen_callbacks *const callbacks =
        &dss->sws.shs.callbacks.save.a;

    STATE_AO_GC(dss->ao);

    if (dss->type != LIBXL_DOMAIN_TYPE_HVM) {
        LOGD(ERROR, dss->domid, "COLO only supports hvm now");
        goto out;
    }

    css->send_fd = dss->fd;
    css->recv_fd = dss->recv_fd;
    css->svm_running = false;
    css->paused = true;
    css->qdisk_setuped = false;
    css->qdisk_used = false;
    libxl__ev_child_init(&css->child);
    css->cps.is_userspace_proxy =
        libxl_defbool_val(dss->remus->userspace_colo_proxy);

    if (dss->remus->netbufscript)
        css->colo_proxy_script = libxl__strdup(gc, dss->remus->netbufscript);
    else
        css->colo_proxy_script = GCSPRINTF("%s/colo-proxy-setup",
                                           libxl__xen_script_dir_path());

    cds->ops = colo_ops;
    cds->callback = colo_save_setup_done;
    cds->ao = ao;
    cds->domid = dss->domid;
    cds->concrete_data = css;

    /* If enable userspace proxy mode, we don't need VIF */
    if (css->cps.is_userspace_proxy) {
        cds->device_kind_flags = (1 << LIBXL__DEVICE_KIND_VBD);

        /* Use this args we can connect to qemu colo-compare */
        cds->nics = libxl__device_list(gc, &libxl__nic_devtype,
                                       cds->domid, &cds->num_nics);
        if (cds->num_nics > 0) {
            css->cps.checkpoint_host = cds->nics[0].colo_checkpoint_host;
            css->cps.checkpoint_port = cds->nics[0].colo_checkpoint_port;
        }
    } else {
        cds->device_kind_flags = (1 << LIBXL__DEVICE_KIND_VIF) |
                                 (1 << LIBXL__DEVICE_KIND_VBD);
    }

    css->srs.ao = ao;
    css->srs.fd = css->recv_fd;
    css->srs.back_channel = true;
    libxl__stream_read_start(egc, &css->srs);
    css->cps.ao = ao;
    if (colo_proxy_setup(&css->cps)) {
        LOGD(ERROR, cds->domid, "COLO: failed to setup colo proxy for guest");
        goto out;
    }

    if (init_device_subkind(cds))
        goto out;

    callbacks->suspend = libxl__colo_save_domain_suspend_callback;
    callbacks->checkpoint = libxl__colo_save_domain_checkpoint_callback;
    callbacks->postcopy = libxl__colo_save_domain_resume_callback;
    callbacks->wait_checkpoint = libxl__colo_save_domain_wait_checkpoint_callback;

    libxl__checkpoint_devices_setup(egc, &dss->cds);

    return;

out:
    dss->callback(egc, dss, ERROR_FAIL);
}

static void colo_save_setup_done(libxl__egc *egc,
                                 libxl__checkpoint_devices_state *cds,
                                 int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    EGC_GC;

    if (!rc) {
        libxl__domain_save(egc, dss);
        return;
    }

    LOGD(ERROR, dss->domid, "COLO: failed to setup device for guest");
    cds->callback = colo_save_setup_failed;
    libxl__checkpoint_devices_teardown(egc, cds);
}

static void colo_save_setup_failed(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds,
                                   int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    STATE_AO_GC(cds->ao);

    if (rc)
        LOGD(ERROR, cds->domid,
             "COLO: failed to teardown device after setup failed"
             " for guest, rc %d", rc);

    cleanup_device_subkind(cds);
    dss->callback(egc, dss, rc);
}

/* ================= colo: teardown save environment ================= */

static void colo_teardown_done(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds,
                               int rc);

void libxl__colo_save_teardown(libxl__egc *egc,
                               libxl__colo_save_state *css,
                               int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    LOGD(WARN, dss->domid,
         "COLO: Domain suspend terminated with rc %d,"
         " teardown COLO devices...", rc);

    libxl__stream_read_abort(egc, &css->srs, 1);

    if (css->qdisk_setuped) {
        libxl__qmp_stop_replication(gc, dss->domid, true);
        css->qdisk_setuped = false;
    }

    dss->cds.callback = colo_teardown_done;
    libxl__checkpoint_devices_teardown(egc, &dss->cds);
    return;
}

static void colo_teardown_done(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds,
                               int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    cleanup_device_subkind(cds);
    colo_proxy_teardown(&css->cps);
    dss->callback(egc, dss, rc);
}

static void colo_common_write_stream_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream,
                                          int rc);
static void colo_common_read_stream_done(libxl__egc *egc,
                                         libxl__stream_read_state *stream,
                                         int rc);

/* ===================== colo: suspend primary vm ===================== */

static void colo_read_svm_suspended_done(libxl__egc *egc,
                                         libxl__colo_save_state *css,
                                         int id);
/*
 * Do the following things when suspending primary vm:
 * 1. suspend primary vm
 * 2. do postsuspend
 * 3. read CHECKPOINT_SVM_SUSPENDED
 * 4. read secondary vm's dirty pages
 */
static void colo_suspend_primary_vm_done(libxl__egc *egc,
                                         libxl__domain_suspend_state *dsps,
                                         int ok);
static void colo_postsuspend_cb(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc);

static void libxl__colo_save_domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__domain_suspend_state *dsps = &dss->dsps;

    dsps->callback_common_done = colo_suspend_primary_vm_done;
    libxl__domain_suspend(egc, dsps);
}

static void colo_suspend_primary_vm_done(libxl__egc *egc,
                                         libxl__domain_suspend_state *dsps,
                                         int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(dsps, *dss, dsps);

    EGC_GC;

    if (rc) {
        LOGD(ERROR, dss->domid, "cannot suspend primary vm");
        goto out;
    }

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    cds->callback = colo_postsuspend_cb;
    libxl__checkpoint_devices_postsuspend(egc, cds);
    return;

out:
    dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void colo_postsuspend_cb(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOGD(ERROR, dss->domid, "postsuspend fails");
        goto out;
    }

    if (!css->svm_running) {
        rc = 0;
        goto out;
    }

    /*
     * read CHECKPOINT_SVM_SUSPENDED
     */
    css->callback = colo_read_svm_suspended_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void colo_read_svm_suspended_done(libxl__egc *egc,
                                         libxl__colo_save_state *css,
                                         int id)
{
    int ok = 0;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_SUSPENDED) {
        LOGD(ERROR, dss->domid, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_SUSPENDED);
        goto out;
    }

    if (!css->paused &&
        libxl__qmp_query_xen_replication_status(gc, dss->domid)) {
        LOGD(ERROR, dss->domid,
             "replication error occurs when primary vm is running");
        goto out;
    }

    ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}

/* ===================== colo: send tailbuf ========================== */

static void libxl__colo_save_domain_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    /* write emulator xenstore data, emulator context, and checkpoint end */
    css->callback = NULL;
    dss->sws.checkpoint_callback = colo_common_write_stream_done;
    libxl__stream_write_start_checkpoint(shs->egc, &dss->sws);
}

/* ===================== colo: resume primary vm ===================== */

/*
 * Do the following things when resuming primary vm:
 *  1. read CHECKPOINT_SVM_READY
 *  2. do preresume
 *  3. resume primary vm
 *  4. read CHECKPOINT_SVM_RESUMED
 */
static void colo_read_svm_ready_done(libxl__egc *egc,
                                     libxl__colo_save_state *css,
                                     int id);
static void colo_preresume_cb(libxl__egc *egc,
                              libxl__checkpoint_devices_state *cds,
                              int rc);
static void colo_read_svm_resumed_done(libxl__egc *egc,
                                       libxl__colo_save_state *css,
                                       int id);

static void libxl__colo_save_domain_resume_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    EGC_GC;

    /* read CHECKPOINT_SVM_READY */
    css->callback = colo_read_svm_ready_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);
}

static void colo_read_svm_ready_done(libxl__egc *egc,
                                     libxl__colo_save_state *css,
                                     int id)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_READY) {
        LOGD(ERROR, dss->domid, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_READY);
        goto out;
    }

    colo_proxy_preresume(&css->cps);

    css->svm_running = true;
    dss->cds.callback = colo_preresume_cb;
    libxl__checkpoint_devices_preresume(egc, &dss->cds);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_preresume_cb(libxl__egc *egc,
                              libxl__checkpoint_devices_state *cds,
                              int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOGD(ERROR, dss->domid, "preresume fails");
        goto out;
    }

    if (css->qdisk_used && !css->qdisk_setuped) {
        if (libxl__qmp_start_replication(gc, dss->domid, true)) {
            LOGD(ERROR, dss->domid, "starting replication fails");
            goto out;
        }
        css->qdisk_setuped = true;
    }

    if (!css->paused) {
        if (libxl__qmp_colo_do_checkpoint(gc, dss->domid)) {
            LOGD(ERROR, dss->domid, "doing checkpoint fails");
            goto out;
        }
    }

    /* Resumes the domain and the device model */
    if (libxl__domain_resume(gc, dss->domid, /* Fast Suspend */1)) {
        LOGD(ERROR, dss->domid, "cannot resume primary vm");
        goto out;
    }

    /*
     * The guest should be paused before doing colo because there is
     * no disk migration.
     */
    if (css->paused) {
        rc = libxl_domain_unpause(CTX, dss->domid);
        if (rc) {
            LOGD(ERROR, dss->domid, "cannot unpause primary vm");
            goto out;
        }
        css->paused = false;
    }

    /* read CHECKPOINT_SVM_RESUMED */
    css->callback = colo_read_svm_resumed_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_read_svm_resumed_done(libxl__egc *egc,
                                       libxl__colo_save_state *css,
                                       int id)
{
    int ok = 0;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_RESUMED) {
        LOGD(ERROR, dss->domid, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_RESUMED);
        goto out;
    }

    colo_proxy_postresume(&css->cps);

    ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}

/* ===================== colo: wait new checkpoint ===================== */

static void colo_start_new_checkpoint(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc);
static void colo_proxy_async_wait_for_checkpoint(libxl__colo_save_state *css);
static void colo_proxy_async_call_done(libxl__egc *egc,
                                       libxl__ev_child *child,
                                       int pid,
                                       int status);

static void colo_proxy_wait_for_checkpoint(libxl__egc *egc,
                                           libxl__colo_save_state *css)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    ASYNC_CALL(egc, dss->cds.ao, &css->child, css,
               colo_proxy_async_wait_for_checkpoint,
               colo_proxy_async_call_done);
}

static void colo_proxy_async_wait_for_checkpoint(libxl__colo_save_state *css)
{
    int req;

    req = colo_proxy_checkpoint(&css->cps, COLO_PROXY_CHECKPOINT_TIMEOUT);
    if (req < 0) {
        /* some error happens */
        _exit(1);
    } else {
        /* req == 0: no checkpoint is needed, do a checkpoint every 5s */
        /* req > 0: net packets is not consistent, we need to start a
         * checkpoint
         */
        _exit(0);
    }
}

static void colo_proxy_async_call_done(libxl__egc *egc,
                                       libxl__ev_child *child,
                                       int pid,
                                       int status)
{
    libxl__colo_save_state *css = CONTAINER_OF(child, *css, child);
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (status) {
        LOGD(ERROR, dss->domid, "failed to wait for new checkpoint");
        colo_start_new_checkpoint(egc, &dss->cds, ERROR_FAIL);
        return;
    }

    colo_start_new_checkpoint(egc, &dss->cds, 0);
}

/*
 * Do the following things:
 * 1. do commit
 * 2. wait for a new checkpoint
 * 3. write CHECKPOINT_NEW
 */
static void colo_device_commit_cb(libxl__egc *egc,
                                  libxl__checkpoint_devices_state *cds,
                                  int rc);

static void libxl__colo_save_domain_wait_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;
    libxl__egc *egc = dss->sws.shs.egc;

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    cds->callback = colo_device_commit_cb;
    libxl__checkpoint_devices_commit(egc, cds);
}

static void colo_device_commit_cb(libxl__egc *egc,
                                  libxl__checkpoint_devices_state *cds,
                                  int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOGD(ERROR, dss->domid, "commit fails");
        goto out;
    }

    colo_proxy_wait_for_checkpoint(egc, css);
    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_start_new_checkpoint(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    libxl_sr_checkpoint_state srcs = { .id = CHECKPOINT_NEW };

    if (rc)
        goto out;

    /* write CHECKPOINT_NEW */
    css->callback = NULL;
    dss->sws.checkpoint_callback = colo_common_write_stream_done;
    libxl__stream_write_checkpoint_state(egc, &dss->sws, &srcs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

/* ===================== colo: common callback ===================== */

static void colo_common_write_stream_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream,
                                          int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(stream, *dss, sws);
    int ok;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    EGC_GC;

    if (rc < 0) {
        /* TODO: it may be a internal error, but we don't know */
        LOGD(ERROR, dss->domid, "sending data fails");
        ok = 0;
        goto out;
    }

    if (!css->callback) {
        /* Everythins is OK */
        ok = 1;
        goto out;
    }

    css->callback(egc, css, 0);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}

static void colo_common_read_stream_done(libxl__egc *egc,
                                         libxl__stream_read_state *stream,
                                         int rc)
{
    libxl__colo_save_state *css = CONTAINER_OF(stream, *css, srs);
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    int ok;

    EGC_GC;

    if (rc < 0) {
        /* TODO: it may be a internal error, but we don't know */
        LOGD(ERROR, dss->domid, "reading data fails");
        ok = 0;
        goto out;
    }

    if (!css->callback) {
        /* Everythins is OK */
        ok = 1;
        goto out;
    }

    /* rc contains the id */
    css->callback(egc, css, rc);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}
