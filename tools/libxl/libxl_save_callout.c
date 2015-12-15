/*
 * Copyright (C) 2012      Citrix Ltd.
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

/* stream_fd is as from the caller (eventually, the application).
 * It may be 0, 1 or 2, in which case we need to dup it elsewhere.
 * The actual fd value is not included in the supplied argnums; rather
 * it will be automatically supplied by run_helper as the 2nd argument.
 *
 * preserve_fds are fds that the caller is intending to pass to the
 * helper so which need cloexec clearing.  They may not be 0, 1 or 2.
 * An entry may be -1 in which case it will be ignored.
 */
static void run_helper(libxl__egc *egc, libxl__save_helper_state *shs,
                       const char *mode_arg,
                       int stream_fd, int back_channel_fd,
                       const int *preserve_fds, int num_preserve_fds,
                       const unsigned long *argnums, int num_argnums);

static void helper_failed(libxl__egc*, libxl__save_helper_state *shs, int rc);
static void helper_stop(libxl__egc *egc, libxl__ao_abortable*, int rc);
static void helper_stdout_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                   int fd, short events, short revents);
static void helper_exited(libxl__egc *egc, libxl__ev_child *ch,
                          pid_t pid, int status);
static void helper_done(libxl__egc *egc, libxl__save_helper_state *shs);

/*----- entrypoints -----*/

void libxl__xc_domain_restore(libxl__egc *egc, libxl__domain_create_state *dcs,
                              libxl__save_helper_state *shs,
                              int hvm, int pae, int superpages)
{
    STATE_AO_GC(dcs->ao);

    /* Convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    const int restore_fd = dcs->libxc_fd;
    const int send_back_fd = dcs->send_back_fd;
    libxl__domain_build_state *const state = &dcs->build_state;

    unsigned cbflags =
        libxl__srm_callout_enumcallbacks_restore(&shs->callbacks.restore.a);

    const unsigned long argnums[] = {
        domid,
        state->store_port,
        state->store_domid, state->console_port,
        state->console_domid,
        hvm, pae, superpages,
        cbflags, dcs->restore_params.checkpointed_stream,
    };

    shs->ao = ao;
    shs->domid = domid;
    shs->recv_callback = libxl__srm_callout_received_restore;
    if (dcs->restore_params.checkpointed_stream ==
        LIBXL_CHECKPOINTED_STREAM_COLO)
        shs->completion_callback = libxl__colo_restore_teardown;
    else
        shs->completion_callback = libxl__xc_domain_restore_done;
    shs->caller_state = dcs;
    shs->need_results = 1;

    run_helper(egc, shs, "--restore-domain", restore_fd, send_back_fd, 0, 0,
               argnums, ARRAY_SIZE(argnums));
}

void libxl__xc_domain_save(libxl__egc *egc, libxl__domain_save_state *dss,
                           libxl__save_helper_state *shs)
{
    STATE_AO_GC(dss->ao);

    unsigned cbflags =
        libxl__srm_callout_enumcallbacks_save(&shs->callbacks.save.a);

    const unsigned long argnums[] = {
        dss->domid, 0, 0, dss->xcflags, dss->hvm,
        cbflags, dss->checkpointed_stream,
    };

    shs->ao = ao;
    shs->domid = dss->domid;
    shs->recv_callback = libxl__srm_callout_received_save;
    shs->completion_callback = libxl__xc_domain_save_done;
    shs->caller_state = dss;
    shs->need_results = 0;

    run_helper(egc, shs, "--save-domain", dss->fd, dss->recv_fd,
               NULL, 0,
               argnums, ARRAY_SIZE(argnums));
    return;
}


void libxl__xc_domain_saverestore_async_callback_done(libxl__egc *egc,
                           libxl__save_helper_state *shs, int return_value)
{
    shs->egc = egc;
    libxl__srm_callout_sendreply(return_value, shs);
    shs->egc = 0;
}

void libxl__save_helper_init(libxl__save_helper_state *shs)
{
    libxl__ao_abortable_init(&shs->abrt);
    libxl__ev_fd_init(&shs->readable);
    libxl__ev_child_init(&shs->child);
}

/*----- helper execution -----*/

/* This function can not fail. */
static int dup_cloexec(libxl__gc *gc, int fd, const char *what)
{
    int dup_fd = fd;

    if (fd <= 2) {
        dup_fd = dup(fd);
        if (dup_fd < 0) {
            LOGE(ERROR,"dup %s", what);
            exit(-1);
        }
    }
    libxl_fd_set_cloexec(CTX, dup_fd, 0);

    return dup_fd;
}

/*
 * Both save and restore share four parameters:
 * 1) Path to libxl-save-helper.
 * 2) --[restore|save]-domain.
 * 3) stream file descriptor.
 * 4) back channel file descriptor.
 * n) save/restore specific parameters.
 * 5) A \0 at the end.
 */
#define HELPER_NR_ARGS 5
static void run_helper(libxl__egc *egc, libxl__save_helper_state *shs,
                       const char *mode_arg,
                       int stream_fd, int back_channel_fd,
                       const int *preserve_fds, int num_preserve_fds,
                       const unsigned long *argnums, int num_argnums)
{
    STATE_AO_GC(shs->ao);
    const char *args[HELPER_NR_ARGS + num_argnums];
    const char **arg = args;
    int i, rc;

    /* Resources we must free */
    libxl__carefd *childs_pipes[2] = { 0,0 };

    /* Convenience aliases */
    const uint32_t domid = shs->domid;

    shs->rc = 0;
    shs->completed = 0;
    shs->pipes[0] = shs->pipes[1] = 0;
    libxl__save_helper_init(shs);

    shs->abrt.ao = shs->ao;
    shs->abrt.callback = helper_stop;
    rc = libxl__ao_abortable_register(&shs->abrt);
    if (rc) goto out;

    shs->stdin_what = GCSPRINTF("domain %"PRIu32" save/restore helper"
                                " stdin pipe", domid);
    shs->stdout_what = GCSPRINTF("domain %"PRIu32" save/restore helper"
                                 " stdout pipe", domid);

    *arg++ = getenv("LIBXL_SAVE_HELPER") ?: LIBEXEC_BIN "/" "libxl-save-helper";
    *arg++ = mode_arg;
    const char **stream_fd_arg = arg++;
    const char **back_channel_fd_arg = arg++;
    for (i=0; i<num_argnums; i++)
        *arg++ = GCSPRINTF("%lu", argnums[i]);
    *arg++ = 0;
    assert(arg == args + ARRAY_SIZE(args));

    libxl__carefd_begin();
    int childfd;
    for (childfd=0; childfd<2; childfd++) {
        /* Setting up the pipe for the child's fd childfd */
        int fds[2];
        if (libxl_pipe(CTX,fds)) {
            rc = ERROR_FAIL;
            libxl__carefd_unlock();
            goto out;
        }
        int childs_end = childfd==0 ? 0 /*read*/  : 1 /*write*/;
        int our_end    = childfd==0 ? 1 /*write*/ : 0 /*read*/;
        childs_pipes[childfd] = libxl__carefd_record(CTX, fds[childs_end]);
        shs->pipes[childfd] =   libxl__carefd_record(CTX, fds[our_end]);
    }
    libxl__carefd_unlock();

    pid_t pid = libxl__ev_child_fork(gc, &shs->child, helper_exited);
    if (!pid) {
        stream_fd = dup_cloexec(gc, stream_fd, "migration stream fd");
        *stream_fd_arg = GCSPRINTF("%d", stream_fd);

        if (back_channel_fd >= 0)
            back_channel_fd = dup_cloexec(gc, back_channel_fd,
                                          "migration back channel fd");
        *back_channel_fd_arg = GCSPRINTF("%d", back_channel_fd);

        for (i=0; i<num_preserve_fds; i++)
            if (preserve_fds[i] >= 0) {
                assert(preserve_fds[i] > 2);
                libxl_fd_set_cloexec(CTX, preserve_fds[i], 0);
            }

        libxl__exec(gc,
                    libxl__carefd_fd(childs_pipes[0]),
                    libxl__carefd_fd(childs_pipes[1]),
                    -1,
                    args[0], (char**)args, 0);
    }

    libxl__carefd_close(childs_pipes[0]);
    libxl__carefd_close(childs_pipes[1]);

    rc = libxl__ev_fd_register(gc, &shs->readable, helper_stdout_readable,
                               libxl__carefd_fd(shs->pipes[1]), POLLIN|POLLPRI);
    if (rc) goto out;
    return;

 out:
    libxl__carefd_close(childs_pipes[0]);
    libxl__carefd_close(childs_pipes[1]);
    helper_failed(egc, shs, rc);;
}

static void helper_failed(libxl__egc *egc, libxl__save_helper_state *shs,
                          int rc)
{
    STATE_AO_GC(shs->ao);

    if (!shs->rc)
        shs->rc = rc;

    libxl__ev_fd_deregister(gc, &shs->readable);

    if (!libxl__save_helper_inuse(shs)) {
        helper_done(egc, shs);
        return;
    }

    libxl__kill(gc, shs->child.pid, SIGKILL, "save/restore helper");
}

static void helper_stop(libxl__egc *egc, libxl__ao_abortable *abrt, int rc)
{
    libxl__save_helper_state *shs = CONTAINER_OF(abrt, *shs, abrt);
    STATE_AO_GC(shs->ao);

    if (!libxl__save_helper_inuse(shs)) {
        helper_failed(egc, shs, rc);
        return;
    }

    if (!shs->rc)
        shs->rc = rc;

    libxl__kill(gc, shs->child.pid, SIGTERM, "save/restore helper");
}

void libxl__save_helper_abort(libxl__egc *egc,
                              libxl__save_helper_state *shs)
{
    helper_stop(egc, &shs->abrt, ERROR_FAIL);
}

static void helper_stdout_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                   int fd, short events, short revents)
{
    libxl__save_helper_state *shs = CONTAINER_OF(ev, *shs, readable);
    STATE_AO_GC(shs->ao);
    int rc, errnoval;

    if (revents & (POLLERR|POLLPRI)) {
        LOG(ERROR, "%s signaled POLLERR|POLLPRI (%#x)",
            shs->stdout_what, revents);
        rc = ERROR_FAIL;
 out:
        /* this is here because otherwise we bypass the decl of msg[] */
        helper_failed(egc, shs, rc);
        return;
    }

    uint16_t msglen;
    errnoval = libxl_read_exactly(CTX, fd, &msglen, sizeof(msglen),
                                  shs->stdout_what, "ipc msg header");
    if (errnoval) { rc = ERROR_FAIL; goto out; }

    unsigned char msg[msglen];
    errnoval = libxl_read_exactly(CTX, fd, msg, msglen,
                                  shs->stdout_what, "ipc msg body");
    if (errnoval) { rc = ERROR_FAIL; goto out; }

    shs->egc = egc;
    shs->recv_callback(msg, msglen, shs);
    shs->egc = 0;
    return;
}

static void helper_exited(libxl__egc *egc, libxl__ev_child *ch,
                          pid_t pid, int status)
{
    libxl__save_helper_state *shs = CONTAINER_OF(ch, *shs, child);
    STATE_AO_GC(shs->ao);

    /* Convenience aliases */
    const uint32_t domid = shs->domid;

    const char *what =
        GCSPRINTF("domain %"PRIu32" save/restore helper", domid);

    if (status) {
        libxl_report_child_exitstatus(CTX, XTL_ERROR, what, pid, status);
        if (!shs->rc)
            shs->rc = ERROR_FAIL;
    }

    if (shs->need_results) {
        if (!shs->rc) {
            LOG(ERROR,"%s exited without providing results",what);
            shs->rc = ERROR_FAIL;
        }
    }

    if (!shs->completed) {
        if (!shs->rc) {
            LOG(ERROR,"%s exited without signaling completion",what);
            shs->rc = ERROR_FAIL;
        }
    }

    helper_done(egc, shs);
    return;
}

static void helper_done(libxl__egc *egc, libxl__save_helper_state *shs)
{
    STATE_AO_GC(shs->ao);

    libxl__ao_abortable_deregister(&shs->abrt);
    libxl__ev_fd_deregister(gc, &shs->readable);
    libxl__carefd_close(shs->pipes[0]);  shs->pipes[0] = 0;
    libxl__carefd_close(shs->pipes[1]);  shs->pipes[1] = 0;
    assert(!libxl__save_helper_inuse(shs));

    shs->egc = egc;
    shs->completion_callback(egc, shs->caller_state,
                             shs->rc, shs->retval, shs->errnoval);
    shs->egc = 0;
}

/*----- generic helpers for the autogenerated code -----*/

const libxl__srm_save_autogen_callbacks*
libxl__srm_callout_get_callbacks_save(void *user)
{
    libxl__save_helper_state *shs = user;
    return &shs->callbacks.save.a;
}

const libxl__srm_restore_autogen_callbacks*
libxl__srm_callout_get_callbacks_restore(void *user)
{
    libxl__save_helper_state *shs = user;
    return &shs->callbacks.restore.a;
}

void libxl__srm_callout_sendreply(int r, void *user)
{
    libxl__save_helper_state *shs = user;
    libxl__egc *egc = shs->egc;
    STATE_AO_GC(shs->ao);
    int errnoval;

    errnoval = libxl_write_exactly(CTX, libxl__carefd_fd(shs->pipes[0]),
                                   &r, sizeof(r), shs->stdin_what,
                                   "callback return value");
    if (errnoval)
        helper_failed(egc, shs, ERROR_FAIL);
}

void libxl__srm_callout_callback_log(uint32_t level, uint32_t errnoval,
                  const char *context, const char *formatted, void *user)
{
    libxl__save_helper_state *shs = user;
    STATE_AO_GC(shs->ao);
    xtl_log(CTX->lg, level, errnoval, context, "%s", formatted);
}

void libxl__srm_callout_callback_progress(const char *context,
                   const char *doing_what, unsigned long done,
                   unsigned long total, void *user)
{
    libxl__save_helper_state *shs = user;
    STATE_AO_GC(shs->ao);
    xtl_progress(CTX->lg, context, doing_what, done, total);
}

int libxl__srm_callout_callback_complete(int retval, int errnoval,
                                         void *user)
{
    libxl__save_helper_state *shs = user;
    STATE_AO_GC(shs->ao);

    shs->completed = 1;
    shs->retval = retval;
    shs->errnoval = errnoval;
    libxl__ev_fd_deregister(gc, &shs->readable);
    return 0;
}
