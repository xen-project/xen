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
                       int stream_fd,
                       const int *preserve_fds, int num_preserve_fds,
                       const unsigned long *argnums, int num_argnums);

static void helper_failed(libxl__egc*, libxl__save_helper_state *shs, int rc);
static void helper_stdout_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                   int fd, short events, short revents);
static void helper_exited(libxl__egc *egc, libxl__ev_child *ch,
                          pid_t pid, int status);
static void helper_done(libxl__egc *egc, libxl__save_helper_state *shs);

/*----- entrypoints -----*/

void libxl__xc_domain_restore(libxl__egc *egc, libxl__domain_create_state *dcs,
                              int hvm, int pae, int superpages,
                              int no_incr_generationid)
{
    STATE_AO_GC(dcs->ao);

    /* Convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    const int restore_fd = dcs->restore_fd;
    libxl__domain_build_state *const state = &dcs->build_state;

    unsigned cbflags = libxl__srm_callout_enumcallbacks_restore
        (&dcs->shs.callbacks.restore.a);

    const unsigned long argnums[] = {
        domid,
        state->store_port,
        state->store_domid, state->console_port,
        state->console_domid,
        hvm, pae, superpages, no_incr_generationid,
        cbflags, dcs->checkpointed_stream,
    };

    dcs->shs.ao = ao;
    dcs->shs.domid = domid;
    dcs->shs.recv_callback = libxl__srm_callout_received_restore;
    dcs->shs.completion_callback = libxl__xc_domain_restore_done;
    dcs->shs.caller_state = dcs;
    dcs->shs.need_results = 1;
    dcs->shs.toolstack_data_file = 0;

    run_helper(egc, &dcs->shs, "--restore-domain", restore_fd, 0,0,
               argnums, ARRAY_SIZE(argnums));
}

void libxl__xc_domain_save(libxl__egc *egc, libxl__domain_suspend_state *dss,
                           unsigned long vm_generationid_addr)
{
    STATE_AO_GC(dss->ao);
    int r, rc, toolstack_data_fd = -1;
    uint32_t toolstack_data_len = 0;

    /* Resources we need to free */
    uint8_t *toolstack_data_buf = 0;

    unsigned cbflags = libxl__srm_callout_enumcallbacks_save
        (&dss->shs.callbacks.save.a);

    if (dss->shs.callbacks.save.toolstack_save) {
        r = dss->shs.callbacks.save.toolstack_save
            (dss->domid, &toolstack_data_buf, &toolstack_data_len, dss);
        if (r) { rc = ERROR_FAIL; goto out; }

        dss->shs.toolstack_data_file = tmpfile();
        if (!dss->shs.toolstack_data_file) {
            LOGE(ERROR, "cannot create toolstack data tmpfile");
            rc = ERROR_FAIL;
            goto out;
        }
        toolstack_data_fd = fileno(dss->shs.toolstack_data_file);

        r = libxl_write_exactly(CTX, toolstack_data_fd,
                                toolstack_data_buf, toolstack_data_len,
                                "toolstack data tmpfile", 0);
        if (r) { rc = ERROR_FAIL; goto out; }
    }

    const unsigned long argnums[] = {
        dss->domid, 0, 0, dss->xcflags, dss->hvm, vm_generationid_addr,
        toolstack_data_fd, toolstack_data_len,
        cbflags,
    };

    dss->shs.ao = ao;
    dss->shs.domid = dss->domid;
    dss->shs.recv_callback = libxl__srm_callout_received_save;
    dss->shs.completion_callback = libxl__xc_domain_save_done;
    dss->shs.caller_state = dss;
    dss->shs.need_results = 0;

    free(toolstack_data_buf);

    run_helper(egc, &dss->shs, "--save-domain", dss->fd,
               &toolstack_data_fd, 1,
               argnums, ARRAY_SIZE(argnums));
    return;

 out:
    free(toolstack_data_buf);
    if (dss->shs.toolstack_data_file) fclose(dss->shs.toolstack_data_file);

    libxl__xc_domain_save_done(egc, dss, rc, 0, 0);
}


void libxl__xc_domain_saverestore_async_callback_done(libxl__egc *egc,
                           libxl__save_helper_state *shs, int return_value)
{
    shs->egc = egc;
    libxl__srm_callout_sendreply(return_value, shs);
    shs->egc = 0;
}

/*----- helper execution -----*/

static void run_helper(libxl__egc *egc, libxl__save_helper_state *shs,
                       const char *mode_arg, int stream_fd,
                       const int *preserve_fds, int num_preserve_fds,
                       const unsigned long *argnums, int num_argnums)
{
    STATE_AO_GC(shs->ao);
    const char *args[4 + num_argnums];
    const char **arg = args;
    int i, rc;

    /* Resources we must free */
    libxl__carefd *childs_pipes[2] = { 0,0 };

    /* Convenience aliases */
    const uint32_t domid = shs->domid;

    shs->rc = 0;
    shs->completed = 0;
    shs->pipes[0] = shs->pipes[1] = 0;
    libxl__ev_fd_init(&shs->readable);
    libxl__ev_child_init(&shs->child);

    shs->stdin_what = GCSPRINTF("domain %"PRIu32" save/restore helper"
                                " stdin pipe", domid);
    shs->stdout_what = GCSPRINTF("domain %"PRIu32" save/restore helper"
                                 " stdout pipe", domid);

    *arg++ = getenv("LIBXL_SAVE_HELPER") ?: PRIVATE_BINDIR "/" "libxl-save-helper";
    *arg++ = mode_arg;
    const char **stream_fd_arg = arg++;
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
        if (stream_fd <= 2) {
            stream_fd = dup(stream_fd);
            if (stream_fd < 0) {
                LOGE(ERROR,"dup migration stream fd");
                exit(-1);
            }
        }
        libxl_fd_set_cloexec(CTX, stream_fd, 0);
        *stream_fd_arg = GCSPRINTF("%d", stream_fd);

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

    if (!libxl__ev_child_inuse(&shs->child)) {
        helper_done(egc, shs);
        return;
    }

    int r = kill(shs->child.pid, SIGKILL);
    if (r) LOGE(WARN, "failed to kill save/restore helper [%lu]",
                (unsigned long)shs->child.pid);
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
        shs->rc = ERROR_FAIL;
    }

    if (shs->need_results) {
        if (!shs->rc)
            LOG(ERROR,"%s exited without providing results",what);
        shs->rc = ERROR_FAIL;
    }

    if (!shs->completed) {
        if (!shs->rc)
            LOG(ERROR,"%s exited without signaling completion",what);
        shs->rc = ERROR_FAIL;
    }

    helper_done(egc, shs);
    return;
}

static void helper_done(libxl__egc *egc, libxl__save_helper_state *shs)
{
    STATE_AO_GC(shs->ao);

    libxl__ev_fd_deregister(gc, &shs->readable);
    libxl__carefd_close(shs->pipes[0]);  shs->pipes[0] = 0;
    libxl__carefd_close(shs->pipes[1]);  shs->pipes[1] = 0;
    assert(!libxl__ev_child_inuse(&shs->child));
    if (shs->toolstack_data_file) fclose(shs->toolstack_data_file);

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
