/*
 * Copyright (C) 2014      Citrix Ltd.
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

/*
 * Infrastructure for converting a legacy migration stream into a
 * libxl v2 stream.
 *
 * This is done by fork()ing the python conversion script, which takes
 * in a legacy stream, and puts out a suitably-formatted v2 stream.
 */

static void helper_exited(libxl__egc *egc, libxl__ev_child *ch,
                          pid_t pid, int status);
static void helper_stop(libxl__egc *egc, libxl__ao_abortable *abrt, int rc);
static void helper_done(libxl__egc *egc,
                        libxl__conversion_helper_state *chs);

/*----- Entrypoints -----*/

void libxl__conversion_helper_init(libxl__conversion_helper_state *chs)
{
    assert(chs->ao);

    chs->v2_carefd = NULL;
    chs->rc = 0;
    libxl__ao_abortable_init(&chs->abrt);
    libxl__ev_child_init(&chs->child);
}

int libxl__convert_legacy_stream(libxl__egc *egc,
                                 libxl__conversion_helper_state *chs)
{
    STATE_AO_GC(chs->ao);
    libxl__carefd *child_in = NULL, *child_out = NULL;
    int rc = 0;

    chs->abrt.ao = chs->ao;
    chs->abrt.callback = helper_stop;
    rc = libxl__ao_abortable_register(&chs->abrt);
    if (rc) goto err;

    libxl__carefd_begin();
    int fds[2];
    if (libxl_pipe(CTX, fds)) {
        rc = ERROR_FAIL;
        libxl__carefd_unlock();
        goto err;
    }
    child_out = libxl__carefd_record(CTX, fds[0]);
    child_in  = libxl__carefd_record(CTX, fds[1]);
    libxl__carefd_unlock();

    pid_t pid = libxl__ev_child_fork(gc, &chs->child, helper_exited);
    if (!pid) {
        char * const args[] =
        {
            getenv("LIBXL_CONVERT_HELPER") ?:
                LIBEXEC_BIN "/convert-legacy-stream",
            "--in",     GCSPRINTF("%d", chs->legacy_fd),
            "--out",    GCSPRINTF("%d", fds[1]),
            /*
             * The width calculation is an assumption for the common
             * case.  The conversion script needs to know the width of
             * the toolstack which saved the legacy stream.
             *
             * In the overwhelming majority of cases, the width of the
             * saving toolstack will be the same as our current
             * width.  To avoid extending the libxl API with a
             * parameter intended to disappear shortly, this option
             * has not been exposed to the caller.
             *
             * If more complicated conversion is required, the
             * conversion script can be instantiated manually, which
             * will bypass all of this conversion logic.
             */
            "--width",  sizeof(unsigned long) == 8 ? "64" : "32",

            "--guest",  chs->hvm ? "hvm" : "pv",
            "--format", "libxl",
            /* "--verbose", */
            NULL,
        };

        libxl_fd_set_cloexec(CTX, chs->legacy_fd, 0);
        libxl_fd_set_cloexec(CTX, libxl__carefd_fd(child_in), 0);

        libxl__exec(gc,
                    -1, -1, -1,
                    args[0], args, NULL);
    }

    libxl__carefd_close(child_in);
    chs->v2_carefd = child_out;

    assert(!rc);
    return rc;

 err:
    libxl__ao_abortable_deregister(&chs->abrt);
    assert(rc);
    return rc;
}

void libxl__conversion_helper_abort(libxl__egc *egc,
                                    libxl__conversion_helper_state *chs,
                                    int rc)
{
    STATE_AO_GC(chs->ao);
    assert(rc);

    if (libxl__conversion_helper_inuse(chs)) {

        if (!chs->rc)
            chs->rc = rc;

        libxl__kill(gc, chs->child.pid, SIGTERM, "conversion helper");
    }
}

/*----- State handling -----*/

static void helper_stop(libxl__egc *egc, libxl__ao_abortable *abrt, int rc)
{
    libxl__conversion_helper_state *chs = CONTAINER_OF(abrt, *chs, abrt);
    STATE_AO_GC(chs->ao);

    libxl__conversion_helper_abort(egc, chs, rc);
}

static void helper_exited(libxl__egc *egc, libxl__ev_child *ch,
                          pid_t pid, int status)
{
    libxl__conversion_helper_state *chs = CONTAINER_OF(ch, *chs, child);
    STATE_AO_GC(chs->ao);

    if (status) {
        libxl_report_child_exitstatus(
            CTX, chs->rc ? XTL_DEBUG : XTL_ERROR,
            "conversion helper", pid, status);

        if (!chs->rc)
            chs->rc = ERROR_FAIL;
    }

    helper_done(egc, chs);
}

static void helper_done(libxl__egc *egc,
                        libxl__conversion_helper_state *chs)
{
    STATE_AO_GC(chs->ao);

    assert(!libxl__conversion_helper_inuse(chs));

    libxl__ao_abortable_deregister(&chs->abrt);

    chs->completion_callback(egc, chs, chs->rc);
}
