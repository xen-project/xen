/*
 * fdevent test helpr for the libxl event system
 */

#include "libxl_internal.h"

#include "libxl_test_fdevent.h"

typedef struct {
    libxl__ao *ao;
    libxl__ev_fd fd;
    libxl__ao_abortable abrt;
} libxl__test_fdevent;

static void fdevent_complete(libxl__egc *egc, libxl__test_fdevent *tfe,
                             int rc);

static void tfe_init(libxl__test_fdevent *tfe, libxl__ao *ao)
{
    tfe->ao = ao;
    libxl__ev_fd_init(&tfe->fd);
    libxl__ao_abortable_init(&tfe->abrt);
}

static void tfe_cleanup(libxl__gc *gc, libxl__test_fdevent *tfe)
{
    libxl__ev_fd_deregister(gc, &tfe->fd);
    libxl__ao_abortable_deregister(&tfe->abrt);
}

static void tfe_fd_cb(libxl__egc *egc, libxl__ev_fd *ev,
                      int fd, short events, short revents)
{
    libxl__test_fdevent *tfe = CONTAINER_OF(ev,*tfe,fd);
    STATE_AO_GC(tfe->ao);
    fdevent_complete(egc, tfe, 0);
}

static void tfe_abrt_cb(libxl__egc *egc, libxl__ao_abortable *abrt,
                        int rc)
{
    libxl__test_fdevent *tfe = CONTAINER_OF(abrt,*tfe,abrt);
    STATE_AO_GC(tfe->ao);
    fdevent_complete(egc, tfe, rc);
}

static void fdevent_complete(libxl__egc *egc, libxl__test_fdevent *tfe,
                             int rc)
{
    STATE_AO_GC(tfe->ao);
    tfe_cleanup(gc, tfe);
    libxl__ao_complete(egc, ao, rc);
}

int libxl_test_fdevent(libxl_ctx *ctx, int fd, short events,
                       libxl_asyncop_how *ao_how)
{
    int rc;
    libxl__test_fdevent *tfe;

    AO_CREATE(ctx, 0, ao_how);
    GCNEW(tfe);

    tfe_init(tfe, ao);

    rc = libxl__ev_fd_register(gc, &tfe->fd, tfe_fd_cb, fd, events);
    if (rc) goto out;

    tfe->abrt.ao = ao;
    tfe->abrt.callback = tfe_abrt_cb;
    rc = libxl__ao_abortable_register(&tfe->abrt);
    if (rc) goto out;

    return AO_INPROGRESS;

 out:
    tfe_cleanup(gc, tfe);
    return AO_CREATE_FAIL(rc);
}
