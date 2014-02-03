/*
 * timedereg test case for the libxl event system
 *
 * To run this test:
 *    ./test_timedereg
 * Success:
 *    program takes a few seconds, prints some debugging output and exits 0
 * Failure:
 *    crash
 *
 * set up [0]-group timeouts 0 1 2
 * wait for timeout 1 to occur
 * deregister 0 and 2.  1 is supposed to be deregistered already
 * register [1]-group 0 1 2
 * deregister 1 (should be a no-op)
 * wait for [1]-group 0 1 2 in turn
 * on final callback assert that all have been deregistered
 */

#include "libxl_internal.h"

#include "libxl_test_timedereg.h"

#define NTIMES 3
static const int ms[2][NTIMES] = { { 2000,1000,2000 }, { 1000,2000,3000 } };
static libxl__ev_time et[2][NTIMES];
static libxl__ao *tao;
static int seq;

static void occurs(libxl__egc *egc, libxl__ev_time *ev,
                   const struct timeval *requested_abs);

static void regs(libxl__gc *gc, int j)
{
    int rc, i;
    LOG(DEBUG,"regs(%d)", j);
    for (i=0; i<NTIMES; i++) {
        rc = libxl__ev_time_register_rel(gc, &et[j][i], occurs, ms[j][i]);
        assert(!rc);
    }    
}

int libxl_test_timedereg(libxl_ctx *ctx, libxl_asyncop_how *ao_how)
{
    int i;
    AO_CREATE(ctx, 0, ao_how);

    tao = ao;

    for (i=0; i<NTIMES; i++) {
        libxl__ev_time_init(&et[0][i]);
        libxl__ev_time_init(&et[1][i]);
    }

    regs(gc, 0);

    return AO_INPROGRESS;
}

static void occurs(libxl__egc *egc, libxl__ev_time *ev,
                   const struct timeval *requested_abs)
{
    EGC_GC;
    int i;

    int off = ev - &et[0][0];
    LOG(DEBUG,"occurs[%d][%d] seq=%d", off/NTIMES, off%NTIMES, seq);

    switch (seq) {
    case 0:
        assert(ev == &et[0][1]);
        libxl__ev_time_deregister(gc, &et[0][0]);
        libxl__ev_time_deregister(gc, &et[0][2]);
        regs(gc, 1);
        libxl__ev_time_deregister(gc, &et[0][1]);
        break;

    case 1:
    case 2:
        assert(ev == &et[1][seq-1]);
        break;
        
    case 3:
        assert(ev == &et[1][2]);
        for (i=0; i<NTIMES; i++) {
            assert(!libxl__ev_time_isregistered(&et[0][i]));
            assert(!libxl__ev_time_isregistered(&et[1][i]));
        }
        libxl__ao_complete(egc, tao, 0);
        return;

    default:
        abort();
    }

    seq++;
}
