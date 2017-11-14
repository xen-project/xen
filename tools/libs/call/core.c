/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>

#include "private.h"

static int all_restrict_cb(Xentoolcore__Active_Handle *ah, domid_t domid) {
    xencall_handle *xcall = CONTAINER_OF(ah, *xcall, tc_ah);
    return xentoolcore__restrict_by_dup2_null(xcall->fd);
}

xencall_handle *xencall_open(xentoollog_logger *logger, unsigned open_flags)
{
    xencall_handle *xcall = malloc(sizeof(*xcall));
    int rc;

    if (!xcall) return NULL;

    xcall->fd = -1;
    xcall->tc_ah.restrict_callback = all_restrict_cb;
    xentoolcore__register_active_handle(&xcall->tc_ah);

    xcall->flags = open_flags;
    xcall->buffer_cache_nr = 0;

    xcall->buffer_total_allocations = 0;
    xcall->buffer_total_releases = 0;
    xcall->buffer_current_allocations = 0;
    xcall->buffer_maximum_allocations = 0;
    xcall->buffer_cache_hits = 0;
    xcall->buffer_cache_misses = 0;
    xcall->buffer_cache_toobig = 0;
    xcall->logger = logger;
    xcall->logger_tofree = NULL;

    if (!xcall->logger) {
        xcall->logger = xcall->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!xcall->logger) goto err;
    }

    rc = osdep_xencall_open(xcall);
    if ( rc  < 0 ) goto err;

    return xcall;

err:
    xentoolcore__deregister_active_handle(&xcall->tc_ah);
    osdep_xencall_close(xcall);
    xtl_logger_destroy(xcall->logger_tofree);
    free(xcall);
    return NULL;
}

int xencall_close(xencall_handle *xcall)
{
    int rc;

    if ( !xcall )
        return 0;

    xentoolcore__deregister_active_handle(&xcall->tc_ah);
    rc = osdep_xencall_close(xcall);
    buffer_release_cache(xcall);
    xtl_logger_destroy(xcall->logger_tofree);
    free(xcall);
    return rc;
}

int xencall0(xencall_handle *xcall, unsigned int op)
{
    privcmd_hypercall_t call = {
        .op = op,
    };

    return osdep_hypercall(xcall, &call);
}

int xencall1(xencall_handle *xcall, unsigned int op,
             uint64_t arg1)
{
    privcmd_hypercall_t call = {
        .op = op,
        .arg = { arg1 },
    };

    return osdep_hypercall(xcall, &call);
}

int xencall2(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2)
{
    privcmd_hypercall_t call = {
        .op = op,
        .arg = { arg1, arg2 },
    };

    return osdep_hypercall(xcall, &call);
}

int xencall3(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    privcmd_hypercall_t call = {
        .op = op,
        .arg = { arg1, arg2, arg3},
    };

    return osdep_hypercall(xcall, &call);
}

int xencall4(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3,
             uint64_t arg4)
{
    privcmd_hypercall_t call = {
        .op = op,
        .arg = { arg1, arg2, arg3, arg4 },
    };

    return osdep_hypercall(xcall, &call);
}

int xencall5(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3,
             uint64_t arg4, uint64_t arg5)
{
    privcmd_hypercall_t call = {
        .op = op,
        .arg = { arg1, arg2, arg3, arg4, arg5 },
    };

    return osdep_hypercall(xcall, &call);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
