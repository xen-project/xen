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
#include <assert.h>
#include <errno.h>

#include "private.h"

static int all_restrict_cb(Xentoolcore__Active_Handle *ah, domid_t domid) {
    xenforeignmemory_handle *fmem = CONTAINER_OF(ah, *fmem, tc_ah);

    if (fmem->fd < 0)
        /* just in case */
        return 0;

    return xenforeignmemory_restrict(fmem, domid);
}

xenforeignmemory_handle *xenforeignmemory_open(xentoollog_logger *logger,
                                               unsigned open_flags)
{
    xenforeignmemory_handle *fmem = malloc(sizeof(*fmem));
    int rc;

    if (!fmem) return NULL;

    fmem->fd = -1;
    fmem->logger = logger;
    fmem->logger_tofree = NULL;

    fmem->tc_ah.restrict_callback = all_restrict_cb;
    xentoolcore__register_active_handle(&fmem->tc_ah);

    if (!fmem->logger) {
        fmem->logger = fmem->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!fmem->logger) goto err;
    }

    rc = osdep_xenforeignmemory_open(fmem);
    if ( rc  < 0 ) goto err;

    return fmem;

err:
    xentoolcore__deregister_active_handle(&fmem->tc_ah);
    osdep_xenforeignmemory_close(fmem);
    xtl_logger_destroy(fmem->logger_tofree);
    free(fmem);
    return NULL;
}

int xenforeignmemory_close(xenforeignmemory_handle *fmem)
{
    int rc;

    if ( !fmem )
        return 0;

    xentoolcore__deregister_active_handle(&fmem->tc_ah);
    rc = osdep_xenforeignmemory_close(fmem);
    xtl_logger_destroy(fmem->logger_tofree);
    free(fmem);
    return rc;
}

void *xenforeignmemory_map2(xenforeignmemory_handle *fmem,
                            uint32_t dom, void *addr,
                            int prot, int flags, size_t num,
                            const xen_pfn_t arr[/*num*/], int err[/*num*/])
{
    void *ret;
    int *err_to_free = NULL;

    if ( err == NULL )
        err = err_to_free = malloc(num * sizeof(int));

    if ( err == NULL )
        return NULL;

    ret = osdep_xenforeignmemory_map(fmem, dom, addr, prot, flags, num, arr, err);

    if ( ret && err_to_free )
    {
        int i;

        for ( i = 0 ; i < num ; i++ )
        {
            if ( err[i] )
            {
                errno = -err[i];
                (void)osdep_xenforeignmemory_unmap(fmem, ret, num);
                ret = NULL;
                break;
            }
        }
    }

    free(err_to_free);

    return ret;
}

void *xenforeignmemory_map(xenforeignmemory_handle *fmem,
                           uint32_t dom, int prot,
                           size_t num,
                           const xen_pfn_t arr[/*num*/], int err[/*num*/])
{
    return xenforeignmemory_map2(fmem, dom, NULL, prot, 0, num, arr, err);
}

int xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                           void *addr, size_t num)
{
    return osdep_xenforeignmemory_unmap(fmem, addr, num);
}

int xenforeignmemory_restrict(xenforeignmemory_handle *fmem,
                              domid_t domid)
{
    return osdep_xenforeignmemory_restrict(fmem, domid);
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
