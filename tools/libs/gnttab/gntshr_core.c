/******************************************************************************
 *
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 *
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
 *
 * Split out from xc_gnttab.c
 */

#include <stdlib.h>

#include "private.h"

xengntshr_handle *xengntshr_open(xentoollog_logger *logger, unsigned open_flags)
{
    xengntshr_handle *xgs = malloc(sizeof(*xgs));
    int rc;

    if (!xgs) return NULL;

    xgs->fd = -1;
    xgs->logger = logger;
    xgs->logger_tofree  = NULL;

    if (!xgs->logger) {
        xgs->logger = xgs->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!xgs->logger) goto err;
    }

    rc = osdep_gntshr_open(xgs);
    if ( rc  < 0 ) goto err;

    return xgs;

err:
    osdep_gntshr_close(xgs);
    xtl_logger_destroy(xgs->logger_tofree);
    free(xgs);
    return NULL;
}

int xengntshr_close(xengntshr_handle *xgs)
{
    int rc;

    if ( !xgs )
        return 0;

    rc = osdep_gntshr_close(xgs);
    xtl_logger_destroy(xgs->logger_tofree);
    free(xgs);
    return rc;
}
void *xengntshr_share_pages(xengntshr_handle *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable)
{
    return osdep_gntshr_share_pages(xcg, domid, count, refs, writable, -1, -1);
}

void *xengntshr_share_page_notify(xengntshr_handle *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port)
{
    return osdep_gntshr_share_pages(xcg, domid, 1, ref, writable,
                                    notify_offset, notify_port);
}

int xengntshr_unshare(xengntshr_handle *xgs, void *start_address, uint32_t count)
{
    return osdep_gntshr_unshare(xgs, start_address, count);
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
