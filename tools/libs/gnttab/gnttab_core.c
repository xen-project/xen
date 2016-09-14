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

xengnttab_handle *xengnttab_open(xentoollog_logger *logger, unsigned open_flags)
{
    xengnttab_handle *xgt = malloc(sizeof(*xgt));
    int rc;

    if (!xgt) return NULL;

    xgt->fd = -1;
    xgt->logger = logger;
    xgt->logger_tofree  = NULL;

    if (!xgt->logger) {
        xgt->logger = xgt->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!xgt->logger) goto err;
    }

    rc = osdep_gnttab_open(xgt);
    if ( rc  < 0 ) goto err;

    return xgt;

err:
    osdep_gnttab_close(xgt);
    xtl_logger_destroy(xgt->logger_tofree);
    free(xgt);
    return NULL;
}

int xengnttab_close(xengnttab_handle *xgt)
{
    int rc;

    if ( !xgt )
        return 0;

    rc = osdep_gnttab_close(xgt);
    xtl_logger_destroy(xgt->logger_tofree);
    free(xgt);
    return rc;
}

int xengnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    return osdep_gnttab_set_max_grants(xgt, count);
}

void *xengnttab_map_grant_ref(xengnttab_handle *xgt,
                              uint32_t domid,
                              uint32_t ref,
                              int prot)
{
    return osdep_gnttab_grant_map(xgt, 1, 0, prot, &domid, &ref, -1, -1);
}

void *xengnttab_map_grant_refs(xengnttab_handle *xgt,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot)
{
    return osdep_gnttab_grant_map(xgt, count, 0, prot, domids, refs, -1, -1);
}

void *xengnttab_map_domain_grant_refs(xengnttab_handle *xgt,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot)
{
    return osdep_gnttab_grant_map(xgt, count, XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN,
                                  prot, &domid, refs, -1, -1);
}

void *xengnttab_map_grant_ref_notify(xengnttab_handle *xgt,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port)
{
    return osdep_gnttab_grant_map(xgt, 1, 0, prot,  &domid, &ref,
                                  notify_offset, notify_port);
}

int xengnttab_unmap(xengnttab_handle *xgt, void *start_address, uint32_t count)
{
    return osdep_gnttab_unmap(xgt, start_address, count);
}

int xengnttab_grant_copy(xengnttab_handle *xgt,
                         uint32_t count,
                         xengnttab_grant_copy_segment_t *segs)
{
    return osdep_gnttab_grant_copy(xgt, count, segs);
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
