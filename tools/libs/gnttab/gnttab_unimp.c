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
    return NULL;
}

int xengnttab_close(xengnttab_handle *xgt)
{
    return 0;
}

int xengnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    abort();
}

void *xengnttab_map_grant_ref(xengnttab_handle *xgt,
                              uint32_t domid,
                              uint32_t ref,
                              int prot)
{
    abort();
}

void *xengnttab_map_grant_refs(xengnttab_handle *xgt,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot)
{
    abort();
}

void *xengnttab_map_domain_grant_refs(xengnttab_handle *xgt,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot)
{
    abort();
}

void *xengnttab_map_grant_ref_notify(xengnttab_handle *xgt,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port)
{
    abort();
}

int xengnttab_unmap(xengnttab_handle *xgt, void *start_address, uint32_t count)
{
    abort();
}

int xengnttab_grant_copy(xengnttab_handle *xgt,
                         uint32_t count,
                         xengnttab_grant_copy_segment_t *segs)
{
    abort();
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
