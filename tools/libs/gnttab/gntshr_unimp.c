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
    return NULL;
}

int xengntshr_close(xengntshr_handle *xgs)
{
    return 0;
}

void *xengntshr_share_pages(xengntshr_handle *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable)
{
    abort();
}

void *xengntshr_share_page_notify(xengntshr_handle *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port)
{
    abort();
}

int xengntshr_unshare(xengntshr_handle *xgs, void *start_address, uint32_t count)
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
