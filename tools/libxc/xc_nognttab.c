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
 */

#include <stdlib.h>

#include "xc_private.h"

int osdep_gnttab_open(xc_gnttab *xgt)
{
    return -1;
}

int osdep_gnttab_close(xc_gnttab *xgt)
{
    return 0;
}

int xc_gnttab_set_max_grants(xc_gnttab *xgt, uint32_t count)
{
    abort();
}

void *osdep_gnttab_grant_map(xc_gnttab *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port)
{
    abort();
}

int xc_gnttab_munmap(xc_gnttab *xgt, void *start_address, uint32_t count)
{
    abort();
}
