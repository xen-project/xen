/*
 *
 * Copyright 2007-2008 Samuel Thibault <samuel.thibault@eu.citrix.com>.
 * All rights reserved.
 * Use is subject to license terms.
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
 * Splitfrom xc_minios.c
 */

#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/lib.h>

#include <mini-os/gntmap.h>
#include <sys/mman.h>

#include <errno.h>
#include <unistd.h>

#include "private.h"

void minios_gnttab_close_fd(int fd);

int osdep_gnttab_open(xengnttab_handle *xgt)
{
    int fd = alloc_fd(FTYPE_GNTMAP);
    if ( fd == -1 )
        return -1;
    gntmap_init(&files[fd].gntmap);
    xgt->fd = fd;
    return 0;
}

int osdep_gnttab_close(xengnttab_handle *xgt)
{
    if ( xgt->fd == -1 )
        return 0;

    return close(xgt->fd);
}

void minios_gnttab_close_fd(int fd)
{
    gntmap_fini(&files[fd].gntmap);
    files[fd].type = FTYPE_NONE;
}

void *osdep_gnttab_grant_map(xengnttab_handle *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port)
{
    int fd = xgt->fd;
    int stride = 1;
    if (flags & XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN)
        stride = 0;
    if (notify_offset != -1 || notify_port != -1) {
        errno = ENOSYS;
        return NULL;
    }
    return gntmap_map_grant_refs(&files[fd].gntmap,
                                 count, domids, stride,
                                 refs, prot & PROT_WRITE);
}

int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count)
{
    int fd = xgt->fd;
    int ret;
    ret = gntmap_munmap(&files[fd].gntmap,
                        (unsigned long) start_address,
                        count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int osdep_gnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    int fd = xgt->fd;
    int ret;
    ret = gntmap_set_max_grants(&files[fd].gntmap,
                                count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int osdep_gnttab_grant_copy(xengnttab_handle *xgt,
                            uint32_t count,
                            xengnttab_grant_copy_segment_t *segs)
{
    return -1;
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
