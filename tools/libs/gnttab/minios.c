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
#include <malloc.h>
#include <unistd.h>

#include "private.h"

static int gnttab_close_fd(struct file *file)
{
    gntmap_fini(file->dev);
    free(file->dev);

    return 0;
}

static const struct file_ops gnttab_ops = {
    .name = "gnttab",
    .close = gnttab_close_fd,
};

static unsigned int ftype_gnttab;

__attribute__((constructor))
static void gnttab_initialize(void)
{
    ftype_gnttab = alloc_file_type(&gnttab_ops);
}

int osdep_gnttab_open(xengnttab_handle *xgt)
{
    int fd;
    struct file *file;
    struct gntmap *gntmap;

    gntmap = malloc(sizeof(*gntmap));
    if ( !gntmap )
        return -1;

    fd = alloc_fd(ftype_gnttab);
    file = get_file_from_fd(fd);

    if ( !file )
    {
        free(gntmap);
        return -1;
    }

    file->dev = gntmap;
    gntmap_init(gntmap);
    xgt->fd = fd;
    return 0;
}

int osdep_gnttab_close(xengnttab_handle *xgt)
{
    if ( xgt->fd == -1 )
        return 0;

    return close(xgt->fd);
}

void *osdep_gnttab_grant_map(xengnttab_handle *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port)
{
    struct file *file = get_file_from_fd(xgt->fd);
    int stride = 1;

    if (flags & XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN)
        stride = 0;
    if (notify_offset != -1 || notify_port != -1) {
        errno = ENOSYS;
        return NULL;
    }
    return gntmap_map_grant_refs(file->dev, count, domids, stride,
                                 refs, prot & PROT_WRITE);
}

int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count)
{
    struct file *file = get_file_from_fd(xgt->fd);
    int ret;

    ret = gntmap_munmap(file->dev, (unsigned long) start_address, count);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int osdep_gnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    struct file *file = get_file_from_fd(xgt->fd);
    int ret;

    ret = gntmap_set_max_grants(file->dev, count);
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

int osdep_gnttab_dmabuf_exp_from_refs(xengnttab_handle *xgt, uint32_t domid,
                                      uint32_t flags, uint32_t count,
                                      const uint32_t *refs, uint32_t *fd)
{
    return -1;
}

int osdep_gnttab_dmabuf_exp_wait_released(xengnttab_handle *xgt,
                                          uint32_t fd, uint32_t wait_to_ms)
{
    return -1;
}

int osdep_gnttab_dmabuf_imp_to_refs(xengnttab_handle *xgt, uint32_t domid,
                                    uint32_t fd, uint32_t count,
                                    uint32_t *refs)
{
    return -1;
}

int osdep_gnttab_dmabuf_imp_release(xengnttab_handle *xgt, uint32_t fd)
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
