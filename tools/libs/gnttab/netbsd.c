/*
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 * Copyright (c) 2016-2017, Akshay Jaggi <jaggi@FreeBSD.org>
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
 * Split out from linux.c
 */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/xenio.h>

#include "private.h"

#define DEVXEN "/kern/xen/privcmd"

int osdep_gnttab_open(xengnttab_handle *xgt)
{
    int fd = open(DEVXEN, O_RDWR | O_CLOEXEC);

    if ( fd == -1 )
        return -1;
    xgt->fd = fd;

    return 0;
}

int osdep_gnttab_close(xengnttab_handle *xgt)
{
    if ( xgt->fd == -1 )
        return 0;

    return close(xgt->fd);
}

int osdep_gnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    return 0;
}

void *osdep_gnttab_grant_map(xengnttab_handle *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port)
{
    uint32_t i;
    int fd = xgt->fd;
    struct ioctl_gntdev_mmap_grant_ref map;
    void *addr = NULL;
    int domids_stride;
    unsigned int refs_size = count * sizeof(struct ioctl_gntdev_grant_ref);
    int rv;

    domids_stride = !!(flags & XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN);
    map.refs = malloc(refs_size);

    for ( i = 0; i < count; i++ )
    {
        map.refs[i].domid = domids[i * domids_stride];
        map.refs[i].ref = refs[i];
    }

    map.count = count;
    addr = mmap(NULL, count * XC_PAGE_SIZE,
                prot, flags | MAP_ANON | MAP_SHARED, -1, 0);
    if ( map.va == MAP_FAILED )
    {
        GTERROR(xgt->logger, "osdep_gnttab_grant_map: mmap failed");
        munmap((void *)map.va, count * XC_PAGE_SIZE);
        addr = MAP_FAILED;
    }
    map.va = addr;

    map.notify.offset = 0;
    map.notify.action = 0;
    if ( notify_offset < XC_PAGE_SIZE * count )
    {
        map.notify.offset = notify_offset;
        map.notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
    }
    if ( notify_port != -1 )
    {
       map.notify.event_channel_port = notify_port;
       map.notify.action |= UNMAP_NOTIFY_SEND_EVENT;
    }

    rv = ioctl(fd, IOCTL_GNTDEV_MMAP_GRANT_REF, &map);
    if ( rv )
    {
        GTERROR(xgt->logger,
            "ioctl IOCTL_GNTDEV_MMAP_GRANT_REF failed: %d", rv);
        munmap(addr, count * XC_PAGE_SIZE);
        addr = MAP_FAILED;
    }

    free(map.refs);

    return addr;
}

int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count)
{
    int rc;
    if ( start_address == NULL )
    {
        errno = EINVAL;
        return -1;
    }

    /* Next, unmap the memory. */
    rc = munmap(start_address, count * XC_PAGE_SIZE);

    return rc;
}

int osdep_gnttab_grant_copy(xengnttab_handle *xgt,
                            uint32_t count,
                            xengnttab_grant_copy_segment_t *segs)
{
    errno = ENOSYS;
    return -1;
}

int osdep_gntshr_open(xengntshr_handle *xgs)
{

    int fd = open(DEVXEN, O_RDWR);

    if ( fd == -1 )
        return -1;

    xgs->fd = fd;
    return 0;
}

int osdep_gntshr_close(xengntshr_handle *xgs)
{
    if ( xgs->fd == -1 )
        return 0;

    return close(xgs->fd);
}

void *osdep_gntshr_share_pages(xengntshr_handle *xgs,
                               uint32_t domid, int count,
                               uint32_t *refs, int writable,
                               uint32_t notify_offset,
                               evtchn_port_t notify_port)
{
    int err;
    int fd = xgs->fd;
    void *area = NULL;
    struct ioctl_gntdev_alloc_grant_ref alloc;

    alloc.gref_ids = malloc(count * sizeof(uint32_t));
    if ( alloc.gref_ids == NULL )
        return NULL;

    alloc.domid = domid;
    alloc.flags = writable ? GNTDEV_ALLOC_FLAG_WRITABLE : 0;
    alloc.count = count;
    area = mmap(NULL, count * XC_PAGE_SIZE,
                PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

    if ( area == MAP_FAILED )
    {
        GTERROR(xgs->logger, "osdep_gnttab_grant_map: mmap failed");
        area = MAP_FAILED;
        goto out;
    }
    alloc.va = area;

    alloc.notify.offset = 0;
    alloc.notify.action = 0;
    if ( notify_offset < XC_PAGE_SIZE * count )
    {
        alloc.notify.offset = notify_offset;
        alloc.notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
    }
    if ( notify_port != -1 )
    {
       alloc.notify.event_channel_port = notify_port;
       alloc.notify.action |= UNMAP_NOTIFY_SEND_EVENT;
    }

    err = ioctl(fd, IOCTL_GNTDEV_ALLOC_GRANT_REF, &alloc);
    if ( err )
    {
        GSERROR(xgs->logger, "IOCTL_GNTDEV_ALLOC_GRANT_REF failed");
        munmap(area, count * XC_PAGE_SIZE);
        area = MAP_FAILED;
        goto out;
    }

    memcpy(refs, alloc.gref_ids, count * sizeof(uint32_t));

 out:
    free(alloc.gref_ids);
    return area;
}

int osdep_gntshr_unshare(xengntshr_handle *xgs,
                         void *start_address, uint32_t count)
{
    return munmap(start_address, count * XC_PAGE_SIZE);
}

/*
 * The functions below are Linux-isms that will likely never be implemented
 * on NetBSD unless NetBSD also implements something akin to Linux dmabuf.
 */
int osdep_gnttab_dmabuf_exp_from_refs(xengnttab_handle *xgt, uint32_t domid,
                                      uint32_t flags, uint32_t count,
                                      const uint32_t *refs,
                                      uint32_t *dmabuf_fd)
{
    abort();
}

int osdep_gnttab_dmabuf_exp_wait_released(xengnttab_handle *xgt,
                                          uint32_t fd, uint32_t wait_to_ms)
{
    abort();
}

int osdep_gnttab_dmabuf_imp_to_refs(xengnttab_handle *xgt, uint32_t domid,
                                    uint32_t fd, uint32_t count, uint32_t *refs)
{
    abort();
}

int osdep_gnttab_dmabuf_imp_release(xengnttab_handle *xgt, uint32_t fd)
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
