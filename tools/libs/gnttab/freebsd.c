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

#include <xen/sys/gntdev.h>

#include "private.h"

#define PAGE_SHIFT           12
#define PAGE_SIZE            (1UL << PAGE_SHIFT)
#define PAGE_MASK            (~(PAGE_SIZE-1))

#define DEVXEN "/dev/xen/gntdev"

int osdep_gnttab_open(xengnttab_handle *xgt)
{
    int fd = open(DEVXEN, O_RDWR|O_CLOEXEC);

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
    struct ioctl_gntdev_map_grant_ref map;
    void *addr = NULL;
    int domids_stride;
    unsigned int refs_size = ROUNDUP(count *
                                     sizeof(struct ioctl_gntdev_grant_ref),
                                     PAGE_SHIFT);

    domids_stride = (flags & XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN) ? 0 : 1;
    if ( refs_size <= PAGE_SIZE )
        map.refs = malloc(refs_size);
    else
    {
        map.refs = mmap(NULL, refs_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
        if ( map.refs == MAP_FAILED )
        {
            GTERROR(xgt->logger, "anon mmap of map failed");
            return NULL;
        }
    }

    for ( i = 0; i < count; i++ )
    {
        map.refs[i].domid = domids[i * domids_stride];
        map.refs[i].ref = refs[i];
    }

    map.count = count;

    if ( ioctl(fd, IOCTL_GNTDEV_MAP_GRANT_REF, &map) )
    {
        GTERROR(xgt->logger, "ioctl MAP_GRANT_REF failed");
        goto out;
    }

    addr = mmap(NULL, PAGE_SIZE * count, prot, MAP_SHARED, fd,
                map.index);
    if ( addr != MAP_FAILED )
    {
        int rv = 0;
        struct ioctl_gntdev_unmap_notify notify;

        notify.index = map.index;
        notify.action = 0;
        if ( notify_offset < PAGE_SIZE * count )
        {
            notify.index += notify_offset;
            notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
        }
        if ( notify_port != -1 )
        {
            notify.event_channel_port = notify_port;
            notify.action |= UNMAP_NOTIFY_SEND_EVENT;
        }
        if ( notify.action )
            rv = ioctl(fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &notify);
        if ( rv )
        {
            GTERROR(xgt->logger, "ioctl SET_UNMAP_NOTIFY failed");
            munmap(addr, count * PAGE_SIZE);
            addr = MAP_FAILED;
        }
    }
    if ( addr == MAP_FAILED )
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        /* Unmap the driver slots used to store the grant information. */
        GTERROR(xgt->logger, "mmap failed");
        unmap_grant.index = map.index;
        unmap_grant.count = count;
        ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        addr = NULL;
    }

 out:
    if ( refs_size > PAGE_SIZE )
        munmap(map.refs, refs_size);
    else
        free(map.refs);

    return addr;
}

int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count)
{
    int rc;
    int fd = xgt->fd;
    struct ioctl_gntdev_unmap_grant_ref unmap_grant;
    struct ioctl_gntdev_get_offset_for_vaddr get_offset;

    if ( start_address == NULL )
    {
        errno = EINVAL;
        return -1;
    }

    /*
     * First, it is necessary to get the offset which was initially used to
     * mmap() the pages.
     */
    get_offset.vaddr = (unsigned long)start_address;
    if ( (rc = ioctl(fd, IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR,
                     &get_offset)) )
        return rc;

    if ( get_offset.count != count )
    {
        errno = EINVAL;
        return -1;
    }

    /* Next, unmap the memory. */
    if ( (rc = munmap(start_address, count * PAGE_SIZE)) )
        return rc;

    /* Finally, unmap the driver slots used to store the grant information. */
    unmap_grant.index = get_offset.offset;
    unmap_grant.count = count;
    if ( (rc = ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant)) )
        return rc;

    return 0;
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
    struct ioctl_gntdev_unmap_notify notify;
    struct ioctl_gntdev_dealloc_gref gref_drop;
    struct ioctl_gntdev_alloc_gref gref_info;

    gref_info.gref_ids = malloc(count * sizeof(uint32_t));
    if ( gref_info.gref_ids == NULL )
        return NULL;
    gref_info.domid = domid;
    gref_info.flags = writable ? GNTDEV_ALLOC_FLAG_WRITABLE : 0;
    gref_info.count = count;

    err = ioctl(fd, IOCTL_GNTDEV_ALLOC_GREF, &gref_info);
    if ( err )
    {
        GSERROR(xgs->logger, "ioctl failed");
        goto out;
    }

    area = mmap(NULL, count * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, gref_info.index);

    if ( area == MAP_FAILED )
    {
        area = NULL;
        GSERROR(xgs->logger, "mmap failed");
        goto out_remove_fdmap;
    }

    notify.index = gref_info.index;
    notify.action = 0;
    if ( notify_offset < PAGE_SIZE * count )
    {
        notify.index += notify_offset;
        notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
    }
    if ( notify_port != -1 )
    {
        notify.event_channel_port = notify_port;
        notify.action |= UNMAP_NOTIFY_SEND_EVENT;
    }
    if ( notify.action )
        err = ioctl(fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &notify);
    if ( err )
    {
        GSERROR(xgs->logger, "ioctl SET_UNMAP_NOTIFY failed");
        munmap(area, count * PAGE_SIZE);
        area = NULL;
    }

    memcpy(refs, gref_info.gref_ids, count * sizeof(uint32_t));

 out_remove_fdmap:
    /*
     * Removing the mapping from the file descriptor does not cause the
     * pages to be deallocated until the mapping is removed.
     */
    gref_drop.index = gref_info.index;
    gref_drop.count = count;
    ioctl(fd, IOCTL_GNTDEV_DEALLOC_GREF, &gref_drop);
 out:
    free(gref_info.gref_ids);

    return area;
}

int osdep_gntshr_unshare(xengntshr_handle *xgs,
                         void *start_address, uint32_t count)
{
    return munmap(start_address, count * PAGE_SIZE);
}

/*
 * The functions below are Linux-isms that will likely never be implemented
 * on FreeBSD unless FreeBSD also implements something akin to Linux dmabuf.
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
