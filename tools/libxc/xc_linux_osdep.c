 /******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * xc_gnttab functions:
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include <xen/memory.h>
#include <xen/sys/evtchn.h>
#include <xen/sys/gntdev.h>
#include <xen/sys/gntalloc.h>

#include "xenctrl.h"
#include "xenctrlosdep.h"

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))
#define ERROR(_m, _a...)  xc_osdep_log(xch,XTL_ERROR,XC_INTERNAL_ERROR,_m , ## _a )
#define PERROR(_m, _a...) xc_osdep_log(xch,XTL_ERROR,XC_INTERNAL_ERROR,_m \
                  " (%d = %s)", ## _a , errno, xc_strerror(xch, errno))

static xc_osdep_handle linux_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open("/proc/xen/privcmd", O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface");
        return XC_OSDEP_OPEN_ERROR;
    }

    /* Although we return the file handle as the 'xc handle' the API
       does not specify / guarentee that this integer is in fact
       a file handle. Thus we must take responsiblity to ensure
       it doesn't propagate (ie leak) outside the process */
    if ( (flags = fcntl(fd, F_GETFD)) < 0 )
    {
        PERROR("Could not get file handle flags");
        goto error;
    }

    flags |= FD_CLOEXEC;

    if ( fcntl(fd, F_SETFD, flags) < 0 )
    {
        PERROR("Could not set file handle flags");
        goto error;
    }

    return (xc_osdep_handle)fd;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return XC_OSDEP_OPEN_ERROR;
}

static int linux_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static void *linux_privcmd_alloc_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, int npages)
{
    size_t size = npages * XC_PAGE_SIZE;
    void *p;
    int rc, saved_errno;

    /* Address returned by mmap is page aligned. */
    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
    if ( p == MAP_FAILED )
    {
        PERROR("xc_alloc_hypercall_buffer: mmap failed");
        return NULL;
    }

    /* Do not copy the VMA to child process on fork. Avoid the page being COW
        on hypercall. */
    rc = madvise(p, npages * XC_PAGE_SIZE, MADV_DONTFORK);
    if ( rc < 0 )
    {
        PERROR("xc_alloc_hypercall_buffer: madvise failed");
        goto out;
    }

    return p;

out:
    saved_errno = errno;
    (void)munmap(p, size);
    errno = saved_errno;
    return NULL;
}

static void linux_privcmd_free_hypercall_buffer(xc_interface *xch, xc_osdep_handle h, void *ptr, int npages)
{
    /* Recover the VMA flags. Maybe it's not necessary */
    madvise(ptr, npages * XC_PAGE_SIZE, MADV_DOFORK);

    munmap(ptr, npages * XC_PAGE_SIZE);
}

static int linux_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    int fd = (int)h;
    return ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);
}

static int xc_map_foreign_batch_single(int fd, uint32_t dom,
                                       xen_pfn_t *mfn, unsigned long addr)
{
    privcmd_mmapbatch_t ioctlx;
    int rc;

    ioctlx.num = 1;
    ioctlx.dom = dom;
    ioctlx.addr = addr;
    ioctlx.arr = mfn;

    do
    {
        *mfn ^= PRIVCMD_MMAPBATCH_PAGED_ERROR;
        usleep(100);
        rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    }
    while ( (rc < 0) && (errno == ENOENT) );

    return rc;
}

static void *linux_privcmd_map_foreign_batch(xc_interface *xch, xc_osdep_handle h,
                                             uint32_t dom, int prot,
                                             xen_pfn_t *arr, int num)
{
    int fd = (int)h;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    int rc;

    addr = mmap(NULL, num << XC_PAGE_SHIFT, prot, MAP_SHARED, fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    if ( (rc < 0) && (errno == ENOENT) )
    {
        int i;

        for ( i = 0; i < num; i++ )
        {
            if ( (arr[i] & PRIVCMD_MMAPBATCH_MFN_ERROR) ==
                           PRIVCMD_MMAPBATCH_PAGED_ERROR )
            {
                unsigned long paged_addr = (unsigned long)addr + (i << XC_PAGE_SHIFT);
                rc = xc_map_foreign_batch_single(fd, dom, &arr[i],
                                                 paged_addr);
                if ( rc < 0 )
                    goto out;
            }
        }
    }

 out:
    if ( rc < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_batch: ioctl failed");
        (void)munmap(addr, num << XC_PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

/*
 * Retry mmap of all paged gfns in batches
 * retuns < 0 on fatal error
 * returns 0 if all gfns left paging state
 * returns > 0 if some gfns are still in paging state
 *
 * Walk all gfns and try to assemble blocks of gfns in paging state.
 * This will keep the request ring full and avoids delays.
 */
static int retry_paged(int fd, uint32_t dom, void *addr,
                       const xen_pfn_t *arr, int *err, unsigned int num)
{
    privcmd_mmapbatch_v2_t ioctlx;
    int rc, paged = 0, i = 0;
    
    do
    {
        /* Skip gfns not in paging state */
        if ( err[i] != -ENOENT )
        {
            i++;
            continue;
        }

        paged++;

        /* At least one gfn is still in paging state */
        ioctlx.num = 1;
        ioctlx.dom = dom;
        ioctlx.addr = (unsigned long)addr + ((unsigned long)i<<XC_PAGE_SHIFT);
        ioctlx.arr = arr + i;
        ioctlx.err = err + i;
        
        /* Assemble a batch of requests */
        while ( ++i < num )
        {
            if ( err[i] != -ENOENT )
                break;
            ioctlx.num++;
        }
        
        /* Send request and abort on fatal error */
        rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);
        if ( rc < 0 && errno != ENOENT )
            goto out;

    } while ( i < num );
    
    rc = paged;
out:
    return rc;
}

static void *linux_privcmd_map_foreign_bulk(xc_interface *xch, xc_osdep_handle h,
                                            uint32_t dom, int prot,
                                            const xen_pfn_t *arr, int *err, unsigned int num)
{
    int fd = (int)h;
    privcmd_mmapbatch_v2_t ioctlx;
    void *addr;
    unsigned int i;
    int rc;

    addr = mmap(NULL, (unsigned long)num << XC_PAGE_SHIFT, prot, MAP_SHARED,
                fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("xc_map_foreign_bulk: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;
    ioctlx.err = err;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);

    /* Command was recognized, some gfn in arr are in paging state */
    if ( rc < 0 && errno == ENOENT )
    {
        do {
            usleep(100);
            rc = retry_paged(fd, dom, addr, arr, err, num);
        } while ( rc > 0 );
    }
    /* Command was not recognized, use fall back */
    else if ( rc < 0 && errno == EINVAL && (int)num > 0 )
    {
        /*
         * IOCTL_PRIVCMD_MMAPBATCH_V2 is not supported - fall back to
         * IOCTL_PRIVCMD_MMAPBATCH.
         */
        privcmd_mmapbatch_t ioctlx;
        xen_pfn_t *pfn;
        unsigned int pfn_arr_size = ROUNDUP((num * sizeof(*pfn)), XC_PAGE_SHIFT);

        if ( pfn_arr_size <= XC_PAGE_SIZE )
            pfn = alloca(num * sizeof(*pfn));
        else
        {
            pfn = mmap(NULL, pfn_arr_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
            if ( pfn == MAP_FAILED )
            {
                PERROR("xc_map_foreign_bulk: mmap of pfn array failed");
                return NULL;
            }
        }

        memcpy(pfn, arr, num * sizeof(*arr));

        ioctlx.num = num;
        ioctlx.dom = dom;
        ioctlx.addr = (unsigned long)addr;
        ioctlx.arr = pfn;

        rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);

        rc = rc < 0 ? -errno : 0;

        for ( i = 0; i < num; ++i )
        {
            switch ( pfn[i] ^ arr[i] )
            {
            case 0:
                err[i] = rc != -ENOENT ? rc : 0;
                continue;
            default:
                err[i] = -EINVAL;
                continue;
            case PRIVCMD_MMAPBATCH_PAGED_ERROR:
                if ( rc != -ENOENT )
                {
                    err[i] = rc ?: -EINVAL;
                    continue;
                }
                rc = xc_map_foreign_batch_single(fd, dom, pfn + i,
                        (unsigned long)addr + ((unsigned long)i<<XC_PAGE_SHIFT));
                if ( rc < 0 )
                {
                    rc = -errno;
                    break;
                }
                rc = -ENOENT;
                continue;
            }
            break;
        }

        if ( pfn_arr_size > XC_PAGE_SIZE )
            munmap(pfn, pfn_arr_size);

        if ( rc == -ENOENT && i == num )
            rc = 0;
        else if ( rc )
        {
            errno = -rc;
            rc = -1;
        }
    }

    if ( rc < 0 )
    {
        int saved_errno = errno;

        PERROR("xc_map_foreign_bulk: ioctl failed");
        (void)munmap(addr, (unsigned long)num << XC_PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

static void *linux_privcmd_map_foreign_range(xc_interface *xch, xc_osdep_handle h,
                                             uint32_t dom, int size, int prot,
                                             unsigned long mfn)
{
    xen_pfn_t *arr;
    int num;
    int i;
    void *ret;

    num = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < num; i++ )
        arr[i] = mfn + i;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static void *linux_privcmd_map_foreign_ranges(xc_interface *xch, xc_osdep_handle h,
                                              uint32_t dom, size_t size, int prot,
                                              size_t chunksize, privcmd_mmap_entry_t entries[],
                                              int nentries)
{
    xen_pfn_t *arr;
    int num_per_entry;
    int num;
    int i;
    int j;
    void *ret;

    num_per_entry = chunksize >> XC_PAGE_SHIFT;
    num = num_per_entry * nentries;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < nentries; i++ )
        for ( j = 0; j < num_per_entry; j++ )
            arr[i * num_per_entry + j] = entries[i].mfn + j;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static struct xc_osdep_ops linux_privcmd_ops = {
    .open = &linux_privcmd_open,
    .close = &linux_privcmd_close,

    .u.privcmd = {
        .alloc_hypercall_buffer = &linux_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &linux_privcmd_free_hypercall_buffer,

        .hypercall = &linux_privcmd_hypercall,

        .map_foreign_batch = &linux_privcmd_map_foreign_batch,
        .map_foreign_bulk = &linux_privcmd_map_foreign_bulk,
        .map_foreign_range = &linux_privcmd_map_foreign_range,
        .map_foreign_ranges = &linux_privcmd_map_foreign_ranges,
    },
};

#define DEVXEN "/dev/xen/"

static xc_osdep_handle linux_evtchn_open(xc_evtchn *xce)
{
    int fd = open(DEVXEN "evtchn", O_RDWR);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;

    return (xc_osdep_handle)fd;
}

static int linux_evtchn_close(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static int linux_evtchn_fd(xc_evtchn *xce, xc_osdep_handle h)
{
    return (int)h;
}

static int linux_evtchn_notify(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    struct ioctl_evtchn_notify notify;

    notify.port = port;

    return ioctl(fd, IOCTL_EVTCHN_NOTIFY, &notify);
}

static evtchn_port_or_error_t
linux_evtchn_bind_unbound_port(xc_evtchn *xce, xc_osdep_handle h, int domid)
{
    int fd = (int)h;
    struct ioctl_evtchn_bind_unbound_port bind;

    bind.remote_domain = domid;

    return ioctl(fd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &bind);
}

static evtchn_port_or_error_t
linux_evtchn_bind_interdomain(xc_evtchn *xce, xc_osdep_handle h, int domid,
                              evtchn_port_t remote_port)
{
    int fd = (int)h;
    struct ioctl_evtchn_bind_interdomain bind;

    bind.remote_domain = domid;
    bind.remote_port = remote_port;

    return ioctl(fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
}

static evtchn_port_or_error_t
linux_evtchn_bind_virq(xc_evtchn *xce, xc_osdep_handle h, unsigned int virq)
{
    int fd = (int)h;
    struct ioctl_evtchn_bind_virq bind;

    bind.virq = virq;

    return ioctl(fd, IOCTL_EVTCHN_BIND_VIRQ, &bind);
}

static int linux_evtchn_unbind(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    struct ioctl_evtchn_unbind unbind;

    unbind.port = port;

    return ioctl(fd, IOCTL_EVTCHN_UNBIND, &unbind);
}

static evtchn_port_or_error_t linux_evtchn_pending(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    evtchn_port_t port;

    if ( read(fd, &port, sizeof(port)) != sizeof(port) )
        return -1;

    return port;
}

static int linux_evtchn_unmask(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;

    if ( write(fd, &port, sizeof(port)) != sizeof(port) )
        return -1;
    return 0;
}

static struct xc_osdep_ops linux_evtchn_ops = {
    .open = &linux_evtchn_open,
    .close = &linux_evtchn_close,

    .u.evtchn = {
        .fd = &linux_evtchn_fd,
        .notify = &linux_evtchn_notify,
        .bind_unbound_port = &linux_evtchn_bind_unbound_port,
        .bind_interdomain = &linux_evtchn_bind_interdomain,
        .bind_virq = &linux_evtchn_bind_virq,
        .unbind = &linux_evtchn_unbind,
        .pending = &linux_evtchn_pending,
        .unmask = &linux_evtchn_unmask,
    },
};

static xc_osdep_handle linux_gnttab_open(xc_gnttab *xcg)
{
    int fd = open(DEVXEN "gntdev", O_RDWR);

    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;

    return (xc_osdep_handle)fd;
}

static int linux_gnttab_close(xc_gnttab *xcg, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static int linux_gnttab_set_max_grants(xc_gnttab *xch, xc_osdep_handle h,
                                       uint32_t count)
{
    int fd = (int)h, rc;
    struct ioctl_gntdev_set_max_grants max_grants = { .count = count };

    rc = ioctl(fd, IOCTL_GNTDEV_SET_MAX_GRANTS, &max_grants);
    if (rc) {
        /*
         * Newer (e.g. pv-ops) kernels don't implement this IOCTL,
         * so ignore the resulting specific failure.
         */
        if (errno == ENOTTY)
            rc = 0;
        else
            PERROR("linux_gnttab_set_max_grants: ioctl SET_MAX_GRANTS failed");
    }

    return rc;
}

static void *linux_gnttab_grant_map(xc_gnttab *xch, xc_osdep_handle h,
                                    uint32_t count, int flags, int prot,
                                    uint32_t *domids, uint32_t *refs,
                                    uint32_t notify_offset,
                                    evtchn_port_t notify_port)
{
    int fd = (int)h;
    struct ioctl_gntdev_map_grant_ref *map;
    unsigned int map_size = ROUNDUP((sizeof(*map) + (count - 1) *
                                    sizeof(struct ioctl_gntdev_map_grant_ref)),
                                    XC_PAGE_SHIFT);
    void *addr = NULL;
    int domids_stride = 1;
    int i;

    if (flags & XC_GRANT_MAP_SINGLE_DOMAIN)
        domids_stride = 0;

    if ( map_size <= XC_PAGE_SIZE )
        map = alloca(sizeof(*map) +
                     (count - 1) * sizeof(struct ioctl_gntdev_map_grant_ref));
    else
    {
        map = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
        if ( map == MAP_FAILED )
        {
            PERROR("linux_gnttab_grant_map: mmap of map failed");
            return NULL;
        }
    }

    for ( i = 0; i < count; i++ )
    {
        map->refs[i].domid = domids[i * domids_stride];
        map->refs[i].ref = refs[i];
    }

    map->count = count;

    if ( ioctl(fd, IOCTL_GNTDEV_MAP_GRANT_REF, map) ) {
        PERROR("linux_gnttab_grant_map: ioctl MAP_GRANT_REF failed");
        goto out;
    }

 retry:
    addr = mmap(NULL, XC_PAGE_SIZE * count, prot, MAP_SHARED, fd,
                map->index);

    if (addr == MAP_FAILED && errno == EAGAIN)
    {
        /*
         * The grant hypercall can return EAGAIN if the granted page is
         * swapped out. Since the paging daemon may be in the same domain, the
         * hypercall cannot block without causing a deadlock.
         *
         * Because there are no notificaitons when the page is swapped in, wait
         * a bit before retrying, and hope that the page will arrive eventually.
         */
        usleep(1000);
        goto retry;
    }

    if (addr != MAP_FAILED)
    {
        int rv = 0;
        struct ioctl_gntdev_unmap_notify notify;
        notify.index = map->index;
        notify.action = 0;
        if (notify_offset < XC_PAGE_SIZE * count) {
            notify.index += notify_offset;
            notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
        }
        if (notify_port != -1) {
            notify.event_channel_port = notify_port;
            notify.action |= UNMAP_NOTIFY_SEND_EVENT;
        }
        if (notify.action)
            rv = ioctl(fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &notify);
        if (rv) {
            PERROR("linux_gnttab_grant_map: ioctl SET_UNMAP_NOTIFY failed");
            munmap(addr, count * XC_PAGE_SIZE);
            addr = MAP_FAILED;
        }
    }

    if (addr == MAP_FAILED)
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        /* Unmap the driver slots used to store the grant information. */
        PERROR("xc_gnttab_map_grant_refs: mmap failed");
        unmap_grant.index = map->index;
        unmap_grant.count = count;
        ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        addr = NULL;
    }

 out:
    if ( map_size > XC_PAGE_SIZE )
        munmap(map, map_size);

    return addr;
}



static int linux_gnttab_munmap(xc_gnttab *xcg, xc_osdep_handle h,
                               void *start_address, uint32_t count)
{
    int fd = (int)h;
    struct ioctl_gntdev_get_offset_for_vaddr get_offset;
    struct ioctl_gntdev_unmap_grant_ref unmap_grant;
    int rc;

    if ( start_address == NULL )
    {
        errno = EINVAL;
        return -1;
    }

    /* First, it is necessary to get the offset which was initially used to
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
    if ( (rc = munmap(start_address, count * getpagesize())) )
        return rc;

    /* Finally, unmap the driver slots used to store the grant information. */
    unmap_grant.index = get_offset.offset;
    unmap_grant.count = count;
    if ( (rc = ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant)) )
        return rc;

    return 0;
}

static struct xc_osdep_ops linux_gnttab_ops = {
    .open = &linux_gnttab_open,
    .close = &linux_gnttab_close,

    .u.gnttab = {
        .set_max_grants = linux_gnttab_set_max_grants,
        .grant_map = &linux_gnttab_grant_map,
        .munmap = &linux_gnttab_munmap,
    },
};

static xc_osdep_handle linux_gntshr_open(xc_gntshr *xcg)
{
    int fd = open(DEVXEN "gntalloc", O_RDWR);

    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;

    return (xc_osdep_handle)fd;
}

static int linux_gntshr_close(xc_gntshr *xcg, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static void *linux_gntshr_share_pages(xc_gntshr *xch, xc_osdep_handle h,
                                      uint32_t domid, int count,
                                      uint32_t *refs, int writable,
                                      uint32_t notify_offset,
                                      evtchn_port_t notify_port)
{
    struct ioctl_gntalloc_alloc_gref *gref_info = NULL;
    struct ioctl_gntalloc_unmap_notify notify;
    struct ioctl_gntalloc_dealloc_gref gref_drop;
    int fd = (int)h;
    int err;
    void *area = NULL;
    gref_info = malloc(sizeof(*gref_info) + count * sizeof(uint32_t));
    if (!gref_info)
        return NULL;
    gref_info->domid = domid;
    gref_info->flags = writable ? GNTALLOC_FLAG_WRITABLE : 0;
    gref_info->count = count;

    err = ioctl(fd, IOCTL_GNTALLOC_ALLOC_GREF, gref_info);
    if (err) {
        PERROR("linux_gntshr_share_pages: ioctl failed");
        goto out;
    }

    area = mmap(NULL, count * XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, gref_info->index);

    if (area == MAP_FAILED) {
        area = NULL;
        PERROR("linux_gntshr_share_pages: mmap failed");
        goto out_remove_fdmap;
    }

    notify.index = gref_info->index;
    notify.action = 0;
    if (notify_offset < XC_PAGE_SIZE * count) {
        notify.index += notify_offset;
        notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
    }
    if (notify_port != -1) {
        notify.event_channel_port = notify_port;
        notify.action |= UNMAP_NOTIFY_SEND_EVENT;
    }
    if (notify.action)
        err = ioctl(fd, IOCTL_GNTALLOC_SET_UNMAP_NOTIFY, &notify);
    if (err) {
        PERROR("linux_gntshr_share_page_notify: ioctl SET_UNMAP_NOTIFY failed");
		munmap(area, count * XC_PAGE_SIZE);
		area = NULL;
	}

    memcpy(refs, gref_info->gref_ids, count * sizeof(uint32_t));

 out_remove_fdmap:
    /* Removing the mapping from the file descriptor does not cause the pages to
     * be deallocated until the mapping is removed.
     */
    gref_drop.index = gref_info->index;
    gref_drop.count = count;
    ioctl(fd, IOCTL_GNTALLOC_DEALLOC_GREF, &gref_drop);
 out:
    free(gref_info);
    return area;
}

static int linux_gntshr_munmap(xc_gntshr *xcg, xc_osdep_handle h,
                               void *start_address, uint32_t count)
{
    return munmap(start_address, count * XC_PAGE_SIZE);
}

static struct xc_osdep_ops linux_gntshr_ops = {
    .open = &linux_gntshr_open,
    .close = &linux_gntshr_close,

    .u.gntshr = {
        .share_pages = &linux_gntshr_share_pages,
        .munmap = &linux_gntshr_munmap,
    },
};


static struct xc_osdep_ops *linux_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &linux_privcmd_ops;
    case XC_OSDEP_EVTCHN:
        return &linux_evtchn_ops;
    case XC_OSDEP_GNTTAB:
        return &linux_gnttab_ops;
    case XC_OSDEP_GNTSHR:
        return &linux_gntshr_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "Linux Native OS interface",
    .init = &linux_osdep_init,
    .fake = 0,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
