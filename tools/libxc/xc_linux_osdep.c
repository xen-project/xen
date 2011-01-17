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

#include "xenctrl.h"
#include "xenctrlosdep.h"

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
        *mfn ^= XEN_DOMCTL_PFINFO_PAGEDTAB;
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
            if ( (arr[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) ==
                 XEN_DOMCTL_PFINFO_PAGEDTAB )
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
        PERROR("xc_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;
    ioctlx.err = err;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);

    if ( rc < 0 && errno == ENOENT )
    {
        for ( i = rc = 0; rc == 0 && i < num; i++ )
        {
            if ( err[i] != -ENOENT )
                continue;

            ioctlx.num = 1;
            ioctlx.dom = dom;
            ioctlx.addr = (unsigned long)addr + ((unsigned long)i<<XC_PAGE_SHIFT);
            ioctlx.arr = arr + i;
            ioctlx.err = err + i;
            do {
                usleep(100);
                rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);
            } while ( rc < 0 && err[i] == -ENOENT );
        }
    }

    if ( rc < 0 && errno == EINVAL && (int)num > 0 )
    {
        /*
         * IOCTL_PRIVCMD_MMAPBATCH_V2 is not supported - fall back to
         * IOCTL_PRIVCMD_MMAPBATCH.
         */
        xen_pfn_t *pfn = malloc(num * sizeof(*pfn));

        if ( pfn )
        {
            privcmd_mmapbatch_t ioctlx;

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
                case XEN_DOMCTL_PFINFO_PAGEDTAB:
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

            free(pfn);

            if ( rc == -ENOENT && i == num )
                rc = 0;
            else if ( rc )
            {
                errno = -rc;
                rc = -1;
            }
        }
        else
        {
            errno = -ENOMEM;
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

static void *linux_gnttab_map_grant_ref(xc_gnttab *xch, xc_osdep_handle h,
                                        uint32_t domid, uint32_t ref, int prot)
{
    int fd = (int)h;
    struct ioctl_gntdev_map_grant_ref map;
    void *addr;

    map.count = 1;
    map.refs[0].domid = domid;
    map.refs[0].ref = ref;

    if ( ioctl(fd, IOCTL_GNTDEV_MAP_GRANT_REF, &map) ) {
        PERROR("xc_gnttab_map_grant_ref: ioctl MAP_GRANT_REF failed");
        return NULL;
    }

mmap_again:    
    addr = mmap(NULL, XC_PAGE_SIZE, prot, MAP_SHARED, fd, map.index);
    if ( addr == MAP_FAILED )
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        if(saved_errno == EAGAIN)
        {
            usleep(1000);
            goto mmap_again;
        }
         /* Unmap the driver slots used to store the grant information. */
        PERROR("xc_gnttab_map_grant_ref: mmap failed");
        unmap_grant.index = map.index;
        unmap_grant.count = 1;
        ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

static void *do_gnttab_map_grant_refs(xc_gnttab *xch, xc_osdep_handle h,
                                      uint32_t count,
                                      uint32_t *domids, int domids_stride,
                                      uint32_t *refs, int prot)
{
    int fd = (int)h;
    struct ioctl_gntdev_map_grant_ref *map;
    void *addr = NULL;
    int i;

    map = malloc(sizeof(*map) +
                 (count - 1) * sizeof(struct ioctl_gntdev_map_grant_ref));
    if ( map == NULL )
        return NULL;

    for ( i = 0; i < count; i++ )
    {
        map->refs[i].domid = domids[i * domids_stride];
        map->refs[i].ref = refs[i];
    }

    map->count = count;

    if ( ioctl(fd, IOCTL_GNTDEV_MAP_GRANT_REF, map) ) {
        PERROR("xc_gnttab_map_grant_refs: ioctl MAP_GRANT_REF failed");
        goto out;
    }

    addr = mmap(NULL, XC_PAGE_SIZE * count, prot, MAP_SHARED, fd,
                map->index);
    if ( addr == MAP_FAILED )
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
    free(map);

    return addr;
}

static void *linux_gnttab_map_grant_refs(xc_gnttab *xcg, xc_osdep_handle h,
                                         uint32_t count, uint32_t *domids,
                                         uint32_t *refs, int prot)
{
    return do_gnttab_map_grant_refs(xcg, h, count, domids, 1, refs, prot);
}

static void *linux_gnttab_map_domain_grant_refs(xc_gnttab *xcg, xc_osdep_handle h,
                                                uint32_t count,
                                                uint32_t domid, uint32_t *refs, int prot)
{
    return do_gnttab_map_grant_refs(xcg, h, count, &domid, 0, refs, prot);
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
        .map_grant_ref = &linux_gnttab_map_grant_ref,
        .map_grant_refs = &linux_gnttab_map_grant_refs,
        .map_domain_grant_refs = &linux_gnttab_map_domain_grant_refs,
        .munmap = &linux_gnttab_munmap,
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
