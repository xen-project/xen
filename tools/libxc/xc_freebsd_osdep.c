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

#include "xenctrl.h"
#include "xenctrlosdep.h"

#define PRIVCMD_DEV     "/dev/xen/privcmd"
#define EVTCHN_DEV      "/dev/xen/evtchn"

#define PERROR(_m, _a...) xc_osdep_log(xch,XTL_ERROR,XC_INTERNAL_ERROR,_m \
                  " (%d = %s)", ## _a , errno, xc_strerror(xch, errno))

/*------------------------- Privcmd device interface -------------------------*/
static xc_osdep_handle freebsd_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open(PRIVCMD_DEV, O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface "
               PRIVCMD_DEV);
        return XC_OSDEP_OPEN_ERROR;
    }

    /*
     * Although we return the file handle as the 'xc handle' the API
     * does not specify / guarentee that this integer is in fact
     * a file handle. Thus we must take responsiblity to ensure
     * it doesn't propagate (ie leak) outside the process.
     */
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

static int freebsd_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    int fd = (int)h;

    return close(fd);
}

/*------------------------ Privcmd hypercall interface -----------------------*/
static void *freebsd_privcmd_alloc_hypercall_buffer(xc_interface *xch,
                                                    xc_osdep_handle h,
                                                    int npages)
{
    size_t size = npages * XC_PAGE_SIZE;
    void *p;

    /* Address returned by mmap is page aligned. */
    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
             -1, 0);
    if (p == NULL)
        return NULL;

    /*
     * Since FreeBSD doesn't have the MAP_LOCKED flag,
     * lock memory using mlock.
     */
    if ( mlock(p, size) < 0 )
    {
        munmap(p, size);
        return NULL;
    }

    return p;
}

static void freebsd_privcmd_free_hypercall_buffer(xc_interface *xch,
                                                  xc_osdep_handle h, void *ptr,
                                                  int npages)
{

    /* Unlock pages */
    munlock(ptr, npages * XC_PAGE_SIZE);

    munmap(ptr, npages * XC_PAGE_SIZE);
}

static int freebsd_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h,
                                     privcmd_hypercall_t *hypercall)
{
    int fd = (int)h;
    int ret;

    ret = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    return (ret == 0) ? hypercall->retval : ret;
}

/*----------------------- Privcmd foreign map interface ----------------------*/
static void *freebsd_privcmd_map_foreign_bulk(xc_interface *xch,
                                               xc_osdep_handle h,
                                               uint32_t dom, int prot,
                                               const xen_pfn_t *arr, int *err,
                                               unsigned int num)
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
    ioctlx.err = err;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
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

static void *freebsd_privcmd_map_foreign_range(xc_interface *xch,
                                               xc_osdep_handle h,
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

static void *freebsd_privcmd_map_foreign_ranges(xc_interface *xch,
                                                xc_osdep_handle h,
                                                uint32_t dom, size_t size,
                                                int prot, size_t chunksize,
                                                privcmd_mmap_entry_t entries[],
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

/*----------------------------- Privcmd handlers -----------------------------*/
static struct xc_osdep_ops freebsd_privcmd_ops = {
    .open = &freebsd_privcmd_open,
    .close = &freebsd_privcmd_close,

    .u.privcmd = {
        .alloc_hypercall_buffer = &freebsd_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &freebsd_privcmd_free_hypercall_buffer,

        .hypercall = &freebsd_privcmd_hypercall,

        .map_foreign_bulk = &freebsd_privcmd_map_foreign_bulk,
        .map_foreign_range = &freebsd_privcmd_map_foreign_range,
        .map_foreign_ranges = &freebsd_privcmd_map_foreign_ranges,
    },
};

/*-------------------------- Evtchn device interface -------------------------*/
static xc_osdep_handle
freebsd_evtchn_open(xc_evtchn *xce)
{
    int fd = open(EVTCHN_DEV, O_RDWR);
    if ( fd == -1 )
        return XC_OSDEP_OPEN_ERROR;

    return (xc_osdep_handle)fd;
}

static int
freebsd_evtchn_close(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    return close(fd);
}

static int
freebsd_evtchn_fd(xc_evtchn *xce, xc_osdep_handle h)
{
    return (int)h;
}

/*------------------------------ Evtchn interface ----------------------------*/
static int
freebsd_evtchn_notify(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    struct ioctl_evtchn_notify notify;

    notify.port = port;

    return ioctl(fd, IOCTL_EVTCHN_NOTIFY, &notify);
}

static evtchn_port_or_error_t
freebsd_evtchn_bind_unbound_port(xc_evtchn *xce, xc_osdep_handle h, int domid)
{
    int ret, fd = (int)h;
    struct ioctl_evtchn_bind_unbound_port bind;

    bind.remote_domain = domid;

    ret = ioctl(fd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &bind);
    return ( ret == 0 ) ? bind.port : ret;
}

static evtchn_port_or_error_t
freebsd_evtchn_bind_interdomain(xc_evtchn *xce, xc_osdep_handle h, int domid,
                                evtchn_port_t remote_port)
{
    int ret, fd = (int)h;
    struct ioctl_evtchn_bind_interdomain bind;

    bind.remote_domain = domid;
    bind.remote_port = remote_port;

    ret = ioctl(fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
    return ( ret == 0 ) ? bind.port : ret;
}

static evtchn_port_or_error_t
freebsd_evtchn_bind_virq(xc_evtchn *xce, xc_osdep_handle h, unsigned int virq)
{
    int ret, fd = (int)h;
    struct ioctl_evtchn_bind_virq bind;

    bind.virq = virq;

    ret = ioctl(fd, IOCTL_EVTCHN_BIND_VIRQ, &bind);
    return ( ret == 0 ) ? bind.port : ret;
}

static int
freebsd_evtchn_unbind(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;
    struct ioctl_evtchn_unbind unbind;

    unbind.port = port;

    return ioctl(fd, IOCTL_EVTCHN_UNBIND, &unbind);
}

static evtchn_port_or_error_t
freebsd_evtchn_pending(xc_evtchn *xce, xc_osdep_handle h)
{
    int fd = (int)h;
    evtchn_port_t port;

    if ( read(fd, &port, sizeof(port)) != sizeof(port) )
        return -1;

    return port;
}

static int
freebsd_evtchn_unmask(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port)
{
    int fd = (int)h;

    if ( write(fd, &port, sizeof(port)) != sizeof(port) )
        return -1;
    return 0;
}

/*----------------------------- Evtchn handlers ------------------------------*/
static struct xc_osdep_ops freebsd_evtchn_ops = {
    .open = &freebsd_evtchn_open,
    .close = &freebsd_evtchn_close,

    .u.evtchn = {
        .fd = &freebsd_evtchn_fd,
        .notify = &freebsd_evtchn_notify,
        .bind_unbound_port = &freebsd_evtchn_bind_unbound_port,
        .bind_interdomain = &freebsd_evtchn_bind_interdomain,
        .bind_virq = &freebsd_evtchn_bind_virq,
        .unbind = &freebsd_evtchn_unbind,
        .pending = &freebsd_evtchn_pending,
        .unmask = &freebsd_evtchn_unmask,
    },
};

/*---------------------------- FreeBSD interface -----------------------------*/
static struct xc_osdep_ops *
freebsd_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &freebsd_privcmd_ops;
    case XC_OSDEP_EVTCHN:
        return &freebsd_evtchn_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "FreeBSD Native OS interface",
    .init = &freebsd_osdep_init,
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
