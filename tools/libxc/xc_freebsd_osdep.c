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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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

#include "xc_private.h"

#define PRIVCMD_DEV     "/dev/xen/privcmd"

/*------------------------- Privcmd device interface -------------------------*/
int osdep_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open(PRIVCMD_DEV, O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface "
               PRIVCMD_DEV);
        return -1
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

    xch->privcmdfd = fd;
    return 0;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;

    return -1;
}

int osdep_privcmd_close(xc_interface *xch)
{
    int fd = xch->privcmdfd;
    if ( fd == -1 )
        return 0;
    return close(fd);
}

/*------------------------ Privcmd hypercall interface -----------------------*/
void *osdep_alloc_hypercall_buffer(xc_interface *xch, int npages)
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

void osdep_free_hypercall_buffer(xc_interface *xch, void *ptr, int npages)
{

    int saved_errno = errno;
    /* Unlock pages */
    munlock(ptr, npages * XC_PAGE_SIZE);

    munmap(ptr, npages * XC_PAGE_SIZE);
    /* We MUST propagate the hypercall errno, not unmap call's. */
    errno = saved_errno;
}

int do_xen_hypercall(xc_interface *xch, privcmd_hypercall_t *hypercall)
{
    int fd = xch->privcmdfd;
    int ret;

    ret = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    return (ret == 0) ? hypercall->retval : ret;
}

/*----------------------- Privcmd foreign map interface ----------------------*/
void *xc_map_foreign_bulk(xc_interface *xch,
                          uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err,
                          unsigned int num)
{
    int fd = xch->privcmdfd;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    int rc;

    addr = mmap(NULL, num << XC_PAGE_SHIFT, prot, MAP_SHARED, fd, 0);
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

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    if ( rc < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_bulk: ioctl failed");
        (void)munmap(addr, num << XC_PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

void *xc_map_foreign_range(xc_interface *xch,
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

void *xc_map_foreign_ranges(xc_interface *xch,
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
