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

#include "xenctrl.h"

#include "xc_private.h"

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

int osdep_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open("/dev/xen/privcmd", O_RDWR); /* prefer this newer interface */

    if ( fd == -1 && ( errno == ENOENT || errno == ENXIO || errno == ENODEV ))
    {
        /* Fallback to /proc/xen/privcmd */
        fd = open("/proc/xen/privcmd", O_RDWR);
    }

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface");
        return -1;
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
    if (fd == -1)
        return 0;
    return close(fd);
}

void *osdep_alloc_hypercall_buffer(xc_interface *xch, int npages)
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

void osdep_free_hypercall_buffer(xc_interface *xch, void *ptr, int npages)
{
    int saved_errno = errno;
    /* Recover the VMA flags. Maybe it's not necessary */
    madvise(ptr, npages * XC_PAGE_SIZE, MADV_DOFORK);

    munmap(ptr, npages * XC_PAGE_SIZE);
    /* We MUST propagate the hypercall errno, not unmap call's. */
    errno = saved_errno;
}

int do_xen_hypercall(xc_interface *xch, privcmd_hypercall_t *hypercall)
{
    int fd = xch->privcmdfd;
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

void *xc_map_foreign_batch(xc_interface *xch,
                           uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    int fd = xch->privcmdfd;
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

void *xc_map_foreign_bulk(xc_interface *xch,
                          uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    int fd = xch->privcmdfd;
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
                (void)munmap(addr, (unsigned long)num << XC_PAGE_SHIFT);
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
