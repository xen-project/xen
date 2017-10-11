/*
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
 * Split out from xc_linus_osdep.c:
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 */

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "private.h"

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int osdep_xenforeignmemory_open(xenforeignmemory_handle *fmem)
{
    int fd;

    /* prefer this newer interface */
    fd = open("/dev/xen/privcmd", O_RDWR|O_CLOEXEC);

    if ( fd == -1 && ( errno == ENOENT || errno == ENXIO || errno == ENODEV ))
    {
        /* Fallback to /proc/xen/privcmd */
        fd = open("/proc/xen/privcmd", O_RDWR|O_CLOEXEC);
    }

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface");
        return -1;
    }

    fmem->fd = fd;
    return 0;
}

int osdep_xenforeignmemory_close(xenforeignmemory_handle *fmem)
{
    int fd = fmem->fd;
    if (fd == -1)
        return 0;
    return close(fd);
}

static int map_foreign_batch_single(int fd, uint32_t dom,
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
                       const xen_pfn_t *arr, int *err, size_t num)
{
    privcmd_mmapbatch_v2_t ioctlx;
    int rc, paged = 0;
    size_t i = 0;

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
        ioctlx.addr = (unsigned long)addr + (i<<PAGE_SHIFT);
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

void *osdep_xenforeignmemory_map(xenforeignmemory_handle *fmem,
                                 uint32_t dom, void *addr,
                                 int prot, int flags, size_t num,
                                 const xen_pfn_t arr[/*num*/], int err[/*num*/])
{
    int fd = fmem->fd;
    privcmd_mmapbatch_v2_t ioctlx;
    size_t i;
    int rc;

    addr = mmap(addr, num << PAGE_SHIFT, prot, flags | MAP_SHARED,
                fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("mmap failed");
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
        unsigned int pfn_arr_size = ROUNDUP((num * sizeof(*pfn)), PAGE_SHIFT);

        if ( pfn_arr_size <= PAGE_SIZE )
            pfn = alloca(num * sizeof(*pfn));
        else
        {
            pfn = mmap(NULL, pfn_arr_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
            if ( pfn == MAP_FAILED )
            {
                PERROR("mmap of pfn array failed");
                (void)munmap(addr, num << PAGE_SHIFT);
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
                rc = map_foreign_batch_single(fd, dom, pfn + i,
                        (unsigned long)addr + (i<<PAGE_SHIFT));
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

        if ( pfn_arr_size > PAGE_SIZE )
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

        PERROR("ioctl failed");
        (void)munmap(addr, num << PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

int osdep_xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                                 void *addr, size_t num)
{
    return munmap(addr, num << PAGE_SHIFT);
}

int osdep_xenforeignmemory_restrict(xenforeignmemory_handle *fmem,
                                    domid_t domid)
{
    return ioctl(fmem->fd, IOCTL_PRIVCMD_RESTRICT, &domid);
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
