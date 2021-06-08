/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "private.h"

int osdep_xenforeignmemory_open(xenforeignmemory_handle *fmem)
{
    int flags, saved_errno;
    int fd = open("/kern/xen/privcmd", O_RDWR);

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

    fmem->fd = fd;
    return 0;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

int osdep_xenforeignmemory_close(xenforeignmemory_handle *fmem)
{
    int fd = fmem->fd;
    return close(fd);
}

void *osdep_xenforeignmemory_map(xenforeignmemory_handle *fmem,
                                 uint32_t dom, void *addr,
                                 int prot, int flags, size_t num,
                                 const xen_pfn_t arr[/*num*/], int err[/*num*/])

{
    int fd = fmem->fd;
    privcmd_mmapbatch_v2_t ioctlx;
    addr = mmap(addr, num * XC_PAGE_SIZE, prot,
                flags | MAP_ANON | MAP_SHARED, -1, 0);
    if ( addr == MAP_FAILED ) {
        PERROR("osdep_xenforeignmemory_map: mmap failed");
        return NULL;
    }

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    ioctlx.err=err;

    if ( ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("osdep_xenforeignmemory_map: ioctl failed");
        munmap(addr, num * XC_PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

int osdep_xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                                 void *addr, size_t num)
{
    return munmap(addr, num * XC_PAGE_SIZE);
}

int osdep_xenforeignmemory_restrict(xenforeignmemory_handle *fmem,
                                    domid_t domid)
{
    errno = EOPNOTSUPP;
    return -1;
}

int osdep_xenforeignmemory_unmap_resource(
    xenforeignmemory_handle *fmem, xenforeignmemory_resource_handle *fres)
{
    return fres ? munmap(fres->addr, fres->nr_frames << XC_PAGE_SHIFT) : 0;
}

int osdep_xenforeignmemory_map_resource(
    xenforeignmemory_handle *fmem, xenforeignmemory_resource_handle *fres)
{
    privcmd_mmap_resource_t mr = {
        .dom = fres->domid,
        .type = fres->type,
        .id = fres->id,
        .idx = fres->frame,
        .num = fres->nr_frames,
    };
    int rc;

    if ( !fres->addr && !fres->nr_frames )
        /* Request for resource size.  Skip mmap(). */
        goto skip_mmap;

    fres->addr = mmap(fres->addr, fres->nr_frames << XC_PAGE_SHIFT,
                      fres->prot, fres->flags | MAP_ANON | MAP_SHARED, -1, 0);
    if ( fres->addr == MAP_FAILED )
        return -1;

    mr.addr = (uintptr_t)fres->addr;

 skip_mmap:
    rc = ioctl(fmem->fd, IOCTL_PRIVCMD_MMAP_RESOURCE, &mr);
    if ( rc )
    {
        if ( errno == ENOSYS )
            errno = EOPNOTSUPP;

        if ( fres->addr )
        {
            int saved_errno = errno;

            osdep_xenforeignmemory_unmap_resource(fmem, fres);
            errno = saved_errno;
        }

        return -1;
    }

    /* If requesting size, copy back. */
    if ( !fres->addr )
        fres->nr_frames = mr.num;

    return 0;
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
