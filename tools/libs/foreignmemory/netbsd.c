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
#include <sys/mman.h>

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

void *osdep_map_foreign_batch(xenforeignmem_handle *fmem, uint32_t dom,
                              int prot, xen_pfn_t *arr, int num)
{
    int fd = fmem->fd;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    addr = mmap(NULL, num*XC_PAGE_SIZE, prot, MAP_ANON | MAP_SHARED, -1, 0);
    if ( addr == MAP_FAILED ) {
        PERROR("osdep_map_foreign_batch: mmap failed");
        return NULL;
    }

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("osdep_map_foreign_batch: ioctl failed");
        (void)munmap(addr, num*XC_PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

int osdep_xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                                 void *addr, size_t num)
{
    return munmap(addr, num*XC_PAGE_SIZE);
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
