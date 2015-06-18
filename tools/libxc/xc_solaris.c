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

#include "xc_private.h"

#include <xen/memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>

int osdep_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open("/dev/xen/privcmd", O_RDWR);

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
    return close(fd);
}

void *osdep_map_foreign_batch(xc_interface *xch,
                              uint32_t dom, int prot,
                              xen_pfn_t *arr, int num)
{
    int fd = xch->privcmdfd;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    addr = mmap(NULL, num*XC_PAGE_SIZE, prot, MAP_SHARED, fd, 0);
    if ( addr == MAP_FAILED )
        return NULL;

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx) < 0 )
    {
        int saved_errno = errno;
        PERROR("XXXXXXXX");
        (void)munmap(addr, num*XC_PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

/* Optionally flush file to disk and discard page cache */
void discard_file_cache(xc_interface *xch, int fd, int flush) 
{
    // TODO: Implement for Solaris!
}

void *xc_memalign(xc_interface *xch, size_t alignment, size_t size)
{
    return memalign(alignment, size);
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
