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
 *
 * Split from xc_netbsd.c
 */

#include "xc_private.h"

#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>

int osdep_xencall_open(xencall_handle *xcall)
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

    xcall->fd = fd;
    return 0;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

int osdep_xencall_close(xencall_handle *xcall)
{
    int fd = xcall->fd;
    return close(fd);
}

void *osdep_alloc_hypercall_buffer(xencall_handle *xcall, size_t npages)
{
    size_t size = npages * XC_PAGE_SIZE;
    void *p;

    ret = posix_memalign(&p, XC_PAGE_SIZE, size);
    if ( ret != 0 || !p )
        return NULL;

    if ( mlock(p, size) < 0 )
    {
        free(p);
        return NULL;
    }
    return p;
}

void osdep_free_hypercall_buffer(xencall_handle *xcall, void *ptr,
                                 size_t npages)
{
    (void) munlock(ptr, npages * XC_PAGE_SIZE);
    free(ptr);
}

int do_xen_hypercall(xencall_handle *xcall, privcmd_hypercall_t *hypercall)
{
    int fd = xcall->fd;
    int error = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    /*
     * Since NetBSD ioctl can only return 0 on success or < 0 on
     * error, if we want to return a value from ioctl we should
     * do so by setting hypercall->retval, to mimic Linux ioctl
     * implementation.
     */
    if (error < 0)
        return error;
    else
        return hypercall->retval;
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
