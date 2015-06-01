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
 * Split from xc_freebsd_osdep.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "private.h"

#define PRIVCMD_DEV     "/dev/xen/privcmd"

int osdep_xencall_open(xencall_handle *xcall)
{
    int flags, saved_errno;
    int fd = open(PRIVCMD_DEV, O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface "
               PRIVCMD_DEV);
        return -1;
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
    if ( fd == -1 )
        return 0;
    return close(fd);
}

int osdep_hypercall(xencall_handle *xcall, privcmd_hypercall_t *hypercall)
{
    int fd = xcall->fd;
    int ret;

    ret = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    return (ret == 0) ? hypercall->retval : ret;
}

void *osdep_alloc_pages(xencall_handle *xcall, size_t npages)
{
    size_t size = npages * PAGE_SIZE;
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

void osdep_free_pages(xencall_handle *xcall, void *ptr, size_t npages)
{
    int saved_errno = errno;
    /* Unlock pages */
    munlock(ptr, npages * PAGE_SIZE);

    munmap(ptr, npages * PAGE_SIZE);
    /* We MUST propagate the hypercall errno, not unmap call's. */
    errno = saved_errno;
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
