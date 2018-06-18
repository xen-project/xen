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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "private.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int osdep_xencall_open(xencall_handle *xcall)
{
    int fd;

    /*
     * Prefer the newer interface.
     */
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

    xcall->fd = fd;

    /*
     * Try the same for the hypercall buffer device.
     */
    fd = open("/dev/xen/hypercall", O_RDWR|O_CLOEXEC);
    if ( fd == -1 && errno != ENOENT )
    {
        PERROR("Error on trying to open hypercall buffer device");
        return -1;
    }
    xcall->buf_fd = fd;

    return 0;
}

int osdep_xencall_close(xencall_handle *xcall)
{
    if ( xcall->buf_fd >= 0 )
        close(xcall->buf_fd);
    if ( xcall->fd >= 0 )
        close(xcall->fd);
    return 0;
}

int osdep_hypercall(xencall_handle *xcall, privcmd_hypercall_t *hypercall)
{
    return ioctl(xcall->fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);
}

static void *alloc_pages_bufdev(xencall_handle *xcall, size_t npages)
{
    void *p;

    p = mmap(NULL, npages * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
             xcall->buf_fd, 0);
    if ( p == MAP_FAILED )
    {
        PERROR("alloc_pages: mmap failed");
        p = NULL;
    }

    return p;
}

static void *alloc_pages_nobufdev(xencall_handle *xcall, size_t npages)
{
    size_t size = npages * PAGE_SIZE;
    void *p;
    int rc, i, saved_errno;

    /* Address returned by mmap is page aligned. */
    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
    if ( p == MAP_FAILED )
    {
        PERROR("alloc_pages: mmap failed");
        return NULL;
    }

    /* Do not copy the VMA to child process on fork. Avoid the page being COW
        on hypercall. */
    rc = madvise(p, npages * PAGE_SIZE, MADV_DONTFORK);
    if ( rc < 0 )
    {
        PERROR("alloc_pages: madvise failed");
        goto out;
    }

    /*
     * Touch each page in turn to force them to be un-CoWed, in case a
     * fork happened in another thread at an inopportune moment
     * above. The madvise() will prevent any subsequent fork calls from
     * causing the same problem.
     */
    for ( i = 0; i < npages ; i++ )
    {
        char *c = (char *)p + (i*PAGE_SIZE);
        *c = 0;
    }

    return p;

out:
    saved_errno = errno;
    (void)munmap(p, size);
    errno = saved_errno;
    return NULL;
}

void *osdep_alloc_pages(xencall_handle *xcall, size_t npages)
{
    void *p;

    if ( xcall->buf_fd >= 0 )
        p = alloc_pages_bufdev(xcall, npages);
    else
        p = alloc_pages_nobufdev(xcall, npages);

    return p;
}

void osdep_free_pages(xencall_handle *xcall, void *ptr, size_t npages)
{
    int saved_errno = errno;

    if ( xcall->buf_fd < 0 )
    {
        /* Recover the VMA flags. Maybe it's not necessary */
        madvise(ptr, npages * PAGE_SIZE, MADV_DOFORK);
    }

    munmap(ptr, npages * PAGE_SIZE);
    /* We MUST propagate the hypercall errno, not unmap call's. */
    errno = saved_errno;
}

int xencall_buffers_never_fault(xencall_handle *xcall)
{
    return xcall->buf_fd >= 0;
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
