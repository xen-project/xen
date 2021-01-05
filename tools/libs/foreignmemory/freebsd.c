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

int osdep_xenforeignmemory_open(xenforeignmemory_handle *fmem)
{
    int fd = open(PRIVCMD_DEV, O_RDWR|O_CLOEXEC);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface "
               PRIVCMD_DEV);
        return -1;
    }

    fmem->fd = fd;
    return 0;
}

int osdep_xenforeignmemory_close(xenforeignmemory_handle *fmem)
{
    int fd = fmem->fd;
    if ( fd == -1 )
        return 0;
    return close(fd);
}

void *osdep_xenforeignmemory_map(xenforeignmemory_handle *fmem,
                                 uint32_t dom, void *addr,
                                 int prot, int flags, size_t num,
                                 const xen_pfn_t arr[/*num*/], int err[/*num*/])
{
    int fd = fmem->fd;
    privcmd_mmapbatch_t ioctlx;
    int rc;

    addr = mmap(addr, num << PAGE_SHIFT, prot, flags | MAP_SHARED, fd, 0);
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

int osdep_xenforeignmemory_unmap_resource(xenforeignmemory_handle *fmem,
                                        xenforeignmemory_resource_handle *fres)
{
    return fres ? munmap(fres->addr, fres->nr_frames << PAGE_SHIFT) : 0;
}

int osdep_xenforeignmemory_map_resource(xenforeignmemory_handle *fmem,
                                        xenforeignmemory_resource_handle *fres)
{
    privcmd_mmap_resource_t mr = {
        .dom = fres->domid,
        .type = fres->type,
        .id = fres->id,
        .idx = fres->frame,
        .num = fres->nr_frames,
    };
    int rc;

    fres->addr = mmap(fres->addr, fres->nr_frames << PAGE_SHIFT,
                      fres->prot, fres->flags | MAP_SHARED, fmem->fd, 0);
    if ( fres->addr == MAP_FAILED )
        return -1;

    mr.addr = (uintptr_t)fres->addr;

    rc = ioctl(fmem->fd, IOCTL_PRIVCMD_MMAP_RESOURCE, &mr);
    if ( rc )
    {
        int saved_errno;

        if ( errno != ENOSYS )
            PERROR("mmap resource ioctl failed");
        else
            errno = EOPNOTSUPP;

        saved_errno = errno;
        osdep_xenforeignmemory_unmap_resource(fmem, fres);
        errno = saved_errno;

        return -1;
    }

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
