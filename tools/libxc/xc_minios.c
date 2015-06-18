/******************************************************************************
 *
 * Copyright 2007-2008 Samuel Thibault <samuel.thibault@eu.citrix.com>.
 * All rights reserved.
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

#undef NDEBUG
#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/mm.h>
#include <mini-os/lib.h>

#include <xen/memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <malloc.h>

#include "xc_private.h"

void minios_interface_close_fd(int fd);

extern void minios_interface_close_fd(int fd);

int osdep_privcmd_open(xc_interface *xch)
{
    int fd = alloc_fd(FTYPE_XC);

    if ( fd == -1)
        return -1;

    xch->privcmdfd = fd;
    return 0;
}

int osdep_privcmd_close(xc_interface *xch)
{
    int fd = xch->privcmdfd;
    return close(fd);
}

void minios_interface_close_fd(int fd)
{
    files[fd].type = FTYPE_NONE;
}

void *xc_map_foreign_bulk(xc_interface *xch,
                          uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    unsigned long pt_prot = 0;
    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;
    return map_frames_ex(arr, num, 1, 0, 1, dom, err, pt_prot);
}

/* Optionally flush file to disk and discard page cache */
void discard_file_cache(xc_interface *xch, int fd, int flush)
{
    if (flush)
        fsync(fd);
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
