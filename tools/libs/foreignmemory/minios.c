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
 * Split out from xc_minios.c
 *
 * Copyright 2007-2008 Samuel Thibault <samuel.thibault@eu.citrix.com>.
 */

#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/mm.h>
#include <mini-os/lib.h>

#include <errno.h>

#include <sys/mman.h>

#include "private.h"

int osdep_xenforeignmemory_open(xenforeignmemory_handle *fmem)
{
    /* No fd required */
    return 0;
}

int osdep_xenforeignmemory_close(xenforeignmemory_handle *fmem)
{
    return 0;
}

void *osdep_xenforeignmemory_map(xenforeignmemory_handle *fmem,
                                 uint32_t dom, void *addr,
                                 int prot, int flags, size_t num,
                                 const xen_pfn_t arr[/*num*/], int err[/*num*/])
{
    unsigned long pt_prot = 0;
    if (prot & PROT_READ)
        pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
        pt_prot = L1_PROT;
    return map_frames_ex(arr, num, 1, 0, 1, dom, err, pt_prot);
}

int osdep_xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                                 void *addr, size_t num)
{
    return munmap(addr, num << PAGE_SHIFT);
}

int osdep_xenforeignmemory_restrict(xenforeignmemory_handle *fmem,
                                    domid_t domid)
{
    errno = -EOPNOTSUPP;
    return -1;
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
