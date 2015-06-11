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

void *osdep_alloc_hypercall_buffer(xc_interface *xch, int npages)
{
    return xc_memalign(xch, PAGE_SIZE, npages * PAGE_SIZE);
}

void osdep_free_hypercall_buffer(xc_interface *xch, void *ptr, int npages)
{
    free(ptr);
}

int do_xen_hypercall(xc_interface *xch, privcmd_hypercall_t *hypercall)
{
    multicall_entry_t call;
    int i, ret;

    call.op = hypercall->op;
    for (i = 0; i < ARRAY_SIZE(hypercall->arg); i++)
	call.args[i] = hypercall->arg[i];

    ret = HYPERVISOR_multicall(&call, 1);

    if (ret < 0) {
	errno = -ret;
	return -1;
    }
    if ((long) call.result < 0) {
        errno = - (long) call.result;
        return -1;
    }
    return call.result;
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

void *xc_map_foreign_batch(xc_interface *xch,
                           uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    unsigned long pt_prot = 0;
    int err[num];
    int i;
    unsigned long addr;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    addr = (unsigned long) map_frames_ex(arr, num, 1, 0, 1, dom, err, pt_prot);
    for (i = 0; i < num; i++) {
        if (err[i])
            arr[i] |= 0xF0000000;
    }
    return (void *) addr;
}

void *xc_map_foreign_range(xc_interface *xch,
                           uint32_t dom,
                           int size, int prot,
                           unsigned long mfn)
{
    unsigned long pt_prot = 0;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    assert(!(size % getpagesize()));
    return map_frames_ex(&mfn, size / getpagesize(), 0, 1, 1, dom, NULL, pt_prot);
}

void *xc_map_foreign_ranges(xc_interface *xch,
                            uint32_t dom,
                            size_t size, int prot, size_t chunksize,
                            privcmd_mmap_entry_t entries[], int nentries)
{
    unsigned long *mfns;
    int i, j, n;
    unsigned long pt_prot = 0;
    void *ret;

    if (prot & PROT_READ)
	pt_prot = L1_PROT_RO;
    if (prot & PROT_WRITE)
	pt_prot = L1_PROT;

    mfns = malloc((size / XC_PAGE_SIZE) * sizeof(*mfns));

    n = 0;
    for (i = 0; i < nentries; i++)
        for (j = 0; j < chunksize / XC_PAGE_SIZE; j++)
            mfns[n++] = entries[i].mfn + j;

    ret = map_frames_ex(mfns, n, 1, 0, 1, dom, NULL, pt_prot);
    free(mfns);
    return ret;
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
