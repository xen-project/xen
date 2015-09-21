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
#include <malloc.h>

#include "private.h"

int osdep_xencall_open(xencall_handle *xcall)
{
    /* No fd required */
    return 0;
}

int osdep_xencall_close(xencall_handle *xcall)
{
    return 0;
}

int osdep_hypercall(xencall_handle *xcall, privcmd_hypercall_t *hypercall)
{
    multicall_entry_t call;
    int i, ret;

    call.op = hypercall->op;
    for (i = 0; i < 5; i++)
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

void *osdep_alloc_pages(xencall_handle *xcall, size_t npages)
{
    return memalign(PAGE_SIZE, npages * PAGE_SIZE);
}

void osdep_free_pages(xencall_handle *xcall, void *ptr, size_t npages)
{
    free(ptr);
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
