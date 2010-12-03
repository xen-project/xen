/******************************************************************************
 * xc_foreign_memory.c
 *
 * Functions for mapping foreign domain's memory.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

void *xc_map_foreign_range(xc_interface *xch, uint32_t dom,
                           int size, int prot, unsigned long mfn)
{
    return xch->ops->u.privcmd.map_foreign_range(xch, xch->ops_handle,
                                                 dom, size, prot, mfn);
}

void *xc_map_foreign_batch(xc_interface *xch, uint32_t dom, int prot,
                           xen_pfn_t *arr, int num)
{
    return xch->ops->u.privcmd.map_foreign_batch(xch, xch->ops_handle,
                                                 dom, prot, arr, num);
}

void *xc_map_foreign_bulk(xc_interface *xch, uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    return xch->ops->u.privcmd.map_foreign_bulk(xch, xch->ops_handle,
                                                dom, prot, arr, err, num);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
