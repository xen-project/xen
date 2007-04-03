/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#include "xg_private.h"
#include "xc_core.h"

static int max_gpfn(int xc_handle, domid_t domid)
{
    return xc_memory_op(xc_handle, XENMEM_maximum_gpfn, &domid);
}

int
xc_core_arch_auto_translated_physmap(const xc_dominfo_t *info)
{
    return info->hvm;
}

int
xc_core_arch_memory_map_get(int xc_handle, xc_dominfo_t *info,
                            shared_info_t *live_shinfo,
                            xc_core_memory_map_t **mapp,
                            unsigned int *nr_entries)
{
    unsigned long p2m_size = max_gpfn(xc_handle, info->domid);
    xc_core_memory_map_t *map;

    map = malloc(sizeof(*map));
    if ( map == NULL )
    {
        PERROR("Could not allocate memory");
        return -1;
    }

    map->addr = 0;
    map->size = p2m_size << PAGE_SHIFT;

    *mapp = map;
    *nr_entries = 1;
    return 0;
}

int
xc_core_arch_map_p2m(int xc_handle, xc_dominfo_t *info,
                     shared_info_t *live_shinfo, xen_pfn_t **live_p2m,
                     unsigned long *pfnp)
{
    /* Double and single indirect references to the live P2M table */
    xen_pfn_t *live_p2m_frame_list_list = NULL;
    xen_pfn_t *live_p2m_frame_list = NULL;
    uint32_t dom = info->domid;
    unsigned long p2m_size = max_gpfn(xc_handle, info->domid);
    int ret = -1;
    int err;

    if ( p2m_size < info->nr_pages  )
    {
        ERROR("p2m_size < nr_pages -1 (%lx < %lx", p2m_size, info->nr_pages - 1);
        goto out;
    }

    live_p2m_frame_list_list =
        xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ,
                             live_shinfo->arch.pfn_to_mfn_frame_list_list);

    if ( !live_p2m_frame_list_list )
    {
        PERROR("Couldn't map p2m_frame_list_list (errno %d)", errno);
        goto out;
    }

    live_p2m_frame_list =
        xc_map_foreign_batch(xc_handle, dom, PROT_READ,
                             live_p2m_frame_list_list,
                             P2M_FLL_ENTRIES);

    if ( !live_p2m_frame_list )
    {
        PERROR("Couldn't map p2m_frame_list");
        goto out;
    }

    *live_p2m = xc_map_foreign_batch(xc_handle, dom, PROT_READ,
                                    live_p2m_frame_list,
                                    P2M_FL_ENTRIES);

    if ( !*live_p2m )
    {
        PERROR("Couldn't map p2m table");
        goto out;
    }

    *pfnp = p2m_size;

    ret = 0;

out:
    err = errno;

    if ( live_p2m_frame_list_list )
        munmap(live_p2m_frame_list_list, PAGE_SIZE);

    if ( live_p2m_frame_list )
        munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

    errno = err;
    return ret;
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
