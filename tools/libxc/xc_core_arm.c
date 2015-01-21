/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (c) 2011 Citrix Systems
 *
 */

#include "xg_private.h"
#include "xc_core.h"

int
xc_core_arch_gpfn_may_present(struct xc_core_arch_context *arch_ctxt,
                              unsigned long pfn)
{
    /* TODO: memory from DT */
    if (pfn >= 0x80000 && pfn < 0x88000)
        return 1;
    return 0;
}


static int nr_gpfns(xc_interface *xch, domid_t domid)
{
    return xc_domain_maximum_gpfn(xch, domid) + 1;
}

int
xc_core_arch_auto_translated_physmap(const xc_dominfo_t *info)
{
    return 1;
}

int
xc_core_arch_memory_map_get(xc_interface *xch, struct xc_core_arch_context *unused,
                            xc_dominfo_t *info, shared_info_any_t *live_shinfo,
                            xc_core_memory_map_t **mapp,
                            unsigned int *nr_entries)
{
    unsigned long p2m_size = nr_gpfns(xch, info->domid);
    xc_core_memory_map_t *map;

    map = malloc(sizeof(*map));
    if ( map == NULL )
    {
        PERROR("Could not allocate memory");
        return -1;
    }

    map->addr = 0;
    map->size = ((uint64_t)p2m_size) << PAGE_SHIFT;

    *mapp = map;
    *nr_entries = 1;
    return 0;
}

static int
xc_core_arch_map_p2m_rw(xc_interface *xch, struct domain_info_context *dinfo, xc_dominfo_t *info,
                        shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m,
                        unsigned long *pfnp, int rw)
{
    errno = ENOSYS;
    return -1;
}

int
xc_core_arch_map_p2m(xc_interface *xch, unsigned int guest_width, xc_dominfo_t *info,
                        shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m,
                        unsigned long *pfnp)
{
    struct domain_info_context _dinfo = { .guest_width = guest_width };
    struct domain_info_context *dinfo = &_dinfo;
    return xc_core_arch_map_p2m_rw(xch, dinfo, info,
                                   live_shinfo, live_p2m, pfnp, 0);
}

int
xc_core_arch_map_p2m_writable(xc_interface *xch, unsigned int guest_width, xc_dominfo_t *info,
                              shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m,
                              unsigned long *pfnp)
{
    struct domain_info_context _dinfo = { .guest_width = guest_width };
    struct domain_info_context *dinfo = &_dinfo;
    return xc_core_arch_map_p2m_rw(xch, dinfo, info,
                                   live_shinfo, live_p2m, pfnp, 1);
}

int
xc_core_arch_get_scratch_gpfn(xc_interface *xch, domid_t domid,
                              xen_pfn_t *gpfn)
{
    /*
     * The Grant Table region space is not used until the guest is
     * booting. Use the first page for the scratch pfn.
     */
    XC_BUILD_BUG_ON(GUEST_GNTTAB_SIZE < XC_PAGE_SIZE);

    *gpfn = GUEST_GNTTAB_BASE >> XC_PAGE_SHIFT;

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
