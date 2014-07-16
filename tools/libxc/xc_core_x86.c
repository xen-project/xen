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
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#include "xg_private.h"
#include "xc_core.h"
#include <xen/hvm/e820.h>

#define GET_FIELD(_p, _f) ((dinfo->guest_width==8) ? ((_p)->x64._f) : ((_p)->x32._f))

int
xc_core_arch_gpfn_may_present(struct xc_core_arch_context *arch_ctxt,
                              unsigned long pfn)
{
    if ((pfn >= 0xa0 && pfn < 0xc0) /* VGA hole */
        || (pfn >= (HVM_BELOW_4G_MMIO_START >> PAGE_SHIFT)
            && pfn < (1ULL<<32) >> PAGE_SHIFT)) /* MMIO */
        return 0;
    return 1;
}


static int nr_gpfns(xc_interface *xch, domid_t domid)
{
    return xc_domain_maximum_gpfn(xch, domid) + 1;
}

int
xc_core_arch_auto_translated_physmap(const xc_dominfo_t *info)
{
    return info->hvm;
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
    /* Double and single indirect references to the live P2M table */
    xen_pfn_t *live_p2m_frame_list_list = NULL;
    xen_pfn_t *live_p2m_frame_list = NULL;
    /* Copies of the above. */
    xen_pfn_t *p2m_frame_list_list = NULL;
    xen_pfn_t *p2m_frame_list = NULL;

    uint32_t dom = info->domid;
    int ret = -1;
    int err;
    int i;

    dinfo->p2m_size = nr_gpfns(xch, info->domid);
    if ( dinfo->p2m_size < info->nr_pages  )
    {
        ERROR("p2m_size < nr_pages -1 (%lx < %lx", dinfo->p2m_size, info->nr_pages - 1);
        goto out;
    }

    live_p2m_frame_list_list =
        xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ,
                             GET_FIELD(live_shinfo, arch.pfn_to_mfn_frame_list_list));

    if ( !live_p2m_frame_list_list )
    {
        PERROR("Couldn't map p2m_frame_list_list (errno %d)", errno);
        goto out;
    }

    /* Get a local copy of the live_P2M_frame_list_list */
    if ( !(p2m_frame_list_list = malloc(PAGE_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list_list array");
        goto out;
    }
    memcpy(p2m_frame_list_list, live_p2m_frame_list_list, PAGE_SIZE);

    /* Canonicalize guest's unsigned long vs ours */
    if ( dinfo->guest_width > sizeof(unsigned long) )
        for ( i = 0; i < PAGE_SIZE/sizeof(unsigned long); i++ )
            if ( i < PAGE_SIZE/dinfo->guest_width )
                p2m_frame_list_list[i] = ((uint64_t *)p2m_frame_list_list)[i];
            else
                p2m_frame_list_list[i] = 0;
    else if ( dinfo->guest_width < sizeof(unsigned long) )
        for ( i = PAGE_SIZE/sizeof(unsigned long) - 1; i >= 0; i-- )
            p2m_frame_list_list[i] = ((uint32_t *)p2m_frame_list_list)[i];

    live_p2m_frame_list =
        xc_map_foreign_pages(xch, dom, PROT_READ,
                             p2m_frame_list_list,
                             P2M_FLL_ENTRIES);

    if ( !live_p2m_frame_list )
    {
        PERROR("Couldn't map p2m_frame_list");
        goto out;
    }

    /* Get a local copy of the live_P2M_frame_list */
    if ( !(p2m_frame_list = malloc(P2M_TOOLS_FL_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list array");
        goto out;
    }
    memset(p2m_frame_list, 0, P2M_TOOLS_FL_SIZE);
    memcpy(p2m_frame_list, live_p2m_frame_list, P2M_GUEST_FL_SIZE);

    /* Canonicalize guest's unsigned long vs ours */
    if ( dinfo->guest_width > sizeof(unsigned long) )
        for ( i = 0; i < P2M_FL_ENTRIES; i++ )
            p2m_frame_list[i] = ((uint64_t *)p2m_frame_list)[i];
    else if ( dinfo->guest_width < sizeof(unsigned long) )
        for ( i = P2M_FL_ENTRIES - 1; i >= 0; i-- )
            p2m_frame_list[i] = ((uint32_t *)p2m_frame_list)[i];

    *live_p2m = xc_map_foreign_pages(xch, dom,
                                    rw ? (PROT_READ | PROT_WRITE) : PROT_READ,
                                    p2m_frame_list,
                                    P2M_FL_ENTRIES);

    if ( !*live_p2m )
    {
        PERROR("Couldn't map p2m table");
        goto out;
    }

    *pfnp = dinfo->p2m_size;

    ret = 0;

out:
    err = errno;

    if ( live_p2m_frame_list_list )
        munmap(live_p2m_frame_list_list, PAGE_SIZE);

    if ( live_p2m_frame_list )
        munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

    free(p2m_frame_list_list);

    free(p2m_frame_list);

    errno = err;
    return ret;
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
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
