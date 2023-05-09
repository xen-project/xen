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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#include <inttypes.h>
#include "xg_private.h"
#include "xg_core.h"
#include <xen/hvm/e820.h>

/* Number of xen_pfn_t in a page */
#define FPP             (PAGE_SIZE/(dinfo->guest_width))

/* Number of entries in the pfn_to_mfn_frame_list_list */
#define P2M_FLL_ENTRIES (((dinfo->p2m_size)+(FPP*FPP)-1)/(FPP*FPP))

/* Number of entries in the pfn_to_mfn_frame_list */
#define P2M_FL_ENTRIES  (((dinfo->p2m_size)+FPP-1)/FPP)

/* Size in bytes of the pfn_to_mfn_frame_list     */
#define P2M_GUEST_FL_SIZE ((P2M_FL_ENTRIES) * (dinfo->guest_width))
#define P2M_TOOLS_FL_SIZE ((P2M_FL_ENTRIES) * \
                           max_t(size_t, sizeof(xen_pfn_t), dinfo->guest_width))

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

int
xc_core_arch_memory_map_get(xc_interface *xch, struct xc_core_arch_context *unused,
                            xc_domaininfo_t *info, shared_info_any_t *live_shinfo,
                            xc_core_memory_map_t **mapp,
                            unsigned int *nr_entries)
{
    xen_pfn_t p2m_size = 0;
    xc_core_memory_map_t *map;

    if ( xc_domain_nr_gpfns(xch, info->domain, &p2m_size) < 0 )
        return -1;

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

static inline bool is_canonical_address(uint64_t vaddr)
{
    return ((int64_t)vaddr >> 47) == ((int64_t)vaddr >> 63);
}

/* Virtual address ranges reserved for hypervisor. */
#define HYPERVISOR_VIRT_START_X86_64 0xFFFF800000000000ULL
#define HYPERVISOR_VIRT_END_X86_64   0xFFFF87FFFFFFFFFFULL

#define HYPERVISOR_VIRT_START_X86_32 0x00000000F5800000ULL
#define HYPERVISOR_VIRT_END_X86_32   0x00000000FFFFFFFFULL

static xen_pfn_t *
xc_core_arch_map_p2m_list_rw(xc_interface *xch, struct domain_info_context *dinfo,
                             uint32_t dom, shared_info_any_t *live_shinfo,
                             uint64_t p2m_cr3)
{
    uint64_t p2m_vaddr, p2m_end, mask, off;
    xen_pfn_t p2m_mfn, mfn, saved_mfn, max_pfn;
    uint64_t *ptes = NULL;
    xen_pfn_t *mfns = NULL;
    unsigned int fpp, n_pages, level, n_levels, shift,
                 idx_start, idx_end, idx, saved_idx;

    p2m_vaddr = GET_FIELD(live_shinfo, arch.p2m_vaddr, dinfo->guest_width);
    fpp = PAGE_SIZE / dinfo->guest_width;
    dinfo->p2m_frames = (dinfo->p2m_size - 1) / fpp + 1;
    p2m_end = p2m_vaddr + dinfo->p2m_frames * PAGE_SIZE - 1;

    if ( dinfo->guest_width == 8 )
    {
        mask = 0x0000ffffffffffffULL;
        n_levels = 4;
        p2m_mfn = p2m_cr3 >> 12;
        if ( !is_canonical_address(p2m_vaddr) ||
             !is_canonical_address(p2m_end) ||
             p2m_end < p2m_vaddr ||
             (p2m_vaddr <= HYPERVISOR_VIRT_END_X86_64 &&
              p2m_end > HYPERVISOR_VIRT_START_X86_64) )
        {
            ERROR("Bad virtual p2m address range %#" PRIx64 "-%#" PRIx64,
                  p2m_vaddr, p2m_end);
            errno = ERANGE;
            goto out;
        }
    }
    else
    {
        mask = 0x00000000ffffffffULL;
        n_levels = 3;
        if ( p2m_cr3 & ~mask )
            p2m_mfn = ~0UL;
        else
            p2m_mfn = (uint32_t)((p2m_cr3 >> 12) | (p2m_cr3 << 20));
        if ( p2m_vaddr > mask || p2m_end > mask || p2m_end < p2m_vaddr ||
             (p2m_vaddr <= HYPERVISOR_VIRT_END_X86_32 &&
              p2m_end > HYPERVISOR_VIRT_START_X86_32) )
        {
            ERROR("Bad virtual p2m address range %#" PRIx64 "-%#" PRIx64,
                  p2m_vaddr, p2m_end);
            errno = ERANGE;
            goto out;
        }
    }

    mfns = malloc(sizeof(*mfns));
    if ( !mfns )
    {
        ERROR("Cannot allocate memory for array of %u mfns", 1);
        goto out;
    }
    mfns[0] = p2m_mfn;
    off = 0;
    saved_mfn = 0;
    idx_start = idx_end = saved_idx = 0;

    for ( level = n_levels; level > 0; level-- )
    {
        n_pages = idx_end - idx_start + 1;
        ptes = xc_map_foreign_pages(xch, dom, PROT_READ, mfns, n_pages);
        if ( !ptes )
        {
            PERROR("Failed to map %u page table pages for p2m list", n_pages);
            goto out;
        }
        free(mfns);

        shift = level * 9 + 3;
        idx_start = ((p2m_vaddr - off) & mask) >> shift;
        idx_end = ((p2m_end - off) & mask) >> shift;
        idx = idx_end - idx_start + 1;
        mfns = malloc(sizeof(*mfns) * idx);
        if ( !mfns )
        {
            ERROR("Cannot allocate memory for array of %u mfns", idx);
            goto out;
        }

        for ( idx = idx_start; idx <= idx_end; idx++ )
        {
            mfn = (ptes[idx] & 0x000ffffffffff000ULL) >> PAGE_SHIFT;
            if ( mfn == 0 )
            {
                ERROR("Bad mfn %#lx during page table walk for vaddr %#" PRIx64 " at level %d of p2m list",
                      mfn, off + ((uint64_t)idx << shift), level);
                errno = ERANGE;
                goto out;
            }
            mfns[idx - idx_start] = mfn;

            /* Maximum pfn check at level 2. Same reasoning as for p2m tree. */
            if ( level == 2 )
            {
                if ( mfn != saved_mfn )
                {
                    saved_mfn = mfn;
                    saved_idx = idx - idx_start;
                }
            }
        }

        if ( level == 2 )
        {
            if ( saved_idx == idx_end )
                saved_idx++;
            max_pfn = ((xen_pfn_t)saved_idx << 9) * fpp;
            if ( max_pfn < dinfo->p2m_size )
            {
                dinfo->p2m_size = max_pfn;
                dinfo->p2m_frames = (dinfo->p2m_size + fpp - 1) / fpp;
                p2m_end = p2m_vaddr + dinfo->p2m_frames * PAGE_SIZE - 1;
                idx_end = idx_start + saved_idx;
            }
        }

        munmap(ptes, n_pages * PAGE_SIZE);
        ptes = NULL;
        off = p2m_vaddr & ((mask >> shift) << shift);
    }

    return mfns;

 out:
    free(mfns);
    if ( ptes )
        munmap(ptes, n_pages * PAGE_SIZE);

    return NULL;
}

static xen_pfn_t *
xc_core_arch_map_p2m_tree_rw(xc_interface *xch, struct domain_info_context *dinfo,
                             uint32_t dom, shared_info_any_t *live_shinfo)
{
    /* Double and single indirect references to the live P2M table */
    xen_pfn_t *live_p2m_frame_list_list = NULL;
    xen_pfn_t *live_p2m_frame_list = NULL;
    /* Copies of the above. */
    xen_pfn_t *p2m_frame_list_list = NULL;
    xen_pfn_t *p2m_frame_list = NULL;

    int err;
    int i;

    live_p2m_frame_list_list =
        xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ,
                             GET_FIELD(live_shinfo, arch.pfn_to_mfn_frame_list_list, dinfo->guest_width));

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

    dinfo->p2m_frames = P2M_FL_ENTRIES;

 out:
    err = errno;

    if ( live_p2m_frame_list_list )
        munmap(live_p2m_frame_list_list, PAGE_SIZE);

    if ( live_p2m_frame_list )
        munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

    free(p2m_frame_list_list);

    errno = err;

    return p2m_frame_list;
}

static int
xc_core_arch_map_p2m_rw(xc_interface *xch, struct domain_info_context *dinfo, xc_domaininfo_t *info,
                        shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m, int rw)
{
    xen_pfn_t *p2m_frame_list = NULL;
    uint64_t p2m_cr3;
    uint32_t dom = info->domain;
    int ret = -1;
    int err;

    if ( xc_domain_nr_gpfns(xch, info->domain, &dinfo->p2m_size) < 0 )
    {
        ERROR("Could not get maximum GPFN!");
        goto out;
    }

    if ( dinfo->p2m_size < info->tot_pages  )
    {
        ERROR("p2m_size < nr_pages -1 (%lx < %"PRIx64, dinfo->p2m_size, info->tot_pages - 1);
        goto out;
    }

    p2m_cr3 = GET_FIELD(live_shinfo, arch.p2m_cr3, dinfo->guest_width);

    p2m_frame_list = p2m_cr3 ? xc_core_arch_map_p2m_list_rw(xch, dinfo, dom, live_shinfo, p2m_cr3)
                             : xc_core_arch_map_p2m_tree_rw(xch, dinfo, dom, live_shinfo);

    if ( !p2m_frame_list )
        goto out;

    *live_p2m = xc_map_foreign_pages(xch, dom,
                                    rw ? (PROT_READ | PROT_WRITE) : PROT_READ,
                                    p2m_frame_list,
                                    dinfo->p2m_frames);

    if ( !*live_p2m )
    {
        PERROR("Couldn't map p2m table");
        goto out;
    }

    ret = 0;

out:
    err = errno;

    free(p2m_frame_list);

    errno = err;
    return ret;
}

int
xc_core_arch_map_p2m(xc_interface *xch, struct domain_info_context *dinfo, xc_domaininfo_t *info,
                        shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m)
{
    return xc_core_arch_map_p2m_rw(xch, dinfo, info, live_shinfo, live_p2m, 0);
}

int
xc_core_arch_map_p2m_writable(xc_interface *xch, struct domain_info_context *dinfo, xc_domaininfo_t *info,
                              shared_info_any_t *live_shinfo, xen_pfn_t **live_p2m)
{
    return xc_core_arch_map_p2m_rw(xch, dinfo, info, live_shinfo, live_p2m, 1);
}

int
xc_core_arch_get_scratch_gpfn(xc_interface *xch, uint32_t domid,
                              xen_pfn_t *gpfn)
{
    return xc_domain_nr_gpfns(xch, domid, gpfn);
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
