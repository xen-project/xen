/******************************************************************************
 * include/asm-x86/paging.h
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _XEN_P2M_H
#define _XEN_P2M_H


/* The phys_to_machine_mapping is the reversed mapping of MPT for full
 * virtualization.  It is only used by shadow_mode_translate()==true
 * guests, so we steal the address space that would have normally
 * been used by the read-only MPT map.
 */
#define phys_to_machine_mapping ((l1_pgentry_t *)RO_MPT_VIRT_START)


/* Read the current domain's P2M table. */
static inline mfn_t gfn_to_mfn_current(unsigned long gfn)
{
    l1_pgentry_t l1e = l1e_empty();
    int ret;

    if ( gfn > current->domain->arch.p2m.max_mapped_pfn )
        return _mfn(INVALID_MFN);

    /* Don't read off the end of the p2m table */
    ASSERT(gfn < (RO_MPT_VIRT_END - RO_MPT_VIRT_START) / sizeof(l1_pgentry_t));

    ret = __copy_from_user(&l1e,
                           &phys_to_machine_mapping[gfn],
                           sizeof(l1e));

    if ( (ret == 0) && (l1e_get_flags(l1e) & _PAGE_PRESENT) )
        return _mfn(l1e_get_pfn(l1e));

    return _mfn(INVALID_MFN);
}

/* Read another domain's P2M table, mapping pages as we go */
mfn_t gfn_to_mfn_foreign(struct domain *d, unsigned long gpfn);

/* General conversion function from gfn to mfn */
static inline mfn_t gfn_to_mfn(struct domain *d, unsigned long gfn)
{
    if ( !paging_mode_translate(d) )
        return _mfn(gfn);
    if ( likely(current->domain == d) )
        return gfn_to_mfn_current(gfn);
    else 
        return gfn_to_mfn_foreign(d, gfn);
}

/* General conversion function from mfn to gfn */
static inline unsigned long mfn_to_gfn(struct domain *d, mfn_t mfn)
{
    if ( paging_mode_translate(d) )
        return get_gpfn_from_mfn(mfn_x(mfn));
    else
        return mfn_x(mfn);
}

/* Compatibility function for HVM code */
static inline unsigned long get_mfn_from_gpfn(unsigned long pfn)
{
    return mfn_x(gfn_to_mfn_current(pfn));
}

/* Is this guest address an mmio one? (i.e. not defined in p2m map) */
static inline int mmio_space(paddr_t gpa)
{
    unsigned long gfn = gpa >> PAGE_SHIFT;    
    return !mfn_valid(mfn_x(gfn_to_mfn_current(gfn)));
}

/* Translate the frame number held in an l1e from guest to machine */
static inline l1_pgentry_t
gl1e_to_ml1e(struct domain *d, l1_pgentry_t l1e)
{
    if ( unlikely(paging_mode_translate(d)) )
        l1e = l1e_from_pfn(gmfn_to_mfn(d, l1e_get_pfn(l1e)),
                           l1e_get_flags(l1e));
    return l1e;
}



/* Init the datastructures for later use by the p2m code */
void p2m_init(struct domain *d);

/* Allocate a new p2m table for a domain. 
 *
 * The alloc_page and free_page functions will be used to get memory to
 * build the p2m, and to release it again at the end of day. 
 *
 * Returns 0 for success or -errno. */
int p2m_alloc_table(struct domain *d,
                    struct page_info * (*alloc_page)(struct domain *d),
                    void (*free_page)(struct domain *d, struct page_info *pg));

/* Return all the p2m resources to Xen. */
void p2m_teardown(struct domain *d);

/* Add a page to a domain's p2m table */
void guest_physmap_add_page(struct domain *d, unsigned long gfn,
                            unsigned long mfn);

/* Remove a page from a domain's p2m table */
void guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                               unsigned long mfn);


#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
