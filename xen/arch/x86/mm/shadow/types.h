/******************************************************************************
 * arch/x86/mm/shadow/types.h
 * 
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

#ifndef _XEN_SHADOW_TYPES_H
#define _XEN_SHADOW_TYPES_H

// Map a shadow page
static inline void *
map_shadow_page(mfn_t smfn)
{
    // XXX -- Possible optimization/measurement question for 32-bit and PAE
    //        hypervisors:
    //        How often is this smfn already available in the shadow linear
    //        table?  Might it be worth checking that table first,
    //        presumably using the reverse map hint in the page_info of this
    //        smfn, rather than calling map_domain_page()?
    //
    return sh_map_domain_page(smfn);
}

// matching unmap for map_shadow_page()
static inline void
unmap_shadow_page(void *p)
{
    sh_unmap_domain_page(p);
}

/* 
 * Define various types for handling pagetabels, based on these options:
 * SHADOW_PAGING_LEVELS : Number of levels of shadow pagetables
 * GUEST_PAGING_LEVELS  : Number of levels of guest pagetables
 */

#if (CONFIG_PAGING_LEVELS < SHADOW_PAGING_LEVELS) 
#error Cannot have more levels of shadow pagetables than host pagetables
#endif

#if (SHADOW_PAGING_LEVELS < GUEST_PAGING_LEVELS) 
#error Cannot have more levels of guest pagetables than shadow pagetables
#endif

#if SHADOW_PAGING_LEVELS == 2
#define SHADOW_L1_PAGETABLE_ENTRIES    1024
#define SHADOW_L2_PAGETABLE_ENTRIES    1024
#define SHADOW_L1_PAGETABLE_SHIFT        12
#define SHADOW_L2_PAGETABLE_SHIFT        22
#endif

#if SHADOW_PAGING_LEVELS == 3
#define SHADOW_L1_PAGETABLE_ENTRIES     512
#define SHADOW_L2_PAGETABLE_ENTRIES     512
#define SHADOW_L3_PAGETABLE_ENTRIES       4
#define SHADOW_L1_PAGETABLE_SHIFT        12
#define SHADOW_L2_PAGETABLE_SHIFT        21
#define SHADOW_L3_PAGETABLE_SHIFT        30
#endif

#if SHADOW_PAGING_LEVELS == 4
#define SHADOW_L1_PAGETABLE_ENTRIES     512
#define SHADOW_L2_PAGETABLE_ENTRIES     512
#define SHADOW_L3_PAGETABLE_ENTRIES     512
#define SHADOW_L4_PAGETABLE_ENTRIES     512
#define SHADOW_L1_PAGETABLE_SHIFT        12
#define SHADOW_L2_PAGETABLE_SHIFT        21
#define SHADOW_L3_PAGETABLE_SHIFT        30
#define SHADOW_L4_PAGETABLE_SHIFT        39
#endif

/* Types of the shadow page tables */
typedef l1_pgentry_t shadow_l1e_t;
typedef l2_pgentry_t shadow_l2e_t;
#if SHADOW_PAGING_LEVELS >= 3
typedef l3_pgentry_t shadow_l3e_t;
#if SHADOW_PAGING_LEVELS >= 4
typedef l4_pgentry_t shadow_l4e_t;
#endif
#endif

/* Access functions for them */
static inline paddr_t shadow_l1e_get_paddr(shadow_l1e_t sl1e)
{ return l1e_get_paddr(sl1e); }
static inline paddr_t shadow_l2e_get_paddr(shadow_l2e_t sl2e)
{ return l2e_get_paddr(sl2e); }
#if SHADOW_PAGING_LEVELS >= 3
static inline paddr_t shadow_l3e_get_paddr(shadow_l3e_t sl3e)
{ return l3e_get_paddr(sl3e); }
#if SHADOW_PAGING_LEVELS >= 4
static inline paddr_t shadow_l4e_get_paddr(shadow_l4e_t sl4e)
{ return l4e_get_paddr(sl4e); }
#endif
#endif

static inline mfn_t shadow_l1e_get_mfn(shadow_l1e_t sl1e)
{ return _mfn(l1e_get_pfn(sl1e)); }
static inline mfn_t shadow_l2e_get_mfn(shadow_l2e_t sl2e)
{ return _mfn(l2e_get_pfn(sl2e)); }
#if SHADOW_PAGING_LEVELS >= 3
static inline mfn_t shadow_l3e_get_mfn(shadow_l3e_t sl3e)
{ return _mfn(l3e_get_pfn(sl3e)); }
#if SHADOW_PAGING_LEVELS >= 4
static inline mfn_t shadow_l4e_get_mfn(shadow_l4e_t sl4e)
{ return _mfn(l4e_get_pfn(sl4e)); }
#endif
#endif

static inline u32 shadow_l1e_get_flags(shadow_l1e_t sl1e)
{ return l1e_get_flags(sl1e); }
static inline u32 shadow_l2e_get_flags(shadow_l2e_t sl2e)
{ return l2e_get_flags(sl2e); }
#if SHADOW_PAGING_LEVELS >= 3
static inline u32 shadow_l3e_get_flags(shadow_l3e_t sl3e)
{ return l3e_get_flags(sl3e); }
#if SHADOW_PAGING_LEVELS >= 4
static inline u32 shadow_l4e_get_flags(shadow_l4e_t sl4e)
{ return l4e_get_flags(sl4e); }
#endif
#endif

static inline shadow_l1e_t
shadow_l1e_remove_flags(shadow_l1e_t sl1e, u32 flags)
{ l1e_remove_flags(sl1e, flags); return sl1e; }

static inline shadow_l1e_t shadow_l1e_empty(void) 
{ return l1e_empty(); }
static inline shadow_l2e_t shadow_l2e_empty(void) 
{ return l2e_empty(); }
#if SHADOW_PAGING_LEVELS >= 3
static inline shadow_l3e_t shadow_l3e_empty(void) 
{ return l3e_empty(); }
#if SHADOW_PAGING_LEVELS >= 4
static inline shadow_l4e_t shadow_l4e_empty(void) 
{ return l4e_empty(); }
#endif
#endif

static inline shadow_l1e_t shadow_l1e_from_mfn(mfn_t mfn, u32 flags)
{ return l1e_from_pfn(mfn_x(mfn), flags); }
static inline shadow_l2e_t shadow_l2e_from_mfn(mfn_t mfn, u32 flags)
{ return l2e_from_pfn(mfn_x(mfn), flags); }
#if SHADOW_PAGING_LEVELS >= 3
static inline shadow_l3e_t shadow_l3e_from_mfn(mfn_t mfn, u32 flags)
{ return l3e_from_pfn(mfn_x(mfn), flags); }
#if SHADOW_PAGING_LEVELS >= 4
static inline shadow_l4e_t shadow_l4e_from_mfn(mfn_t mfn, u32 flags)
{ return l4e_from_pfn(mfn_x(mfn), flags); }
#endif
#endif

#define shadow_l1_table_offset(a) l1_table_offset(a)
#define shadow_l2_table_offset(a) l2_table_offset(a)
#define shadow_l3_table_offset(a) l3_table_offset(a)
#define shadow_l4_table_offset(a) l4_table_offset(a)

/**************************************************************************/
/* Access to the linear mapping of shadow page tables. */

/* Offsets into each level of the linear mapping for a virtual address. */
#define shadow_l1_linear_offset(_a)                                           \
        (((_a) & VADDR_MASK) >> SHADOW_L1_PAGETABLE_SHIFT)
#define shadow_l2_linear_offset(_a)                                           \
        (((_a) & VADDR_MASK) >> SHADOW_L2_PAGETABLE_SHIFT)
#define shadow_l3_linear_offset(_a)                                           \
        (((_a) & VADDR_MASK) >> SHADOW_L3_PAGETABLE_SHIFT)
#define shadow_l4_linear_offset(_a)                                           \
        (((_a) & VADDR_MASK) >> SHADOW_L4_PAGETABLE_SHIFT)

/* Where to find each level of the linear mapping.  For PV guests, we use 
 * the shadow linear-map self-entry as many times as we need.  For HVM 
 * guests, the shadow doesn't have a linear-map self-entry so we must use 
 * the monitor-table's linear-map entry N-1 times and then the shadow-map 
 * entry once. */
#define __sh_linear_l1_table ((shadow_l1e_t *)(SH_LINEAR_PT_VIRT_START))
#define __sh_linear_l2_table ((shadow_l2e_t *)                               \
    (__sh_linear_l1_table + shadow_l1_linear_offset(SH_LINEAR_PT_VIRT_START)))

// shadow linear L3 and L4 tables only exist in 4 level paging...
#if SHADOW_PAGING_LEVELS == 4
#define __sh_linear_l3_table ((shadow_l3e_t *)                               \
    (__sh_linear_l2_table + shadow_l2_linear_offset(SH_LINEAR_PT_VIRT_START)))
#define __sh_linear_l4_table ((shadow_l4e_t *)                               \
    (__sh_linear_l3_table + shadow_l3_linear_offset(SH_LINEAR_PT_VIRT_START)))
#endif

#define sh_linear_l1_table(v) ({ \
    ASSERT(current == (v)); \
    __sh_linear_l1_table; \
})

// XXX -- these should not be conditional on is_hvm_vcpu(v), but rather on
//        shadow_mode_external(d)...
//
#define sh_linear_l2_table(v) ({ \
    ASSERT(current == (v)); \
    ((shadow_l2e_t *) \
     (is_hvm_vcpu(v) ? __linear_l1_table : __sh_linear_l1_table) + \
     shadow_l1_linear_offset(SH_LINEAR_PT_VIRT_START)); \
})

#if SHADOW_PAGING_LEVELS >= 4
#define sh_linear_l3_table(v) ({ \
    ASSERT(current == (v)); \
    ((shadow_l3e_t *) \
     (is_hvm_vcpu(v) ? __linear_l2_table : __sh_linear_l2_table) + \
      shadow_l2_linear_offset(SH_LINEAR_PT_VIRT_START)); \
})

// we use l4_pgentry_t instead of shadow_l4e_t below because shadow_l4e_t is
// not defined for when xen_levels==4 & shadow_levels==3...
#define sh_linear_l4_table(v) ({ \
    ASSERT(current == (v)); \
    ((l4_pgentry_t *) \
     (is_hvm_vcpu(v) ? __linear_l3_table : __sh_linear_l3_table) + \
      shadow_l3_linear_offset(SH_LINEAR_PT_VIRT_START)); \
})
#endif

#if GUEST_PAGING_LEVELS == 2

#include "page-guest32.h"

#define GUEST_L1_PAGETABLE_ENTRIES     1024
#define GUEST_L2_PAGETABLE_ENTRIES     1024
#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         22

/* Type of the guest's frame numbers */
TYPE_SAFE(u32,gfn)
#define INVALID_GFN ((u32)(-1u))
#define SH_PRI_gfn "05x"

/* Types of the guest's page tables */
typedef l1_pgentry_32_t guest_l1e_t;
typedef l2_pgentry_32_t guest_l2e_t;

/* Access functions for them */
static inline paddr_t guest_l1e_get_paddr(guest_l1e_t gl1e)
{ return l1e_get_paddr_32(gl1e); }
static inline paddr_t guest_l2e_get_paddr(guest_l2e_t gl2e)
{ return l2e_get_paddr_32(gl2e); }

static inline gfn_t guest_l1e_get_gfn(guest_l1e_t gl1e)
{ return _gfn(l1e_get_paddr_32(gl1e) >> PAGE_SHIFT); }
static inline gfn_t guest_l2e_get_gfn(guest_l2e_t gl2e)
{ return _gfn(l2e_get_paddr_32(gl2e) >> PAGE_SHIFT); }

static inline u32 guest_l1e_get_flags(guest_l1e_t gl1e)
{ return l1e_get_flags_32(gl1e); }
static inline u32 guest_l2e_get_flags(guest_l2e_t gl2e)
{ return l2e_get_flags_32(gl2e); }

static inline guest_l1e_t guest_l1e_add_flags(guest_l1e_t gl1e, u32 flags)
{ l1e_add_flags_32(gl1e, flags); return gl1e; }
static inline guest_l2e_t guest_l2e_add_flags(guest_l2e_t gl2e, u32 flags)
{ l2e_add_flags_32(gl2e, flags); return gl2e; }

static inline guest_l1e_t guest_l1e_from_gfn(gfn_t gfn, u32 flags)
{ return l1e_from_pfn_32(gfn_x(gfn), flags); }
static inline guest_l2e_t guest_l2e_from_gfn(gfn_t gfn, u32 flags)
{ return l2e_from_pfn_32(gfn_x(gfn), flags); }

#define guest_l1_table_offset(a) l1_table_offset_32(a)
#define guest_l2_table_offset(a) l2_table_offset_32(a)

/* The shadow types needed for the various levels. */
#define SH_type_l1_shadow  SH_type_l1_32_shadow
#define SH_type_l2_shadow  SH_type_l2_32_shadow
#define SH_type_fl1_shadow SH_type_fl1_32_shadow

#else /* GUEST_PAGING_LEVELS != 2 */

#if GUEST_PAGING_LEVELS == 3
#define GUEST_L1_PAGETABLE_ENTRIES      512
#define GUEST_L2_PAGETABLE_ENTRIES      512
#define GUEST_L3_PAGETABLE_ENTRIES        4
#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         21
#define GUEST_L3_PAGETABLE_SHIFT         30
#else /* GUEST_PAGING_LEVELS == 4 */
#define GUEST_L1_PAGETABLE_ENTRIES      512
#define GUEST_L2_PAGETABLE_ENTRIES      512
#define GUEST_L3_PAGETABLE_ENTRIES      512
#define GUEST_L4_PAGETABLE_ENTRIES      512
#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         21
#define GUEST_L3_PAGETABLE_SHIFT         30
#define GUEST_L4_PAGETABLE_SHIFT         39
#endif

/* Type of the guest's frame numbers */
TYPE_SAFE(unsigned long,gfn)
#define INVALID_GFN ((unsigned long)(-1ul))
#define SH_PRI_gfn "05lx"

/* Types of the guest's page tables */
typedef l1_pgentry_t guest_l1e_t;
typedef l2_pgentry_t guest_l2e_t;
typedef l3_pgentry_t guest_l3e_t;
#if GUEST_PAGING_LEVELS >= 4
typedef l4_pgentry_t guest_l4e_t;
#endif

/* Access functions for them */
static inline paddr_t guest_l1e_get_paddr(guest_l1e_t gl1e)
{ return l1e_get_paddr(gl1e); }
static inline paddr_t guest_l2e_get_paddr(guest_l2e_t gl2e)
{ return l2e_get_paddr(gl2e); }
static inline paddr_t guest_l3e_get_paddr(guest_l3e_t gl3e)
{ return l3e_get_paddr(gl3e); }
#if GUEST_PAGING_LEVELS >= 4
static inline paddr_t guest_l4e_get_paddr(guest_l4e_t gl4e)
{ return l4e_get_paddr(gl4e); }
#endif

static inline gfn_t guest_l1e_get_gfn(guest_l1e_t gl1e)
{ return _gfn(l1e_get_paddr(gl1e) >> PAGE_SHIFT); }
static inline gfn_t guest_l2e_get_gfn(guest_l2e_t gl2e)
{ return _gfn(l2e_get_paddr(gl2e) >> PAGE_SHIFT); }
static inline gfn_t guest_l3e_get_gfn(guest_l3e_t gl3e)
{ return _gfn(l3e_get_paddr(gl3e) >> PAGE_SHIFT); }
#if GUEST_PAGING_LEVELS >= 4
static inline gfn_t guest_l4e_get_gfn(guest_l4e_t gl4e)
{ return _gfn(l4e_get_paddr(gl4e) >> PAGE_SHIFT); }
#endif

static inline u32 guest_l1e_get_flags(guest_l1e_t gl1e)
{ return l1e_get_flags(gl1e); }
static inline u32 guest_l2e_get_flags(guest_l2e_t gl2e)
{ return l2e_get_flags(gl2e); }
static inline u32 guest_l3e_get_flags(guest_l3e_t gl3e)
{ return l3e_get_flags(gl3e); }
#if GUEST_PAGING_LEVELS >= 4
static inline u32 guest_l4e_get_flags(guest_l4e_t gl4e)
{ return l4e_get_flags(gl4e); }
#endif

static inline guest_l1e_t guest_l1e_add_flags(guest_l1e_t gl1e, u32 flags)
{ l1e_add_flags(gl1e, flags); return gl1e; }
static inline guest_l2e_t guest_l2e_add_flags(guest_l2e_t gl2e, u32 flags)
{ l2e_add_flags(gl2e, flags); return gl2e; }
static inline guest_l3e_t guest_l3e_add_flags(guest_l3e_t gl3e, u32 flags)
{ l3e_add_flags(gl3e, flags); return gl3e; }
#if GUEST_PAGING_LEVELS >= 4
static inline guest_l4e_t guest_l4e_add_flags(guest_l4e_t gl4e, u32 flags)
{ l4e_add_flags(gl4e, flags); return gl4e; }
#endif

static inline guest_l1e_t guest_l1e_from_gfn(gfn_t gfn, u32 flags)
{ return l1e_from_pfn(gfn_x(gfn), flags); }
static inline guest_l2e_t guest_l2e_from_gfn(gfn_t gfn, u32 flags)
{ return l2e_from_pfn(gfn_x(gfn), flags); }
static inline guest_l3e_t guest_l3e_from_gfn(gfn_t gfn, u32 flags)
{ return l3e_from_pfn(gfn_x(gfn), flags); }
#if GUEST_PAGING_LEVELS >= 4
static inline guest_l4e_t guest_l4e_from_gfn(gfn_t gfn, u32 flags)
{ return l4e_from_pfn(gfn_x(gfn), flags); }
#endif

#define guest_l1_table_offset(a) l1_table_offset(a)
#define guest_l2_table_offset(a) l2_table_offset(a)
#define guest_l3_table_offset(a) l3_table_offset(a)
#define guest_l4_table_offset(a) l4_table_offset(a)

/* The shadow types needed for the various levels. */
#if GUEST_PAGING_LEVELS == 3
#define SH_type_l1_shadow  SH_type_l1_pae_shadow
#define SH_type_fl1_shadow SH_type_fl1_pae_shadow
#define SH_type_l2_shadow  SH_type_l2_pae_shadow
#define SH_type_l2h_shadow SH_type_l2h_pae_shadow
#else
#define SH_type_l1_shadow  SH_type_l1_64_shadow
#define SH_type_fl1_shadow SH_type_fl1_64_shadow
#define SH_type_l2_shadow  SH_type_l2_64_shadow
#define SH_type_l2h_shadow SH_type_l2h_64_shadow
#define SH_type_l3_shadow  SH_type_l3_64_shadow
#define SH_type_l4_shadow  SH_type_l4_64_shadow
#endif

#endif /* GUEST_PAGING_LEVELS != 2 */

#define VALID_GFN(m) (m != INVALID_GFN)

static inline int
valid_gfn(gfn_t m)
{
    return VALID_GFN(gfn_x(m));
}

/* Translation between mfns and gfns */

// vcpu-specific version of gfn_to_mfn().  This is where we hide the dirty
// little secret that, for hvm guests with paging disabled, nearly all of the
// shadow code actually think that the guest is running on *untranslated* page
// tables (which is actually domain->phys_table).
//

static inline mfn_t
vcpu_gfn_to_mfn(struct vcpu *v, gfn_t gfn)
{
    if ( !paging_vcpu_mode_translate(v) )
        return _mfn(gfn_x(gfn));
    return gfn_to_mfn(v->domain, gfn_x(gfn));
}

static inline paddr_t
gfn_to_paddr(gfn_t gfn)
{
    return ((paddr_t)gfn_x(gfn)) << PAGE_SHIFT;
}

/* Type used for recording a walk through guest pagetables.  It is
 * filled in by the pagetable walk function, and also used as a cache
 * for later walks.  
 * Any non-null pointer in this structure represents a mapping of guest
 * memory.  We must always call walk_init() before using a walk_t, and 
 * call walk_unmap() when we're done. 
 * The "Effective l1e" field is used when there isn't an l1e to point to, 
 * but we have fabricated an l1e for propagation to the shadow (e.g., 
 * for splintering guest superpages into many shadow l1 entries).  */
typedef struct shadow_walk_t walk_t;
struct shadow_walk_t 
{
    unsigned long va;           /* Address we were looking for */
#if GUEST_PAGING_LEVELS >= 3
#if GUEST_PAGING_LEVELS >= 4
    guest_l4e_t *l4e;           /* Pointer to guest's level 4 entry */
#endif
    guest_l3e_t *l3e;           /* Pointer to guest's level 3 entry */
#endif
    guest_l2e_t *l2e;           /* Pointer to guest's level 2 entry */
    guest_l1e_t *l1e;           /* Pointer to guest's level 1 entry */
    guest_l1e_t eff_l1e;        /* Effective level 1 entry */
#if GUEST_PAGING_LEVELS >= 4
    mfn_t l4mfn;                /* MFN that the level 4 entry is in */
    mfn_t l3mfn;                /* MFN that the level 3 entry is in */
#endif
    mfn_t l2mfn;                /* MFN that the level 2 entry is in */
    mfn_t l1mfn;                /* MFN that the level 1 entry is in */
};

/* macros for dealing with the naming of the internal function names of the
 * shadow code's external entry points.
 */
#define INTERNAL_NAME(name) \
    SHADOW_INTERNAL_NAME(name, SHADOW_PAGING_LEVELS, GUEST_PAGING_LEVELS)

/* macros for renaming the primary entry points, so that they are more
 * easily distinguished from a debugger
 */
#define sh_page_fault              INTERNAL_NAME(sh_page_fault)
#define sh_invlpg                  INTERNAL_NAME(sh_invlpg)
#define sh_gva_to_gpa              INTERNAL_NAME(sh_gva_to_gpa)
#define sh_gva_to_gfn              INTERNAL_NAME(sh_gva_to_gfn)
#define sh_update_cr3              INTERNAL_NAME(sh_update_cr3)
#define sh_rm_write_access_from_l1 INTERNAL_NAME(sh_rm_write_access_from_l1)
#define sh_rm_mappings_from_l1     INTERNAL_NAME(sh_rm_mappings_from_l1)
#define sh_remove_l1_shadow        INTERNAL_NAME(sh_remove_l1_shadow)
#define sh_remove_l2_shadow        INTERNAL_NAME(sh_remove_l2_shadow)
#define sh_remove_l3_shadow        INTERNAL_NAME(sh_remove_l3_shadow)
#define sh_map_and_validate_gl4e   INTERNAL_NAME(sh_map_and_validate_gl4e)
#define sh_map_and_validate_gl3e   INTERNAL_NAME(sh_map_and_validate_gl3e)
#define sh_map_and_validate_gl2e   INTERNAL_NAME(sh_map_and_validate_gl2e)
#define sh_map_and_validate_gl2he  INTERNAL_NAME(sh_map_and_validate_gl2he)
#define sh_map_and_validate_gl1e   INTERNAL_NAME(sh_map_and_validate_gl1e)
#define sh_destroy_l4_shadow       INTERNAL_NAME(sh_destroy_l4_shadow)
#define sh_destroy_l3_shadow       INTERNAL_NAME(sh_destroy_l3_shadow)
#define sh_destroy_l2_shadow       INTERNAL_NAME(sh_destroy_l2_shadow)
#define sh_destroy_l1_shadow       INTERNAL_NAME(sh_destroy_l1_shadow)
#define sh_unhook_32b_mappings     INTERNAL_NAME(sh_unhook_32b_mappings)
#define sh_unhook_pae_mappings     INTERNAL_NAME(sh_unhook_pae_mappings)
#define sh_unhook_64b_mappings     INTERNAL_NAME(sh_unhook_64b_mappings)
#define sh_paging_mode             INTERNAL_NAME(sh_paging_mode)
#define sh_detach_old_tables       INTERNAL_NAME(sh_detach_old_tables)
#define sh_x86_emulate_write       INTERNAL_NAME(sh_x86_emulate_write)
#define sh_x86_emulate_cmpxchg     INTERNAL_NAME(sh_x86_emulate_cmpxchg)
#define sh_x86_emulate_cmpxchg8b   INTERNAL_NAME(sh_x86_emulate_cmpxchg8b)
#define sh_audit_l1_table          INTERNAL_NAME(sh_audit_l1_table)
#define sh_audit_fl1_table         INTERNAL_NAME(sh_audit_fl1_table)
#define sh_audit_l2_table          INTERNAL_NAME(sh_audit_l2_table)
#define sh_audit_l3_table          INTERNAL_NAME(sh_audit_l3_table)
#define sh_audit_l4_table          INTERNAL_NAME(sh_audit_l4_table)
#define sh_guess_wrmap             INTERNAL_NAME(sh_guess_wrmap)
#define sh_clear_shadow_entry      INTERNAL_NAME(sh_clear_shadow_entry)

/* The sh_guest_(map|get)_* functions only depends on the number of config
 * levels
 */
#define sh_guest_map_l1e                                       \
        SHADOW_INTERNAL_NAME(sh_guest_map_l1e,                \
                              CONFIG_PAGING_LEVELS,             \
                              CONFIG_PAGING_LEVELS)
#define sh_guest_get_eff_l1e                                   \
        SHADOW_INTERNAL_NAME(sh_guest_get_eff_l1e,            \
                              CONFIG_PAGING_LEVELS,             \
                              CONFIG_PAGING_LEVELS)

/* sh_make_monitor_table only depends on the number of shadow levels */
#define sh_make_monitor_table                                  \
        SHADOW_INTERNAL_NAME(sh_make_monitor_table,           \
                              SHADOW_PAGING_LEVELS,             \
                              SHADOW_PAGING_LEVELS)
#define sh_destroy_monitor_table                               \
        SHADOW_INTERNAL_NAME(sh_destroy_monitor_table,        \
                              SHADOW_PAGING_LEVELS,             \
                              SHADOW_PAGING_LEVELS)


#if SHADOW_PAGING_LEVELS == 3
#define MFN_FITS_IN_HVM_CR3(_MFN) !(mfn_x(_MFN) >> 20)
#endif

#if SHADOW_PAGING_LEVELS == 2
#define SH_PRI_pte "08x"
#else /* SHADOW_PAGING_LEVELS >= 3 */
#ifndef __x86_64__
#define SH_PRI_pte "016llx"
#else
#define SH_PRI_pte "016lx"
#endif
#endif /* SHADOW_PAGING_LEVELS >= 3 */

#if GUEST_PAGING_LEVELS == 2
#define SH_PRI_gpte "08x"
#else /* GUEST_PAGING_LEVELS >= 3 */
#ifndef __x86_64__
#define SH_PRI_gpte "016llx"
#else
#define SH_PRI_gpte "016lx"
#endif
#endif /* GUEST_PAGING_LEVELS >= 3 */

static inline u32
accumulate_guest_flags(struct vcpu *v, walk_t *gw)
{
    u32 accumulated_flags;

    // We accumulate the permission flags with bitwise ANDing.
    // This works for the PRESENT bit, RW bit, and USER bit.
    // For the NX bit, however, the polarity is wrong, so we accumulate the
    // inverse of the NX bit.
    //
    accumulated_flags =  guest_l1e_get_flags(gw->eff_l1e) ^ _PAGE_NX_BIT;
    accumulated_flags &= guest_l2e_get_flags(*gw->l2e) ^ _PAGE_NX_BIT;

    // Note that PAE guests do not have USER or RW or NX bits in their L3s.
    //
#if GUEST_PAGING_LEVELS == 3
    accumulated_flags &=
        ~_PAGE_PRESENT | (guest_l3e_get_flags(*gw->l3e) & _PAGE_PRESENT);
#elif GUEST_PAGING_LEVELS >= 4
    accumulated_flags &= guest_l3e_get_flags(*gw->l3e) ^ _PAGE_NX_BIT;
    accumulated_flags &= guest_l4e_get_flags(*gw->l4e) ^ _PAGE_NX_BIT;
#endif

    // Revert the NX bit back to its original polarity
    accumulated_flags ^= _PAGE_NX_BIT;

    // In 64-bit PV guests, the _PAGE_USER bit is implied in all guest
    // entries (since even the guest kernel runs in ring 3).
    //
    if ( (GUEST_PAGING_LEVELS == 4) && !is_hvm_vcpu(v) )
        accumulated_flags |= _PAGE_USER;

    return accumulated_flags;
}


#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH) && SHADOW_PAGING_LEVELS > 2
/******************************************************************************
 * We implement a "fast path" for two special cases: faults that require
 * MMIO emulation, and faults where the guest PTE is not present.  We
 * record these as shadow l1 entries that have reserved bits set in
 * them, so we can spot them immediately in the fault handler and handle
 * them without needing to hold the shadow lock or walk the guest
 * pagetables.
 *
 * This is only feasible for PAE and 64bit Xen: 32-bit non-PAE PTEs don't
 * have reserved bits that we can use for this.
 */

#define SH_L1E_MAGIC 0xffffffff00000000ULL
static inline int sh_l1e_is_magic(shadow_l1e_t sl1e)
{
    return ((sl1e.l1 & SH_L1E_MAGIC) == SH_L1E_MAGIC);
}

/* Guest not present: a single magic value */
static inline shadow_l1e_t sh_l1e_gnp(void) 
{
    return (shadow_l1e_t){ -1ULL };
}

static inline int sh_l1e_is_gnp(shadow_l1e_t sl1e) 
{
    return (sl1e.l1 == sh_l1e_gnp().l1);
}

/* MMIO: an invalid PTE that contains the GFN of the equivalent guest l1e.
 * We store 28 bits of GFN in bits 4:32 of the entry.
 * The present bit is set, and the U/S and R/W bits are taken from the guest.
 * Bit 3 is always 0, to differentiate from gnp above.  */
#define SH_L1E_MMIO_MAGIC       0xffffffff00000001ULL
#define SH_L1E_MMIO_MAGIC_MASK  0xffffffff00000009ULL
#define SH_L1E_MMIO_GFN_MASK    0x00000000fffffff0ULL
#define SH_L1E_MMIO_GFN_SHIFT   4

static inline shadow_l1e_t sh_l1e_mmio(gfn_t gfn, u32 gflags) 
{
    return (shadow_l1e_t) { (SH_L1E_MMIO_MAGIC 
                             | (gfn_x(gfn) << SH_L1E_MMIO_GFN_SHIFT) 
                             | (gflags & (_PAGE_USER|_PAGE_RW))) };
}

static inline int sh_l1e_is_mmio(shadow_l1e_t sl1e) 
{
    return ((sl1e.l1 & SH_L1E_MMIO_MAGIC_MASK) == SH_L1E_MMIO_MAGIC);
}

static inline gfn_t sh_l1e_mmio_get_gfn(shadow_l1e_t sl1e) 
{
    return _gfn((sl1e.l1 & SH_L1E_MMIO_GFN_MASK) >> SH_L1E_MMIO_GFN_SHIFT);
}

static inline u32 sh_l1e_mmio_get_flags(shadow_l1e_t sl1e) 
{
    return (u32)((sl1e.l1 & (_PAGE_USER|_PAGE_RW)));
}

#else

#define sh_l1e_gnp() shadow_l1e_empty()
#define sh_l1e_mmio(_gfn, _flags) shadow_l1e_empty()
#define sh_l1e_is_magic(_e) (0)

#endif /* SHOPT_FAST_FAULT_PATH */


#endif /* _XEN_SHADOW_TYPES_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
