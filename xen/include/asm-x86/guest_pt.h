/******************************************************************************
 * xen/asm-x86/guest_pt.h
 *
 * Types and accessors for guest pagetable entries, as distinct from
 * Xen's pagetable types. 
 *
 * Users must #define GUEST_PAGING_LEVELS to 2, 3 or 4 before including
 * this file.
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

#ifndef _XEN_ASM_GUEST_PT_H
#define _XEN_ASM_GUEST_PT_H

/* Type of the guest's frame numbers */
TYPE_SAFE(unsigned long,gfn)
#define PRI_gfn "05lx"

#define VALID_GFN(m) (m != INVALID_GFN)

static inline int
valid_gfn(gfn_t m)
{
    return VALID_GFN(gfn_x(m));
}

static inline paddr_t
gfn_to_paddr(gfn_t gfn)
{
    return ((paddr_t)gfn_x(gfn)) << PAGE_SHIFT;
}

/* Override gfn_to_mfn to work with gfn_t */
#undef gfn_to_mfn
#define gfn_to_mfn(d, g, t) _gfn_to_mfn((d), gfn_x(g), (t))


/* Types of the guest's page tables and access functions for them */

#if GUEST_PAGING_LEVELS == 2

#define GUEST_L1_PAGETABLE_ENTRIES     1024
#define GUEST_L2_PAGETABLE_ENTRIES     1024
#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         22

typedef uint32_t guest_intpte_t;
typedef struct { guest_intpte_t l1; } guest_l1e_t;
typedef struct { guest_intpte_t l2; } guest_l2e_t;

#define PRI_gpte "08x"

static inline paddr_t guest_l1e_get_paddr(guest_l1e_t gl1e)
{ return ((paddr_t) gl1e.l1) & (PADDR_MASK & PAGE_MASK); }
static inline paddr_t guest_l2e_get_paddr(guest_l2e_t gl2e)
{ return ((paddr_t) gl2e.l2) & (PADDR_MASK & PAGE_MASK); }

static inline gfn_t guest_l1e_get_gfn(guest_l1e_t gl1e)
{ return _gfn(guest_l1e_get_paddr(gl1e) >> PAGE_SHIFT); }
static inline gfn_t guest_l2e_get_gfn(guest_l2e_t gl2e)
{ return _gfn(guest_l2e_get_paddr(gl2e) >> PAGE_SHIFT); }

static inline u32 guest_l1e_get_flags(guest_l1e_t gl1e)
{ return gl1e.l1 & 0xfff; }
static inline u32 guest_l2e_get_flags(guest_l2e_t gl2e)
{ return gl2e.l2 & 0xfff; }

static inline guest_l1e_t guest_l1e_from_gfn(gfn_t gfn, u32 flags)
{ return (guest_l1e_t) { (gfn_x(gfn) << PAGE_SHIFT) | flags }; }
static inline guest_l2e_t guest_l2e_from_gfn(gfn_t gfn, u32 flags)
{ return (guest_l2e_t) { (gfn_x(gfn) << PAGE_SHIFT) | flags }; }

#define guest_l1_table_offset(_va)                                           \
    (((_va) >> GUEST_L1_PAGETABLE_SHIFT) & (GUEST_L1_PAGETABLE_ENTRIES - 1))
#define guest_l2_table_offset(_va)                                           \
    (((_va) >> GUEST_L2_PAGETABLE_SHIFT) & (GUEST_L2_PAGETABLE_ENTRIES - 1))

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

typedef l1_pgentry_t guest_l1e_t;
typedef l2_pgentry_t guest_l2e_t;
typedef l3_pgentry_t guest_l3e_t;
#if GUEST_PAGING_LEVELS >= 4
typedef l4_pgentry_t guest_l4e_t;
#endif
typedef intpte_t guest_intpte_t;

#define PRI_gpte "016"PRIx64

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

#endif /* GUEST_PAGING_LEVELS != 2 */


/* Type used for recording a walk through guest pagetables.  It is
 * filled in by the pagetable walk function, and also used as a cache
 * for later walks.  When we encounter a superpage l2e, we fabricate an
 * l1e for propagation to the shadow (for splintering guest superpages
 * into many shadow l1 entries).  */
typedef struct guest_pagetable_walk walk_t;
struct guest_pagetable_walk
{
    unsigned long va;           /* Address we were looking for */
#if GUEST_PAGING_LEVELS >= 3
#if GUEST_PAGING_LEVELS >= 4
    guest_l4e_t l4e;            /* Guest's level 4 entry */
#endif
    guest_l3e_t l3e;            /* Guest's level 3 entry */
#endif
    guest_l2e_t l2e;            /* Guest's level 2 entry */
    guest_l1e_t l1e;            /* Guest's level 1 entry (or fabrication) */
#if GUEST_PAGING_LEVELS >= 4
    mfn_t l4mfn;                /* MFN that the level 4 entry was in */
    mfn_t l3mfn;                /* MFN that the level 3 entry was in */
#endif
    mfn_t l2mfn;                /* MFN that the level 2 entry was in */
    mfn_t l1mfn;                /* MFN that the level 1 entry was in */
};

#endif /* _XEN_ASM_GUEST_PT_H */
