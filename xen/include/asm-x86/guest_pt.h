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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _XEN_ASM_GUEST_PT_H
#define _XEN_ASM_GUEST_PT_H

#if !defined(GUEST_PAGING_LEVELS)
#error GUEST_PAGING_LEVELS not defined
#endif

static inline paddr_t
gfn_to_paddr(gfn_t gfn)
{
    return ((paddr_t)gfn_x(gfn)) << PAGE_SHIFT;
}

/* Override get_gfn to work with gfn_t */
#undef get_gfn
#define get_gfn(d, g, t) get_gfn_type((d), gfn_x(g), (t), P2M_ALLOC)

/* Mask covering the reserved bits from superpage alignment. */
#define SUPERPAGE_RSVD(bit)                                             \
    (((1ul << (bit)) - 1) & ~(_PAGE_PSE_PAT | (_PAGE_PSE_PAT - 1ul)))

static inline uint32_t fold_pse36(uint64_t val)
{
    return (val & ~(0x1fful << 13)) | ((val & (0x1fful << 32)) >> (32 - 13));
}
static inline uint64_t unfold_pse36(uint32_t val)
{
    return (val & ~(0x1fful << 13)) | ((val & (0x1fful << 13)) << (32 - 13));
}

/* Types of the guest's page tables and access functions for them */

#if GUEST_PAGING_LEVELS == 2

#define GUEST_L1_PAGETABLE_ENTRIES     1024
#define GUEST_L2_PAGETABLE_ENTRIES     1024

#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         22

#define GUEST_L1_PAGETABLE_RSVD           0
#define GUEST_L2_PAGETABLE_RSVD           0

typedef uint32_t guest_intpte_t;
typedef struct { guest_intpte_t l1; } guest_l1e_t;
typedef struct { guest_intpte_t l2; } guest_l2e_t;

#define PRI_gpte "08x"

static inline gfn_t guest_l1e_get_gfn(guest_l1e_t gl1e)
{ return _gfn(gl1e.l1 >> PAGE_SHIFT); }
static inline gfn_t guest_l2e_get_gfn(guest_l2e_t gl2e)
{ return _gfn(gl2e.l2 >> PAGE_SHIFT); }

static inline u32 guest_l1e_get_flags(guest_l1e_t gl1e)
{ return gl1e.l1 & 0xfff; }
static inline u32 guest_l2e_get_flags(guest_l2e_t gl2e)
{ return gl2e.l2 & 0xfff; }

static inline u32 guest_l1e_get_pkey(guest_l1e_t gl1e)
{ return 0; }
static inline u32 guest_l2e_get_pkey(guest_l2e_t gl2e)
{ return 0; }

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

#define GUEST_L1_PAGETABLE_RSVD            0x7ff0000000000000ul
#define GUEST_L2_PAGETABLE_RSVD            0x7ff0000000000000ul
#define GUEST_L3_PAGETABLE_RSVD                                      \
    (0xfff0000000000000ul | _PAGE_GLOBAL | _PAGE_PSE | _PAGE_DIRTY | \
     _PAGE_ACCESSED | _PAGE_USER | _PAGE_RW)

#else /* GUEST_PAGING_LEVELS == 4 */

#define GUEST_L1_PAGETABLE_ENTRIES      512
#define GUEST_L2_PAGETABLE_ENTRIES      512
#define GUEST_L3_PAGETABLE_ENTRIES      512
#define GUEST_L4_PAGETABLE_ENTRIES      512

#define GUEST_L1_PAGETABLE_SHIFT         12
#define GUEST_L2_PAGETABLE_SHIFT         21
#define GUEST_L3_PAGETABLE_SHIFT         30
#define GUEST_L4_PAGETABLE_SHIFT         39

#define GUEST_L1_PAGETABLE_RSVD            0
#define GUEST_L2_PAGETABLE_RSVD            0
#define GUEST_L3_PAGETABLE_RSVD            0
/* NB L4e._PAGE_GLOBAL is reserved for AMD, but ignored for Intel. */
#define GUEST_L4_PAGETABLE_RSVD            _PAGE_PSE

#endif

typedef l1_pgentry_t guest_l1e_t;
typedef l2_pgentry_t guest_l2e_t;
typedef l3_pgentry_t guest_l3e_t;
#if GUEST_PAGING_LEVELS >= 4
typedef l4_pgentry_t guest_l4e_t;
#endif
typedef intpte_t guest_intpte_t;

#define PRI_gpte "016"PRIx64

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

static inline u32 guest_l1e_get_pkey(guest_l1e_t gl1e)
{ return l1e_get_pkey(gl1e); }
static inline u32 guest_l2e_get_pkey(guest_l2e_t gl2e)
{ return l2e_get_pkey(gl2e); }
static inline u32 guest_l3e_get_pkey(guest_l3e_t gl3e)
{ return l3e_get_pkey(gl3e); }

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

/* Mask of the GFNs covered by an L2 or L3 superpage */
#define GUEST_L2_GFN_MASK (GUEST_L1_PAGETABLE_ENTRIES - 1)
#define GUEST_L3_GFN_MASK \
    ((GUEST_L2_PAGETABLE_ENTRIES * GUEST_L1_PAGETABLE_ENTRIES) - 1)


/* Which pagetable features are supported on this vcpu? */

static inline bool guest_can_use_l2_superpages(const struct vcpu *v)
{
    /*
     * PV guests use Xen's paging settings.  Being 4-level, 2M
     * superpages are unconditionally supported.
     *
     * The L2 _PAGE_PSE bit must be honoured in HVM guests, whenever
     * CR4.PSE is set or the guest is in PAE or long mode.
     * It's also used in the dummy PT for vcpus with CR0.PG cleared.
     */
    return (is_pv_vcpu(v) ||
            GUEST_PAGING_LEVELS != 2 ||
            !hvm_paging_enabled(v) ||
            (v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PSE));
}

static inline bool guest_can_use_l3_superpages(const struct domain *d)
{
    /*
     * There are no control register settings for the hardware pagewalk on the
     * subject of 1G superpages.
     *
     * Shadow pagetables don't support 1GB superpages at all, and will always
     * treat L3 _PAGE_PSE as reserved.
     *
     * With HAP however, if the guest constructs a 1GB superpage on capable
     * hardware, it will function irrespective of whether the feature is
     * advertised.  Xen's model of performing a pagewalk should match.
     */
    return GUEST_PAGING_LEVELS >= 4 && paging_mode_hap(d) && cpu_has_page1gb;
}

static inline bool guest_can_use_pse36(const struct domain *d)
{
    /*
     * Only called in the context of 2-level guests, after
     * guest_can_use_l2_superpages() has indicated true.
     *
     * Shadow pagetables don't support PSE36 superpages at all, and will
     * always treat them as reserved.
     *
     * With HAP however, once L2 superpages are active, here are no control
     * register settings for the hardware pagewalk on the subject of PSE36.
     * If the guest constructs a PSE36 superpage on capable hardware, it will
     * function irrespective of whether the feature is advertised.  Xen's
     * model of performing a pagewalk should match.
     */
    return paging_mode_hap(d) && cpu_has_pse36;
}

static inline bool guest_nx_enabled(const struct vcpu *v)
{
    if ( GUEST_PAGING_LEVELS == 2 ) /* NX has no effect witout CR4.PAE. */
        return false;

    /* PV guests can't control EFER.NX, and inherits Xen's choice. */
    return is_pv_vcpu(v) ? cpu_has_nx : hvm_nx_enabled(v);
}

static inline bool guest_wp_enabled(const struct vcpu *v)
{
    /* PV guests can't control CR0.WP, and it is unconditionally set by Xen. */
    return is_pv_vcpu(v) || hvm_wp_enabled(v);
}

static inline bool guest_smep_enabled(const struct vcpu *v)
{
    return !is_pv_vcpu(v) && hvm_smep_enabled(v);
}

static inline bool guest_smap_enabled(const struct vcpu *v)
{
    return !is_pv_vcpu(v) && hvm_smap_enabled(v);
}

static inline bool guest_pku_enabled(const struct vcpu *v)
{
    return !is_pv_vcpu(v) && hvm_pku_enabled(v);
}

/* Helpers for identifying whether guest entries have reserved bits set. */

/* Bits reserved because of maxphysaddr, and (lack of) EFER.NX */
static inline uint64_t guest_rsvd_bits(const struct vcpu *v)
{
    return ((PADDR_MASK &
             ~((1ul << v->domain->arch.cpuid->extd.maxphysaddr) - 1)) |
            (guest_nx_enabled(v) ? 0 : put_pte_flags(_PAGE_NX_BIT)));
}

static inline bool guest_l1e_rsvd_bits(const struct vcpu *v, guest_l1e_t l1e)
{
    return l1e.l1 & (guest_rsvd_bits(v) | GUEST_L1_PAGETABLE_RSVD);
}

static inline bool guest_l2e_rsvd_bits(const struct vcpu *v, guest_l2e_t l2e)
{
    uint64_t rsvd_bits = guest_rsvd_bits(v);

    return ((l2e.l2 & (rsvd_bits | GUEST_L2_PAGETABLE_RSVD |
                       (guest_can_use_l2_superpages(v) ? 0 : _PAGE_PSE))) ||
            ((l2e.l2 & _PAGE_PSE) &&
             (l2e.l2 & ((GUEST_PAGING_LEVELS == 2 && guest_can_use_pse36(v->domain))
                          /* PSE36 tops out at 40 bits of address width. */
                        ? (fold_pse36(rsvd_bits | (1ul << 40)))
                        : SUPERPAGE_RSVD(GUEST_L2_PAGETABLE_SHIFT)))));
}

#if GUEST_PAGING_LEVELS >= 3
static inline bool guest_l3e_rsvd_bits(const struct vcpu *v, guest_l3e_t l3e)
{
    return ((l3e.l3 & (guest_rsvd_bits(v) | GUEST_L3_PAGETABLE_RSVD |
                       (guest_can_use_l3_superpages(v->domain) ? 0 : _PAGE_PSE))) ||
            ((l3e.l3 & _PAGE_PSE) &&
             (l3e.l3 & SUPERPAGE_RSVD(GUEST_L3_PAGETABLE_SHIFT))));
}

#if GUEST_PAGING_LEVELS >= 4
static inline bool guest_l4e_rsvd_bits(const struct vcpu *v, guest_l4e_t l4e)
{
    return l4e.l4 & (guest_rsvd_bits(v) | GUEST_L4_PAGETABLE_RSVD |
                     ((v->domain->arch.cpuid->x86_vendor == X86_VENDOR_AMD)
                      ? _PAGE_GLOBAL : 0));
}
#endif /* GUEST_PAGING_LEVELS >= 4 */
#endif /* GUEST_PAGING_LEVELS >= 3 */

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
    union
    {
        guest_l1e_t l1e;        /* Guest's level 1 entry (or fabrication). */
        uint64_t   el1e;        /* L2 PSE36 superpages wider than 32 bits. */
    };
#if GUEST_PAGING_LEVELS >= 4
    mfn_t l4mfn;                /* MFN that the level 4 entry was in */
    mfn_t l3mfn;                /* MFN that the level 3 entry was in */
#endif
    mfn_t l2mfn;                /* MFN that the level 2 entry was in */
    mfn_t l1mfn;                /* MFN that the level 1 entry was in */

    uint32_t pfec;              /* Accumulated PFEC_* error code from walk. */
};

/* Given a walk_t, translate the gw->va into the guest's notion of the
 * corresponding frame number. */
static inline gfn_t guest_walk_to_gfn(const walk_t *gw)
{
    if ( !(guest_l1e_get_flags(gw->l1e) & _PAGE_PRESENT) )
        return INVALID_GFN;
    return (GUEST_PAGING_LEVELS == 2
            ? _gfn(gw->el1e >> PAGE_SHIFT)
            : guest_l1e_get_gfn(gw->l1e));
}

/* Given a walk_t, translate the gw->va into the guest's notion of the
 * corresponding physical address. */
static inline paddr_t guest_walk_to_gpa(const walk_t *gw)
{
    gfn_t gfn = guest_walk_to_gfn(gw);

    if ( gfn_eq(gfn, INVALID_GFN) )
        return INVALID_PADDR;

    return (gfn_x(gfn) << PAGE_SHIFT) | (gw->va & ~PAGE_MASK);
}

/* Given a walk_t from a successful walk, return the page-order of the
 * page or superpage that the virtual address is in. */
static inline unsigned int guest_walk_to_page_order(const walk_t *gw)
{
    /* This is only valid for successful walks - otherwise the
     * PSE bits might be invalid. */
    ASSERT(guest_l1e_get_flags(gw->l1e) & _PAGE_PRESENT);
#if GUEST_PAGING_LEVELS >= 3
    if ( guest_l3e_get_flags(gw->l3e) & _PAGE_PSE )
        return GUEST_L3_PAGETABLE_SHIFT - PAGE_SHIFT;
#endif
    if ( guest_l2e_get_flags(gw->l2e) & _PAGE_PSE )
        return GUEST_L2_PAGETABLE_SHIFT - PAGE_SHIFT;
    return GUEST_L1_PAGETABLE_SHIFT - PAGE_SHIFT;
}


/*
 * Walk the guest pagetables, after the manner of a hardware walker.
 *
 * Inputs: a vcpu, a virtual address, a walk_t to fill, a
 *         pointer to a pagefault code, the MFN of the guest's
 *         top-level pagetable, and a mapping of the
 *         guest's top-level pagetable.
 *
 * We walk the vcpu's guest pagetables, filling the walk_t with what we
 * see and adding any Accessed and Dirty bits that are needed in the
 * guest entries.  Using the pagefault code, we check the permissions as
 * we go.  For the purposes of reading pagetables we treat all non-RAM
 * memory as contining zeroes.
 *
 * Returns a boolean indicating success or failure.  walk_t.pfec contains
 * the accumulated error code on failure.
 */

/* Macro-fu so you can call guest_walk_tables() and get the right one. */
#define GPT_RENAME2(_n, _l) _n ## _ ## _l ## _levels
#define GPT_RENAME(_n, _l) GPT_RENAME2(_n, _l)
#define guest_walk_tables GPT_RENAME(guest_walk_tables, GUEST_PAGING_LEVELS)

bool
guest_walk_tables(struct vcpu *v, struct p2m_domain *p2m, unsigned long va,
                  walk_t *gw, uint32_t pfec, mfn_t top_mfn, void *top_map);

/* Pretty-print the contents of a guest-walk */
static inline void print_gw(const walk_t *gw)
{
    gprintk(XENLOG_INFO, "GUEST WALK TO %p\n", _p(gw->va));
#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    gprintk(XENLOG_INFO, "   l4e=%" PRI_gpte " l4mfn=%" PRI_mfn "\n",
            gw->l4e.l4, mfn_x(gw->l4mfn));
    gprintk(XENLOG_INFO, "   l3e=%" PRI_gpte " l3mfn=%" PRI_mfn "\n",
            gw->l3e.l3, mfn_x(gw->l3mfn));
#else  /* PAE only... */
    gprintk(XENLOG_INFO, "   l3e=%" PRI_gpte "\n", gw->l3e.l3);
#endif /* PAE or 64... */
#endif /* All levels... */
    gprintk(XENLOG_INFO, "   l2e=%" PRI_gpte " l2mfn=%" PRI_mfn "\n",
            gw->l2e.l2, mfn_x(gw->l2mfn));
#if GUEST_PAGING_LEVELS == 2
    gprintk(XENLOG_INFO, "  el1e=%08" PRIx64 " l1mfn=%" PRI_mfn "\n",
            gw->el1e, mfn_x(gw->l1mfn));
#else
    gprintk(XENLOG_INFO, "   l1e=%" PRI_gpte " l1mfn=%" PRI_mfn "\n",
            gw->l1e.l1, mfn_x(gw->l1mfn));
#endif
    gprintk(XENLOG_INFO, "   pfec=%02x[%c%c%c%c%c%c]\n", gw->pfec,
            gw->pfec & PFEC_prot_key     ? 'K' : '-',
            gw->pfec & PFEC_insn_fetch   ? 'I' : 'd',
            gw->pfec & PFEC_reserved_bit ? 'R' : '-',
            gw->pfec & PFEC_user_mode    ? 'U' : 's',
            gw->pfec & PFEC_write_access ? 'W' : 'r',
            gw->pfec & PFEC_page_present ? 'P' : '-'
        );
}

#endif /* _XEN_ASM_GUEST_PT_H */
