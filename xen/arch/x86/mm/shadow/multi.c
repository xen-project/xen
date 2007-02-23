/******************************************************************************
 * arch/x86/mm/shadow/multi.c
 *
 * Simple, mostly-synchronous shadow page tables. 
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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/shadow.h>
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include "private.h"
#include "types.h"

/* THINGS TO DO LATER:
 * 
 * TEARDOWN HEURISTICS
 * Also: have a heuristic for when to destroy a previous paging-mode's 
 * shadows.  When a guest is done with its start-of-day 32-bit tables
 * and reuses the memory we want to drop those shadows.  Start with 
 * shadows in a page in two modes as a hint, but beware of clever tricks 
 * like reusing a pagetable for both PAE and 64-bit during boot...
 *
 * PAE LINEAR MAPS
 * Rework shadow_get_l*e() to have the option of using map_domain_page()
 * instead of linear maps.  Add appropriate unmap_l*e calls in the users. 
 * Then we can test the speed difference made by linear maps.  If the 
 * map_domain_page() version is OK on PAE, we could maybe allow a lightweight 
 * l3-and-l2h-only shadow mode for PAE PV guests that would allow them 
 * to share l2h pages again. 
 *
 * GUEST_WALK_TABLES TLB FLUSH COALESCE
 * guest_walk_tables can do up to three remote TLB flushes as it walks to
 * the first l1 of a new pagetable.  Should coalesce the flushes to the end, 
 * and if we do flush, re-do the walk.  If anything has changed, then 
 * pause all the other vcpus and do the walk *again*.
 *
 * WP DISABLED
 * Consider how to implement having the WP bit of CR0 set to 0.  
 * Since we need to be able to cause write faults to pagetables, this might
 * end up looking like not having the (guest) pagetables present at all in 
 * HVM guests...
 *
 * PSE disabled / PSE36
 * We don't support any modes other than PSE enabled, PSE36 disabled.
 * Neither of those would be hard to change, but we'd need to be able to 
 * deal with shadows made in one mode and used in another.
 */

#define FETCH_TYPE_PREFETCH 1
#define FETCH_TYPE_DEMAND   2
#define FETCH_TYPE_WRITE    4
typedef enum {
    ft_prefetch     = FETCH_TYPE_PREFETCH,
    ft_demand_read  = FETCH_TYPE_DEMAND,
    ft_demand_write = FETCH_TYPE_DEMAND | FETCH_TYPE_WRITE,
} fetch_type_t;

#ifdef DEBUG_TRACE_DUMP
static char *fetch_type_names[] = {
    [ft_prefetch]     "prefetch",
    [ft_demand_read]  "demand read",
    [ft_demand_write] "demand write",
};
#endif

/**************************************************************************/
/* Hash table mapping from guest pagetables to shadows
 *
 * Normal case: maps the mfn of a guest page to the mfn of its shadow page.
 * FL1's:       maps the *gfn* of the start of a superpage to the mfn of a
 *              shadow L1 which maps its "splinters".
 */

static inline mfn_t 
get_fl1_shadow_status(struct vcpu *v, gfn_t gfn)
/* Look for FL1 shadows in the hash table */
{
    mfn_t smfn = shadow_hash_lookup(v, gfn_x(gfn), SH_type_fl1_shadow);

    if ( unlikely(shadow_mode_log_dirty(v->domain) && mfn_valid(smfn)) )
    {
        struct shadow_page_info *sp = mfn_to_shadow_page(smfn);
        if ( !(sp->logdirty) )
            shadow_convert_to_log_dirty(v, smfn);
    }

    return smfn;
}

static inline mfn_t 
get_shadow_status(struct vcpu *v, mfn_t gmfn, u32 shadow_type)
/* Look for shadows in the hash table */
{
    mfn_t smfn = shadow_hash_lookup(v, mfn_x(gmfn), shadow_type);
    perfc_incrc(shadow_get_shadow_status);

    if ( unlikely(shadow_mode_log_dirty(v->domain) && mfn_valid(smfn)) )
    {
        struct shadow_page_info *sp = mfn_to_shadow_page(smfn);
        if ( !(sp->logdirty) )
            shadow_convert_to_log_dirty(v, smfn);
    }

    return smfn;
}

static inline void 
set_fl1_shadow_status(struct vcpu *v, gfn_t gfn, mfn_t smfn)
/* Put an FL1 shadow into the hash table */
{
    SHADOW_PRINTK("gfn=%"SH_PRI_gfn", type=%08x, smfn=%05lx\n",
                   gfn_x(gfn), SH_type_fl1_shadow, mfn_x(smfn));

    if ( unlikely(shadow_mode_log_dirty(v->domain)) )
        // mark this shadow as a log dirty shadow...
        mfn_to_shadow_page(smfn)->logdirty = 1;
    else
        mfn_to_shadow_page(smfn)->logdirty = 0;

    shadow_hash_insert(v, gfn_x(gfn), SH_type_fl1_shadow, smfn);
}

static inline void 
set_shadow_status(struct vcpu *v, mfn_t gmfn, u32 shadow_type, mfn_t smfn)
/* Put a shadow into the hash table */
{
    struct domain *d = v->domain;
    int res;

    SHADOW_PRINTK("d=%d, v=%d, gmfn=%05lx, type=%08x, smfn=%05lx\n",
                   d->domain_id, v->vcpu_id, mfn_x(gmfn),
                   shadow_type, mfn_x(smfn));

    if ( unlikely(shadow_mode_log_dirty(d)) )
        // mark this shadow as a log dirty shadow...
        mfn_to_shadow_page(smfn)->logdirty = 1;
    else
        mfn_to_shadow_page(smfn)->logdirty = 0;

#ifdef CONFIG_COMPAT
    if ( !IS_COMPAT(d) || shadow_type != SH_type_l4_64_shadow )
#endif
    {
        res = get_page(mfn_to_page(gmfn), d);
        ASSERT(res == 1);
    }

    shadow_hash_insert(v, mfn_x(gmfn), shadow_type, smfn);
}

static inline void 
delete_fl1_shadow_status(struct vcpu *v, gfn_t gfn, mfn_t smfn)
/* Remove a shadow from the hash table */
{
    SHADOW_PRINTK("gfn=%"SH_PRI_gfn", type=%08x, smfn=%05lx\n",
                   gfn_x(gfn), SH_type_fl1_shadow, mfn_x(smfn));
    shadow_hash_delete(v, gfn_x(gfn), SH_type_fl1_shadow, smfn);
}

static inline void 
delete_shadow_status(struct vcpu *v, mfn_t gmfn, u32 shadow_type, mfn_t smfn)
/* Remove a shadow from the hash table */
{
    SHADOW_PRINTK("d=%d, v=%d, gmfn=%05lx, type=%08x, smfn=%05lx\n",
                   v->domain->domain_id, v->vcpu_id,
                   mfn_x(gmfn), shadow_type, mfn_x(smfn));
    shadow_hash_delete(v, mfn_x(gmfn), shadow_type, smfn);
#ifdef CONFIG_COMPAT
    if ( !IS_COMPAT(v->domain) || shadow_type != SH_type_l4_64_shadow )
#endif
        put_page(mfn_to_page(gmfn));
}

/**************************************************************************/
/* CPU feature support querying */

static inline int
guest_supports_superpages(struct vcpu *v)
{
    /* The _PAGE_PSE bit must be honoured in HVM guests, whenever
     * CR4.PSE is set or the guest is in PAE or long mode */
    return (is_hvm_vcpu(v) && (GUEST_PAGING_LEVELS != 2 
                             || (hvm_get_guest_ctrl_reg(v, 4) & X86_CR4_PSE)));
}

static inline int
guest_supports_nx(struct vcpu *v)
{
    if ( !is_hvm_vcpu(v) )
        return cpu_has_nx;

    // XXX - fix this!
    return 1;
}


/**************************************************************************/
/* Functions for walking the guest page tables */


/* Walk the guest pagetables, filling the walk_t with what we see. 
 * Takes an uninitialised walk_t.  The caller must call unmap_walk() 
 * on the walk_t before discarding it or calling guest_walk_tables again. 
 * If "guest_op" is non-zero, we are serving a genuine guest memory access, 
 * and must (a) be under the shadow lock, and (b) remove write access
 * from any gueat PT pages we see, as we will be using their contents to 
 * perform shadow updates.
 * Returns 0 for success or non-zero if the guest pagetables are malformed.
 * N.B. Finding a not-present entry does not cause a non-zero return code. */
static inline int 
guest_walk_tables(struct vcpu *v, unsigned long va, walk_t *gw, int guest_op)
{
    ASSERT(!guest_op || shadow_locked_by_me(v->domain));

    perfc_incrc(shadow_guest_walk);
    memset(gw, 0, sizeof(*gw));
    gw->va = va;

#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    /* Get l4e from the top level table */
    gw->l4mfn = pagetable_get_mfn(v->arch.guest_table);
    gw->l4e = (guest_l4e_t *)v->arch.paging.shadow.guest_vtable 
        + guest_l4_table_offset(va);
    /* Walk down to the l3e */
    if ( !(guest_l4e_get_flags(*gw->l4e) & _PAGE_PRESENT) ) return 0;
    gw->l3mfn = vcpu_gfn_to_mfn(v, guest_l4e_get_gfn(*gw->l4e));
    if ( !mfn_valid(gw->l3mfn) ) return 1;
    /* This mfn is a pagetable: make sure the guest can't write to it. */
    if ( guest_op && sh_remove_write_access(v, gw->l3mfn, 3, va) != 0 )
        flush_tlb_mask(v->domain->domain_dirty_cpumask); 
    gw->l3e = ((guest_l3e_t *)sh_map_domain_page(gw->l3mfn))
        + guest_l3_table_offset(va);
#else /* PAE only... */
    /* Get l3e from the cache of the guest's top level table */
    gw->l3e = (guest_l3e_t *)&v->arch.paging.shadow.gl3e[guest_l3_table_offset(va)];
#endif /* PAE or 64... */
    /* Walk down to the l2e */
    if ( !(guest_l3e_get_flags(*gw->l3e) & _PAGE_PRESENT) ) return 0;
    gw->l2mfn = vcpu_gfn_to_mfn(v, guest_l3e_get_gfn(*gw->l3e));
    if ( !mfn_valid(gw->l2mfn) ) return 1;
    /* This mfn is a pagetable: make sure the guest can't write to it. */
    if ( guest_op && sh_remove_write_access(v, gw->l2mfn, 2, va) != 0 )
        flush_tlb_mask(v->domain->domain_dirty_cpumask); 
    gw->l2e = ((guest_l2e_t *)sh_map_domain_page(gw->l2mfn))
        + guest_l2_table_offset(va);
#else /* 32-bit only... */
    /* Get l2e from the top level table */
    gw->l2mfn = pagetable_get_mfn(v->arch.guest_table);
    gw->l2e = (guest_l2e_t *)v->arch.paging.shadow.guest_vtable 
        + guest_l2_table_offset(va);
#endif /* All levels... */
    
    if ( !(guest_l2e_get_flags(*gw->l2e) & _PAGE_PRESENT) ) return 0;
    if ( guest_supports_superpages(v) &&
         (guest_l2e_get_flags(*gw->l2e) & _PAGE_PSE) ) 
    {
        /* Special case: this guest VA is in a PSE superpage, so there's
         * no guest l1e.  We make one up so that the propagation code
         * can generate a shadow l1 table.  Start with the gfn of the 
         * first 4k-page of the superpage. */
        gfn_t start = guest_l2e_get_gfn(*gw->l2e);
        /* Grant full access in the l1e, since all the guest entry's 
         * access controls are enforced in the shadow l2e.  This lets 
         * us reflect l2 changes later without touching the l1s. */
        int flags = (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                     _PAGE_ACCESSED|_PAGE_DIRTY);
        /* PSE level 2 entries use bit 12 for PAT; propagate it to bit 7
         * of the level 1 */
        if ( (guest_l2e_get_flags(*gw->l2e) & _PAGE_PSE_PAT) ) 
            flags |= _PAGE_PAT; 
        /* Increment the pfn by the right number of 4k pages.  
         * The ~0x1 is to mask out the PAT bit mentioned above. */
        start = _gfn((gfn_x(start) & ~0x1) + guest_l1_table_offset(va));
        gw->eff_l1e = guest_l1e_from_gfn(start, flags);
        gw->l1e = NULL;
        gw->l1mfn = _mfn(INVALID_MFN);
    } 
    else 
    {
        /* Not a superpage: carry on and find the l1e. */
        gw->l1mfn = vcpu_gfn_to_mfn(v, guest_l2e_get_gfn(*gw->l2e));
        if ( !mfn_valid(gw->l1mfn) ) return 1;
        /* This mfn is a pagetable: make sure the guest can't write to it. */
        if ( guest_op 
             && sh_remove_write_access(v, gw->l1mfn, 1, va) != 0 )
            flush_tlb_mask(v->domain->domain_dirty_cpumask); 
        gw->l1e = ((guest_l1e_t *)sh_map_domain_page(gw->l1mfn))
            + guest_l1_table_offset(va);
        gw->eff_l1e = *gw->l1e;
    }

    return 0;
}

/* Given a walk_t, translate the gw->va into the guest's notion of the
 * corresponding frame number. */
static inline gfn_t
guest_walk_to_gfn(walk_t *gw)
{
    if ( !(guest_l1e_get_flags(gw->eff_l1e) & _PAGE_PRESENT) )
        return _gfn(INVALID_GFN);
    return guest_l1e_get_gfn(gw->eff_l1e);
}

/* Given a walk_t, translate the gw->va into the guest's notion of the
 * corresponding physical address. */
static inline paddr_t
guest_walk_to_gpa(walk_t *gw)
{
    if ( !(guest_l1e_get_flags(gw->eff_l1e) & _PAGE_PRESENT) )
        return 0;
    return guest_l1e_get_paddr(gw->eff_l1e) + (gw->va & ~PAGE_MASK);
}


/* Unmap (and reinitialise) a guest walk.  
 * Call this to dispose of any walk filled in by guest_walk_tables() */
static void unmap_walk(struct vcpu *v, walk_t *gw)
{
#if GUEST_PAGING_LEVELS >= 3
#if GUEST_PAGING_LEVELS >= 4
    if ( gw->l3e != NULL ) sh_unmap_domain_page(gw->l3e);
#endif
    if ( gw->l2e != NULL ) sh_unmap_domain_page(gw->l2e);
#endif
    if ( gw->l1e != NULL ) sh_unmap_domain_page(gw->l1e);
#ifdef DEBUG
    memset(gw, 0, sizeof(*gw));
#endif
}


/* Pretty-print the contents of a guest-walk */
static inline void print_gw(walk_t *gw)
{
    SHADOW_PRINTK("GUEST WALK TO %#lx:\n", gw->va);
#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    SHADOW_PRINTK("   l4mfn=%" PRI_mfn "\n", mfn_x(gw->l4mfn));
    SHADOW_PRINTK("   l4e=%p\n", gw->l4e);
    if ( gw->l4e )
        SHADOW_PRINTK("   *l4e=%" SH_PRI_gpte "\n", gw->l4e->l4);
    SHADOW_PRINTK("   l3mfn=%" PRI_mfn "\n", mfn_x(gw->l3mfn));
#endif /* PAE or 64... */
    SHADOW_PRINTK("   l3e=%p\n", gw->l3e);
    if ( gw->l3e )
        SHADOW_PRINTK("   *l3e=%" SH_PRI_gpte "\n", gw->l3e->l3);
#endif /* All levels... */
    SHADOW_PRINTK("   l2mfn=%" PRI_mfn "\n", mfn_x(gw->l2mfn));
    SHADOW_PRINTK("   l2e=%p\n", gw->l2e);
    if ( gw->l2e )
        SHADOW_PRINTK("   *l2e=%" SH_PRI_gpte "\n", gw->l2e->l2);
    SHADOW_PRINTK("   l1mfn=%" PRI_mfn "\n", mfn_x(gw->l1mfn));
    SHADOW_PRINTK("   l1e=%p\n", gw->l1e);
    if ( gw->l1e )
        SHADOW_PRINTK("   *l1e=%" SH_PRI_gpte "\n", gw->l1e->l1);
    SHADOW_PRINTK("   eff_l1e=%" SH_PRI_gpte "\n", gw->eff_l1e.l1);
}


#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES
/* Lightweight audit: pass all the shadows associated with this guest walk
 * through the audit mechanisms */
static void sh_audit_gw(struct vcpu *v, walk_t *gw) 
{
    mfn_t smfn;

    if ( !(SHADOW_AUDIT_ENABLE) )
        return;

#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    if ( mfn_valid(gw->l4mfn)
         && mfn_valid((smfn = get_shadow_status(v, gw->l4mfn, 
                                                SH_type_l4_shadow))) )
        (void) sh_audit_l4_table(v, smfn, _mfn(INVALID_MFN));
    if ( mfn_valid(gw->l3mfn)
         && mfn_valid((smfn = get_shadow_status(v, gw->l3mfn, 
                                                SH_type_l3_shadow))) )
        (void) sh_audit_l3_table(v, smfn, _mfn(INVALID_MFN));
#endif /* PAE or 64... */
    if ( mfn_valid(gw->l2mfn) )
    {
        if ( mfn_valid((smfn = get_shadow_status(v, gw->l2mfn, 
                                                 SH_type_l2_shadow))) )
            (void) sh_audit_l2_table(v, smfn, _mfn(INVALID_MFN));
#if GUEST_PAGING_LEVELS == 3
        if ( mfn_valid((smfn = get_shadow_status(v, gw->l2mfn, 
                                                 SH_type_l2h_shadow))) )
            (void) sh_audit_l2_table(v, smfn, _mfn(INVALID_MFN));
#endif
    }
    if ( mfn_valid(gw->l1mfn)
         && mfn_valid((smfn = get_shadow_status(v, gw->l1mfn, 
                                                SH_type_l1_shadow))) )
        (void) sh_audit_l1_table(v, smfn, _mfn(INVALID_MFN));
    else if ( gw->l2e
              && (guest_l2e_get_flags(*gw->l2e) & _PAGE_PSE)
              && mfn_valid( 
              (smfn = get_fl1_shadow_status(v, guest_l2e_get_gfn(*gw->l2e)))) )
        (void) sh_audit_fl1_table(v, smfn, _mfn(INVALID_MFN));
}

#else
#define sh_audit_gw(_v, _gw) do {} while(0)
#endif /* audit code */



/**************************************************************************/
/* Function to write to the guest tables, for propagating accessed and 
 * dirty bits from the shadow to the guest.
 * Takes a guest mfn, a pointer to the guest entry, the level of pagetable,
 * and an operation type.  The guest entry is always passed as an l1e: 
 * since we only ever write flags, that's OK.
 * Returns the new flag bits of the guest entry. */

static u32 guest_set_ad_bits(struct vcpu *v,
                             mfn_t gmfn, 
                             guest_l1e_t *ep,
                             unsigned int level, 
                             fetch_type_t ft)
{
    u32 flags;
    int res = 0;

    ASSERT(ep && !(((unsigned long)ep) & ((sizeof *ep) - 1)));
    ASSERT(level <= GUEST_PAGING_LEVELS);
    ASSERT(shadow_locked_by_me(v->domain));

    flags = guest_l1e_get_flags(*ep);

    /* Only set A and D bits for guest-initiated accesses */
    if ( !(ft & FETCH_TYPE_DEMAND) )
        return flags;

    ASSERT(mfn_valid(gmfn)
           && (sh_mfn_is_a_page_table(gmfn)
               || ((mfn_to_page(gmfn)->u.inuse.type_info & PGT_count_mask) 
                   == 0)));

    /* PAE l3s do not have A and D bits */
    ASSERT(GUEST_PAGING_LEVELS > 3 || level != 3);

    /* Need the D bit as well for writes, in L1es and PSE L2es. */
    if ( ft == ft_demand_write  
         && (level == 1 ||
             (level == 2 && (flags & _PAGE_PSE) && guest_supports_superpages(v))) )
    {
        if ( (flags & (_PAGE_DIRTY | _PAGE_ACCESSED)) 
             == (_PAGE_DIRTY | _PAGE_ACCESSED) )
            return flags;  /* Guest already has A and D bits set */
        flags |= _PAGE_DIRTY | _PAGE_ACCESSED;
        perfc_incrc(shadow_ad_update);
    }
    else 
    {
        if ( flags & _PAGE_ACCESSED )
            return flags;  /* Guest already has A bit set */
        flags |= _PAGE_ACCESSED;
        perfc_incrc(shadow_a_update);
    }

    /* Set the bit(s) */
    sh_mark_dirty(v->domain, gmfn);
    SHADOW_DEBUG(A_AND_D, "gfn = %" SH_PRI_gfn ", "
                 "old flags = %#x, new flags = %#x\n", 
                 gfn_x(guest_l1e_get_gfn(*ep)), guest_l1e_get_flags(*ep), 
                 flags);
    *ep = guest_l1e_from_gfn(guest_l1e_get_gfn(*ep), flags);
    
    /* Propagate this change to any other shadows of the page 
     * (only necessary if there is more than one shadow) */
    if ( mfn_to_page(gmfn)->count_info & PGC_page_table )
    {
        u32 shflags = mfn_to_page(gmfn)->shadow_flags & SHF_page_type_mask;
        /* More than one type bit set in shadow-flags? */
        if ( shflags & ~(1UL << find_first_set_bit(shflags)) )
            res = sh_validate_guest_entry(v, gmfn, ep, sizeof (*ep));
    }

    /* We should never need to flush the TLB or recopy PAE entries */
    ASSERT((res == 0) || (res == SHADOW_SET_CHANGED));

    return flags;
}

#if (CONFIG_PAGING_LEVELS == GUEST_PAGING_LEVELS) && (CONFIG_PAGING_LEVELS == SHADOW_PAGING_LEVELS)
void *
sh_guest_map_l1e(struct vcpu *v, unsigned long addr,
                  unsigned long *gl1mfn)
{
    void *pl1e = NULL;
    walk_t gw;

    ASSERT(shadow_mode_translate(v->domain));
        
    // XXX -- this is expensive, but it's easy to cobble together...
    // FIXME!

    shadow_lock(v->domain);
    guest_walk_tables(v, addr, &gw, 1);

    if ( gw.l2e &&
         (guest_l2e_get_flags(*gw.l2e) & _PAGE_PRESENT) &&
         !(guest_supports_superpages(v) && (guest_l2e_get_flags(*gw.l2e) & _PAGE_PSE)) )
    {
        if ( gl1mfn )
            *gl1mfn = mfn_x(gw.l1mfn);
        pl1e = map_domain_page(mfn_x(gw.l1mfn)) +
            (guest_l1_table_offset(addr) * sizeof(guest_l1e_t));
    }

    unmap_walk(v, &gw);
    shadow_unlock(v->domain);

    return pl1e;
}

void
sh_guest_get_eff_l1e(struct vcpu *v, unsigned long addr, void *eff_l1e)
{
    walk_t gw;

    ASSERT(shadow_mode_translate(v->domain));
        
    // XXX -- this is expensive, but it's easy to cobble together...
    // FIXME!

    shadow_lock(v->domain);
    guest_walk_tables(v, addr, &gw, 1);
    *(guest_l1e_t *)eff_l1e = gw.eff_l1e;
    unmap_walk(v, &gw);
    shadow_unlock(v->domain);
}
#endif /* CONFIG==SHADOW==GUEST */

/**************************************************************************/
/* Functions to compute the correct index into a shadow page, given an
 * index into the guest page (as returned by guest_get_index()).
 * This is trivial when the shadow and guest use the same sized PTEs, but
 * gets more interesting when those sizes are mismatched (e.g. 32-bit guest,
 * PAE- or 64-bit shadows).
 *
 * These functions also increment the shadow mfn, when necessary.  When PTE
 * sizes are mismatched, it takes 2 shadow L1 pages for a single guest L1
 * page.  In this case, we allocate 2 contiguous pages for the shadow L1, and
 * use simple pointer arithmetic on a pointer to the guest L1e to figure out
 * which shadow page we really want.  Similarly, when PTE sizes are
 * mismatched, we shadow a guest L2 page with 4 shadow L2 pages.  (The easiest
 * way to see this is: a 32-bit guest L2 page maps 4GB of virtual address
 * space, while a PAE- or 64-bit shadow L2 page maps 1GB of virtual address
 * space.)
 *
 * For PAE guests, for every 32-bytes of guest L3 page table, we use 64-bytes
 * of shadow (to store both the shadow, and the info that would normally be
 * stored in page_info fields).  This arrangement allows the shadow and the
 * "page_info" fields to always be stored in the same page (in fact, in
 * the same cache line), avoiding an extra call to map_domain_page().
 */

static inline u32
guest_index(void *ptr)
{
    return (u32)((unsigned long)ptr & ~PAGE_MASK) / sizeof(guest_l1e_t);
}

static u32
shadow_l1_index(mfn_t *smfn, u32 guest_index)
{
#if (GUEST_PAGING_LEVELS == 2) && (SHADOW_PAGING_LEVELS != 2)
    *smfn = _mfn(mfn_x(*smfn) +
                 (guest_index / SHADOW_L1_PAGETABLE_ENTRIES));
    return (guest_index % SHADOW_L1_PAGETABLE_ENTRIES);
#else
    return guest_index;
#endif
}

static u32
shadow_l2_index(mfn_t *smfn, u32 guest_index)
{
#if (GUEST_PAGING_LEVELS == 2) && (SHADOW_PAGING_LEVELS != 2)
    // Because we use 2 shadow l2 entries for each guest entry, the number of
    // guest entries per shadow page is SHADOW_L2_PAGETABLE_ENTRIES/2
    //
    *smfn = _mfn(mfn_x(*smfn) +
                 (guest_index / (SHADOW_L2_PAGETABLE_ENTRIES / 2)));

    // We multiple by two to get the index of the first of the two entries
    // used to shadow the specified guest entry.
    return (guest_index % (SHADOW_L2_PAGETABLE_ENTRIES / 2)) * 2;
#else
    return guest_index;
#endif
}

#if GUEST_PAGING_LEVELS >= 4

static u32
shadow_l3_index(mfn_t *smfn, u32 guest_index)
{
    return guest_index;
}

static u32
shadow_l4_index(mfn_t *smfn, u32 guest_index)
{
    return guest_index;
}

#endif // GUEST_PAGING_LEVELS >= 4


/**************************************************************************/
/* Function which computes shadow entries from their corresponding guest
 * entries.  This is the "heart" of the shadow code. It operates using
 * level-1 shadow types, but handles all levels of entry.
 * Don't call it directly, but use the four wrappers below.
 */

static always_inline void
_sh_propagate(struct vcpu *v, 
              void *guest_entry_ptr, 
              mfn_t guest_table_mfn, 
              mfn_t target_mfn, 
              void *shadow_entry_ptr,
              int level,
              fetch_type_t ft, 
              int mmio)
{
    guest_l1e_t *gp = guest_entry_ptr;
    shadow_l1e_t *sp = shadow_entry_ptr;
    struct domain *d = v->domain;
    u32 pass_thru_flags;
    u32 gflags, sflags;

    /* We don't shadow PAE l3s */
    ASSERT(GUEST_PAGING_LEVELS > 3 || level != 3);

    if ( mfn_valid(guest_table_mfn) )
        /* Handle A and D bit propagation into the guest */
        gflags = guest_set_ad_bits(v, guest_table_mfn, gp, level, ft);
    else 
    {
        /* Must be an fl1e or a prefetch */
        ASSERT(level==1 || !(ft & FETCH_TYPE_DEMAND));
        gflags = guest_l1e_get_flags(*gp);
    }

    if ( unlikely(!(gflags & _PAGE_PRESENT)) )
    {
        /* If a guest l1 entry is not present, shadow with the magic 
         * guest-not-present entry. */
        if ( level == 1 )
            *sp = sh_l1e_gnp();
        else 
            *sp = shadow_l1e_empty();
        goto done;
    }

    if ( level == 1 && mmio )
    {
        /* Guest l1e maps MMIO space */
        *sp = sh_l1e_mmio(guest_l1e_get_gfn(*gp), gflags);
        goto done;
    }

    // Must have a valid target_mfn, unless this is a prefetch.  In the
    // case of a prefetch, an invalid mfn means that we can not usefully
    // shadow anything, and so we return early.
    //
    if ( !mfn_valid(target_mfn) )
    {
        ASSERT((ft == ft_prefetch));
        *sp = shadow_l1e_empty();
        goto done;
    }

    // Propagate bits from the guest to the shadow.
    // Some of these may be overwritten, below.
    // Since we know the guest's PRESENT bit is set, we also set the shadow's
    // SHADOW_PRESENT bit.
    //
    pass_thru_flags = (_PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER |
                       _PAGE_RW | _PAGE_PRESENT);
    if ( guest_supports_nx(v) )
        pass_thru_flags |= _PAGE_NX_BIT;
    sflags = gflags & pass_thru_flags;

    // Set the A&D bits for higher level shadows.
    // Higher level entries do not, strictly speaking, have dirty bits, but
    // since we use shadow linear tables, each of these entries may, at some
    // point in time, also serve as a shadow L1 entry.
    // By setting both the A&D bits in each of these, we eliminate the burden
    // on the hardware to update these bits on initial accesses.
    //
    if ( (level > 1) && !((SHADOW_PAGING_LEVELS == 3) && (level == 3)) )
        sflags |= _PAGE_ACCESSED | _PAGE_DIRTY;

    // If the A or D bit has not yet been set in the guest, then we must
    // prevent the corresponding kind of access.
    //
    if ( unlikely(!(gflags & _PAGE_ACCESSED)) )
        sflags &= ~_PAGE_PRESENT;

    /* D bits exist in L1es and PSE L2es */
    if ( unlikely(((level == 1) ||
                   ((level == 2) &&
                    (gflags & _PAGE_PSE) &&
                    guest_supports_superpages(v)))
                  && !(gflags & _PAGE_DIRTY)) )
        sflags &= ~_PAGE_RW;

    // shadow_mode_log_dirty support
    //
    // Only allow the guest write access to a page a) on a demand fault,
    // or b) if the page is already marked as dirty.
    //
    if ( unlikely((level == 1) && shadow_mode_log_dirty(d)) )
    {
        if ( ft & FETCH_TYPE_WRITE ) 
            sh_mark_dirty(d, target_mfn);
        else if ( !sh_mfn_is_dirty(d, target_mfn) )
            sflags &= ~_PAGE_RW;
    }
    
    // protect guest page tables
    //
    if ( unlikely((level == 1) && sh_mfn_is_a_page_table(target_mfn)) )
    {
        if ( shadow_mode_trap_reads(d) )
        {
            // if we are trapping both reads & writes, then mark this page
            // as not present...
            //
            sflags &= ~_PAGE_PRESENT;
        }
        else
        {
            // otherwise, just prevent any writes...
            //
            sflags &= ~_PAGE_RW;
        }
    }

    // PV guests in 64-bit mode use two different page tables for user vs
    // supervisor permissions, making the guest's _PAGE_USER bit irrelevant.
    // It is always shadowed as present...
    if ( (GUEST_PAGING_LEVELS == 4) && !IS_COMPAT(d) && !is_hvm_domain(d) )
    {
        sflags |= _PAGE_USER;
    }

    *sp = shadow_l1e_from_mfn(target_mfn, sflags);
 done:
    SHADOW_DEBUG(PROPAGATE,
                 "%s level %u guest %" SH_PRI_gpte " shadow %" SH_PRI_pte "\n",
                 fetch_type_names[ft], level, gp->l1, sp->l1);
}


/* These four wrappers give us a little bit of type-safety back around the 
 * use of void-* pointers in _sh_propagate(), and allow the compiler to 
 * optimize out some level checks. */

#if GUEST_PAGING_LEVELS >= 4
static void
l4e_propagate_from_guest(struct vcpu *v, 
                         guest_l4e_t *gl4e,
                         mfn_t gl4mfn,
                         mfn_t sl3mfn,
                         shadow_l4e_t *sl4e,
                         fetch_type_t ft)
{
    _sh_propagate(v, gl4e, gl4mfn, sl3mfn, sl4e, 4, ft, 0);
}

static void
l3e_propagate_from_guest(struct vcpu *v,
                         guest_l3e_t *gl3e,
                         mfn_t gl3mfn, 
                         mfn_t sl2mfn, 
                         shadow_l3e_t *sl3e,
                         fetch_type_t ft)
{
    _sh_propagate(v, gl3e, gl3mfn, sl2mfn, sl3e, 3, ft, 0);
}
#endif // GUEST_PAGING_LEVELS >= 4

static void
l2e_propagate_from_guest(struct vcpu *v, 
                         guest_l2e_t *gl2e,
                         mfn_t gl2mfn,
                         mfn_t sl1mfn,
                         shadow_l2e_t *sl2e,
                         fetch_type_t ft)
{
    _sh_propagate(v, gl2e, gl2mfn, sl1mfn, sl2e, 2, ft, 0);
}

static void
l1e_propagate_from_guest(struct vcpu *v, 
                         guest_l1e_t *gl1e,
                         mfn_t gl1mfn,
                         mfn_t gmfn, 
                         shadow_l1e_t *sl1e,
                         fetch_type_t ft, 
                         int mmio)
{
    _sh_propagate(v, gl1e, gl1mfn, gmfn, sl1e, 1, ft, mmio);
}


/**************************************************************************/
/* These functions update shadow entries (and do bookkeeping on the shadow
 * tables they are in).  It is intended that they are the only
 * functions which ever write (non-zero) data onto a shadow page.
 */

static inline void safe_write_entry(void *dst, void *src) 
/* Copy one PTE safely when processors might be running on the
 * destination pagetable.   This does *not* give safety against
 * concurrent writes (that's what the shadow lock is for), just 
 * stops the hardware picking up partially written entries. */
{
    volatile unsigned long *d = dst;
    unsigned long *s = src;
    ASSERT(!((unsigned long) d & (sizeof (shadow_l1e_t) - 1)));
#if CONFIG_PAGING_LEVELS == 3
    /* In PAE mode, pagetable entries are larger
     * than machine words, so won't get written atomically.  We need to make
     * sure any other cpu running on these shadows doesn't see a
     * half-written entry.  Do this by marking the entry not-present first,
     * then writing the high word before the low word. */
    BUILD_BUG_ON(sizeof (shadow_l1e_t) != 2 * sizeof (unsigned long));
    d[0] = 0;
    d[1] = s[1];
    d[0] = s[0];
#else
    /* In 32-bit and 64-bit, sizeof(pte) == sizeof(ulong) == 1 word,
     * which will be an atomic write, since the entry is aligned. */
    BUILD_BUG_ON(sizeof (shadow_l1e_t) != sizeof (unsigned long));
    *d = *s;
#endif
}


static inline void 
shadow_write_entries(void *d, void *s, int entries, mfn_t mfn)
/* This function does the actual writes to shadow pages.
 * It must not be called directly, since it doesn't do the bookkeeping
 * that shadow_set_l*e() functions do. */
{
    shadow_l1e_t *dst = d;
    shadow_l1e_t *src = s;
    void *map = NULL;
    int i;

    /* Because we mirror access rights at all levels in the shadow, an
     * l2 (or higher) entry with the RW bit cleared will leave us with
     * no write access through the linear map.  
     * We detect that by writing to the shadow with copy_to_user() and 
     * using map_domain_page() to get a writeable mapping if we need to. */
    if ( __copy_to_user(d, d, sizeof (unsigned long)) != 0 ) 
    {
        perfc_incrc(shadow_linear_map_failed);
        map = sh_map_domain_page(mfn);
        ASSERT(map != NULL);
        dst = map + ((unsigned long)dst & (PAGE_SIZE - 1));
    }


    for ( i = 0; i < entries; i++ )
        safe_write_entry(dst++, src++);

    if ( map != NULL ) sh_unmap_domain_page(map);
}

static inline int
perms_strictly_increased(u32 old_flags, u32 new_flags) 
/* Given the flags of two entries, are the new flags a strict
 * increase in rights over the old ones? */
{
    u32 of = old_flags & (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX);
    u32 nf = new_flags & (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX);
    /* Flip the NX bit, since it's the only one that decreases rights;
     * we calculate as if it were an "X" bit. */
    of ^= _PAGE_NX_BIT;
    nf ^= _PAGE_NX_BIT;
    /* If the changed bits are all set in the new flags, then rights strictly 
     * increased between old and new. */
    return ((of | (of ^ nf)) == nf);
}

static int inline
shadow_get_page_from_l1e(shadow_l1e_t sl1e, struct domain *d)
{
    int res;
    mfn_t mfn;
    struct domain *owner;

    ASSERT(!sh_l1e_is_magic(sl1e));

    if ( !shadow_mode_refcounts(d) )
        return 1;

    res = get_page_from_l1e(sl1e, d);

    // If a privileged domain is attempting to install a map of a page it does
    // not own, we let it succeed anyway.
    //
    if ( unlikely(!res) &&
         IS_PRIV(d) &&
         !shadow_mode_translate(d) &&
         mfn_valid(mfn = shadow_l1e_get_mfn(sl1e)) &&
         (owner = page_get_owner(mfn_to_page(mfn))) &&
         (d != owner) )
    {
        res = get_page_from_l1e(sl1e, owner);
        SHADOW_PRINTK("privileged domain %d installs map of mfn %05lx "
                       "which is owned by domain %d: %s\n",
                       d->domain_id, mfn_x(mfn), owner->domain_id,
                       res ? "success" : "failed");
    }

    if ( unlikely(!res) )
    {
        perfc_incrc(shadow_get_page_fail);
        SHADOW_PRINTK("failed: l1e=" SH_PRI_pte "\n");
    }

    return res;
}

static void inline
shadow_put_page_from_l1e(shadow_l1e_t sl1e, struct domain *d)
{ 
    if ( !shadow_mode_refcounts(d) )
        return;

    put_page_from_l1e(sl1e, d);
}

#if GUEST_PAGING_LEVELS >= 4
static int shadow_set_l4e(struct vcpu *v, 
                          shadow_l4e_t *sl4e, 
                          shadow_l4e_t new_sl4e, 
                          mfn_t sl4mfn)
{
    int flags = 0, ok;
    shadow_l4e_t old_sl4e;
    paddr_t paddr;
    ASSERT(sl4e != NULL);
    old_sl4e = *sl4e;

    if ( old_sl4e.l4 == new_sl4e.l4 ) return 0; /* Nothing to do */
    
    paddr = ((((paddr_t)mfn_x(sl4mfn)) << PAGE_SHIFT) 
             | (((unsigned long)sl4e) & ~PAGE_MASK));

    if ( shadow_l4e_get_flags(new_sl4e) & _PAGE_PRESENT ) 
    {
        /* About to install a new reference */        
        mfn_t sl3mfn = shadow_l4e_get_mfn(new_sl4e);
        ok = sh_get_ref(v, sl3mfn, paddr);
        /* Are we pinning l3 shadows to handle wierd linux behaviour? */
        if ( sh_type_is_pinnable(v, SH_type_l3_64_shadow) )
            ok |= sh_pin(v, sl3mfn);
        if ( !ok )
        {
            domain_crash(v->domain);
            return SHADOW_SET_ERROR;
        }
    }

    /* Write the new entry */
    shadow_write_entries(sl4e, &new_sl4e, 1, sl4mfn);
    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l4e_get_flags(old_sl4e) & _PAGE_PRESENT ) 
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl3mfn = shadow_l4e_get_mfn(old_sl4e);
        if ( (mfn_x(osl3mfn) != mfn_x(shadow_l4e_get_mfn(new_sl4e)))
             || !perms_strictly_increased(shadow_l4e_get_flags(old_sl4e), 
                                          shadow_l4e_get_flags(new_sl4e)) )
        {
            flags |= SHADOW_SET_FLUSH;
        }
        sh_put_ref(v, osl3mfn, paddr);
    }
    return flags;
}

static int shadow_set_l3e(struct vcpu *v, 
                          shadow_l3e_t *sl3e, 
                          shadow_l3e_t new_sl3e, 
                          mfn_t sl3mfn)
{
    int flags = 0;
    shadow_l3e_t old_sl3e;
    paddr_t paddr;
    ASSERT(sl3e != NULL);
    old_sl3e = *sl3e;

    if ( old_sl3e.l3 == new_sl3e.l3 ) return 0; /* Nothing to do */

    paddr = ((((paddr_t)mfn_x(sl3mfn)) << PAGE_SHIFT) 
             | (((unsigned long)sl3e) & ~PAGE_MASK));
    
    if ( shadow_l3e_get_flags(new_sl3e) & _PAGE_PRESENT )
        /* About to install a new reference */        
        if ( !sh_get_ref(v, shadow_l3e_get_mfn(new_sl3e), paddr) )
        {
            domain_crash(v->domain);
            return SHADOW_SET_ERROR;
        } 

    /* Write the new entry */
    shadow_write_entries(sl3e, &new_sl3e, 1, sl3mfn);
    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l3e_get_flags(old_sl3e) & _PAGE_PRESENT ) 
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl2mfn = shadow_l3e_get_mfn(old_sl3e);
        if ( (mfn_x(osl2mfn) != mfn_x(shadow_l3e_get_mfn(new_sl3e))) ||
             !perms_strictly_increased(shadow_l3e_get_flags(old_sl3e), 
                                       shadow_l3e_get_flags(new_sl3e)) ) 
        {
            flags |= SHADOW_SET_FLUSH;
        }
        sh_put_ref(v, osl2mfn, paddr);
    }
    return flags;
}
#endif /* GUEST_PAGING_LEVELS >= 4 */ 

static int shadow_set_l2e(struct vcpu *v, 
                          shadow_l2e_t *sl2e, 
                          shadow_l2e_t new_sl2e, 
                          mfn_t sl2mfn)
{
    int flags = 0;
    shadow_l2e_t old_sl2e;
    paddr_t paddr;

#if GUEST_PAGING_LEVELS == 2 && SHADOW_PAGING_LEVELS > 2
    /* In 2-on-3 we work with pairs of l2es pointing at two-page
     * shadows.  Reference counting and up-pointers track from the first
     * page of the shadow to the first l2e, so make sure that we're 
     * working with those:     
     * Align the pointer down so it's pointing at the first of the pair */
    sl2e = (shadow_l2e_t *)((unsigned long)sl2e & ~(sizeof(shadow_l2e_t)));
    /* Align the mfn of the shadow entry too */
    new_sl2e.l2 &= ~(1<<PAGE_SHIFT);
#endif

    ASSERT(sl2e != NULL);
    old_sl2e = *sl2e;
    
    if ( old_sl2e.l2 == new_sl2e.l2 ) return 0; /* Nothing to do */
    
    paddr = ((((paddr_t)mfn_x(sl2mfn)) << PAGE_SHIFT)
             | (((unsigned long)sl2e) & ~PAGE_MASK));

    if ( shadow_l2e_get_flags(new_sl2e) & _PAGE_PRESENT ) 
        /* About to install a new reference */
        if ( !sh_get_ref(v, shadow_l2e_get_mfn(new_sl2e), paddr) )
        {
            domain_crash(v->domain);
            return SHADOW_SET_ERROR;
        } 

    /* Write the new entry */
#if GUEST_PAGING_LEVELS == 2 && SHADOW_PAGING_LEVELS > 2
    {
        shadow_l2e_t pair[2] = { new_sl2e, new_sl2e };
        /* The l1 shadow is two pages long and need to be pointed to by
         * two adjacent l1es.  The pair have the same flags, but point
         * at odd and even MFNs */
        ASSERT(!(pair[0].l2 & (1<<PAGE_SHIFT)));
        pair[1].l2 |= (1<<PAGE_SHIFT);
        shadow_write_entries(sl2e, &pair, 2, sl2mfn);
    }
#else /* normal case */
    shadow_write_entries(sl2e, &new_sl2e, 1, sl2mfn);
#endif
    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l2e_get_flags(old_sl2e) & _PAGE_PRESENT ) 
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl1mfn = shadow_l2e_get_mfn(old_sl2e);
        if ( (mfn_x(osl1mfn) != mfn_x(shadow_l2e_get_mfn(new_sl2e))) ||
             !perms_strictly_increased(shadow_l2e_get_flags(old_sl2e), 
                                       shadow_l2e_get_flags(new_sl2e)) ) 
        {
            flags |= SHADOW_SET_FLUSH;
        }
        sh_put_ref(v, osl1mfn, paddr);
    }
    return flags;
}

static int shadow_set_l1e(struct vcpu *v, 
                          shadow_l1e_t *sl1e, 
                          shadow_l1e_t new_sl1e,
                          mfn_t sl1mfn)
{
    int flags = 0;
    struct domain *d = v->domain;
    shadow_l1e_t old_sl1e;
    ASSERT(sl1e != NULL);
    
    old_sl1e = *sl1e;

    if ( old_sl1e.l1 == new_sl1e.l1 ) return 0; /* Nothing to do */
    
    if ( (shadow_l1e_get_flags(new_sl1e) & _PAGE_PRESENT)
         && !sh_l1e_is_magic(new_sl1e) ) 
    {
        /* About to install a new reference */        
        if ( shadow_mode_refcounts(d) ) {
            if ( shadow_get_page_from_l1e(new_sl1e, d) == 0 ) 
            {
                /* Doesn't look like a pagetable. */
                flags |= SHADOW_SET_ERROR;
                new_sl1e = shadow_l1e_empty();
            }
        }
    } 

    /* Write the new entry */
    shadow_write_entries(sl1e, &new_sl1e, 1, sl1mfn);
    flags |= SHADOW_SET_CHANGED;

    if ( (shadow_l1e_get_flags(old_sl1e) & _PAGE_PRESENT) 
         && !sh_l1e_is_magic(old_sl1e) )
    {
        /* We lost a reference to an old mfn. */
        /* N.B. Unlike higher-level sets, never need an extra flush 
         * when writing an l1e.  Because it points to the same guest frame 
         * as the guest l1e did, it's the guest's responsibility to
         * trigger a flush later. */
        if ( shadow_mode_refcounts(d) ) 
        {
            shadow_put_page_from_l1e(old_sl1e, d);
        } 
    }
    return flags;
}


/**************************************************************************/
/* Macros to walk pagetables.  These take the shadow of a pagetable and 
 * walk every "interesting" entry.  That is, they don't touch Xen mappings, 
 * and for 32-bit l2s shadowed onto PAE or 64-bit, they only touch every 
 * second entry (since pairs of entries are managed together). For multi-page
 * shadows they walk all pages.
 * 
 * Arguments are an MFN, the variable to point to each entry, a variable 
 * to indicate that we are done (we will shortcut to the end of the scan 
 * when _done != 0), a variable to indicate that we should avoid Xen mappings,
 * and the code. 
 *
 * WARNING: These macros have side-effects.  They change the values of both 
 * the pointer and the MFN. */ 

static inline void increment_ptr_to_guest_entry(void *ptr)
{
    if ( ptr )
    {
        guest_l1e_t **entry = ptr;
        (*entry)++;
    }
}

/* All kinds of l1: touch all entries */
#define _SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)        \
do {                                                                    \
    int _i;                                                             \
    shadow_l1e_t *_sp = map_shadow_page((_sl1mfn));                     \
    ASSERT(mfn_to_shadow_page(_sl1mfn)->type == SH_type_l1_shadow       \
           || mfn_to_shadow_page(_sl1mfn)->type == SH_type_fl1_shadow); \
    for ( _i = 0; _i < SHADOW_L1_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        (_sl1e) = _sp + _i;                                             \
        if ( shadow_l1e_get_flags(*(_sl1e)) & _PAGE_PRESENT )           \
            {_code}                                                     \
        if ( _done ) break;                                             \
        increment_ptr_to_guest_entry(_gl1p);                            \
    }                                                                   \
    unmap_shadow_page(_sp);                                             \
} while (0)

/* 32-bit l1, on PAE or 64-bit shadows: need to walk both pages of shadow */
#if GUEST_PAGING_LEVELS == 2 && SHADOW_PAGING_LEVELS > 2
#define SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p, _done,  _code)        \
do {                                                                    \
    int __done = 0;                                                     \
    _SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p,                          \
                         ({ (__done = _done); }), _code);               \
    _sl1mfn = _mfn(mfn_x(_sl1mfn) + 1);                                 \
    if ( !__done )                                                      \
        _SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p,                      \
                             ({ (__done = _done); }), _code);           \
} while (0)
#else /* Everything else; l1 shadows are only one page */
#define SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)         \
       _SHADOW_FOREACH_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)
#endif
    

#if GUEST_PAGING_LEVELS == 2 && SHADOW_PAGING_LEVELS > 2

/* 32-bit l2 on PAE/64: four pages, touch every second entry, and avoid Xen */
#define SHADOW_FOREACH_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)     \
do {                                                                      \
    int _i, _j, __done = 0;                                               \
    int _xen = !shadow_mode_external(_dom);                               \
    ASSERT(mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2_32_shadow);    \
    for ( _j = 0; _j < 4 && !__done; _j++ )                               \
    {                                                                     \
        shadow_l2e_t *_sp = map_shadow_page(_sl2mfn);                     \
        for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i += 2 )         \
            if ( (!(_xen))                                                \
                 || ((_j * SHADOW_L2_PAGETABLE_ENTRIES) + _i)             \
                 < (HYPERVISOR_VIRT_START >> SHADOW_L2_PAGETABLE_SHIFT) ) \
            {                                                             \
                (_sl2e) = _sp + _i;                                       \
                if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )     \
                    {_code}                                               \
                if ( (__done = (_done)) ) break;                          \
                increment_ptr_to_guest_entry(_gl2p);                      \
            }                                                             \
        unmap_shadow_page(_sp);                                           \
        _sl2mfn = _mfn(mfn_x(_sl2mfn) + 1);                               \
    }                                                                     \
} while (0)

#elif GUEST_PAGING_LEVELS == 2

/* 32-bit on 32-bit: avoid Xen entries */
#define SHADOW_FOREACH_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)      \
do {                                                                       \
    int _i;                                                                \
    int _xen = !shadow_mode_external(_dom);                                \
    shadow_l2e_t *_sp = map_shadow_page((_sl2mfn));                        \
    ASSERT(mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2_32_shadow);     \
    for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i++ )                 \
        if ( (!(_xen))                                                     \
             ||                                                            \
             (_i < (HYPERVISOR_VIRT_START >> SHADOW_L2_PAGETABLE_SHIFT)) ) \
        {                                                                  \
            (_sl2e) = _sp + _i;                                            \
            if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )          \
                {_code}                                                    \
            if ( _done ) break;                                            \
            increment_ptr_to_guest_entry(_gl2p);                           \
        }                                                                  \
    unmap_shadow_page(_sp);                                                \
} while (0)

#elif GUEST_PAGING_LEVELS == 3

/* PAE: if it's an l2h, don't touch Xen mappings */
#define SHADOW_FOREACH_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)      \
do {                                                                       \
    int _i;                                                                \
    int _xen = !shadow_mode_external(_dom);                                \
    shadow_l2e_t *_sp = map_shadow_page((_sl2mfn));                        \
    ASSERT(mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2_pae_shadow      \
           || mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2h_pae_shadow);\
    for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i++ )                 \
        if ( (!(_xen))                                                     \
             || mfn_to_shadow_page(_sl2mfn)->type != SH_type_l2h_pae_shadow\
             || ((_i + (3 * SHADOW_L2_PAGETABLE_ENTRIES))                  \
                 < (HYPERVISOR_VIRT_START >> SHADOW_L2_PAGETABLE_SHIFT)) ) \
        {                                                                  \
            (_sl2e) = _sp + _i;                                            \
            if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )          \
                {_code}                                                    \
            if ( _done ) break;                                            \
            increment_ptr_to_guest_entry(_gl2p);                           \
        }                                                                  \
    unmap_shadow_page(_sp);                                                \
} while (0)

#else 

/* 64-bit l2: touch all entries except for PAE compat guests. */
#define SHADOW_FOREACH_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)       \
do {                                                                        \
    int _i;                                                                 \
    int _xen = !shadow_mode_external(_dom);                                 \
    shadow_l2e_t *_sp = map_shadow_page((_sl2mfn));                         \
    ASSERT(mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2_64_shadow ||     \
           mfn_to_shadow_page(_sl2mfn)->type == SH_type_l2h_64_shadow);     \
    for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i++ )                  \
    {                                                                       \
        if ( (!(_xen))                                                      \
             || !IS_COMPAT(_dom)                                            \
             || mfn_to_shadow_page(_sl2mfn)->type != SH_type_l2h_64_shadow  \
             || (_i < COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(_dom)) )           \
        {                                                                   \
            (_sl2e) = _sp + _i;                                             \
            if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )           \
                {_code}                                                     \
            if ( _done ) break;                                             \
            increment_ptr_to_guest_entry(_gl2p);                            \
        }                                                                   \
    }                                                                       \
    unmap_shadow_page(_sp);                                                 \
} while (0)

#endif /* different kinds of l2 */

#if GUEST_PAGING_LEVELS == 4

/* 64-bit l3: touch all entries */
#define SHADOW_FOREACH_L3E(_sl3mfn, _sl3e, _gl3p, _done, _code)         \
do {                                                                    \
    int _i;                                                             \
    shadow_l3e_t *_sp = map_shadow_page((_sl3mfn));                     \
    ASSERT(mfn_to_shadow_page(_sl3mfn)->type == SH_type_l3_64_shadow);  \
    for ( _i = 0; _i < SHADOW_L3_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        (_sl3e) = _sp + _i;                                             \
        if ( shadow_l3e_get_flags(*(_sl3e)) & _PAGE_PRESENT )           \
            {_code}                                                     \
        if ( _done ) break;                                             \
        increment_ptr_to_guest_entry(_gl3p);                            \
    }                                                                   \
    unmap_shadow_page(_sp);                                             \
} while (0)

/* 64-bit l4: avoid Xen mappings */
#define SHADOW_FOREACH_L4E(_sl4mfn, _sl4e, _gl4p, _done, _dom, _code)   \
do {                                                                    \
    shadow_l4e_t *_sp = map_shadow_page((_sl4mfn));                     \
    int _xen = !shadow_mode_external(_dom);                             \
    int _i;                                                             \
    ASSERT(mfn_to_shadow_page(_sl4mfn)->type == SH_type_l4_64_shadow);  \
    for ( _i = 0; _i < SHADOW_L4_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        if ( (!(_xen)) || is_guest_l4_slot(_dom, _i) )                  \
        {                                                               \
            (_sl4e) = _sp + _i;                                         \
            if ( shadow_l4e_get_flags(*(_sl4e)) & _PAGE_PRESENT )       \
                {_code}                                                 \
            if ( _done ) break;                                         \
        }                                                               \
        increment_ptr_to_guest_entry(_gl4p);                            \
    }                                                                   \
    unmap_shadow_page(_sp);                                             \
} while (0)

#endif



/**************************************************************************/
/* Functions to install Xen mappings and linear mappings in shadow pages */

// XXX -- this function should probably be moved to shadow-common.c, but that
//        probably wants to wait until the shadow types have been moved from
//        shadow-types.h to shadow-private.h
//
#if CONFIG_PAGING_LEVELS == 4 && GUEST_PAGING_LEVELS == 4
void sh_install_xen_entries_in_l4(struct vcpu *v, mfn_t gl4mfn, mfn_t sl4mfn)
{
    struct domain *d = v->domain;
    shadow_l4e_t *sl4e;

    sl4e = sh_map_domain_page(sl4mfn);
    ASSERT(sl4e != NULL);
    ASSERT(sizeof (l4_pgentry_t) == sizeof (shadow_l4e_t));
    
    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));

    /* Install the per-domain mappings for this domain */
    sl4e[shadow_l4_table_offset(PERDOMAIN_VIRT_START)] =
        shadow_l4e_from_mfn(page_to_mfn(virt_to_page(d->arch.mm_perdomain_l3)),
                            __PAGE_HYPERVISOR);

    /* Linear mapping */
    sl4e[shadow_l4_table_offset(SH_LINEAR_PT_VIRT_START)] =
        shadow_l4e_from_mfn(sl4mfn, __PAGE_HYPERVISOR);

    if ( shadow_mode_translate(v->domain) && !shadow_mode_external(v->domain) )
    {
        // linear tables may not be used with translated PV guests
        sl4e[shadow_l4_table_offset(LINEAR_PT_VIRT_START)] =
            shadow_l4e_empty();
    }
    else
    {
        sl4e[shadow_l4_table_offset(LINEAR_PT_VIRT_START)] =
            shadow_l4e_from_mfn(gl4mfn, __PAGE_HYPERVISOR);
    }

    if ( shadow_mode_translate(v->domain) )
    {
        /* install domain-specific P2M table */
        sl4e[shadow_l4_table_offset(RO_MPT_VIRT_START)] =
            shadow_l4e_from_mfn(pagetable_get_mfn(d->arch.phys_table),
                                __PAGE_HYPERVISOR);
    }

    if ( IS_COMPAT(v->domain) )
    {
        /* install compat arg xlat entry */
        sl4e[shadow_l4_table_offset(COMPAT_ARG_XLAT_VIRT_BASE)] =
            shadow_l4e_from_mfn(
                    page_to_mfn(virt_to_page(d->arch.mm_arg_xlat_l3)),
                    __PAGE_HYPERVISOR);
    }

    sh_unmap_domain_page(sl4e);    
}
#endif

#if CONFIG_PAGING_LEVELS >= 3 && GUEST_PAGING_LEVELS >= 3
// For 3-on-3 PV guests, we need to make sure the xen mappings are in
// place, which means that we need to populate the l2h entry in the l3
// table.

static void sh_install_xen_entries_in_l2h(struct vcpu *v, mfn_t sl2hmfn)
{
    struct domain *d = v->domain;
    shadow_l2e_t *sl2e;
#if CONFIG_PAGING_LEVELS == 3
    int i;
#else

    if ( !pv_32bit_guest(v) )
        return;
#endif

    sl2e = sh_map_domain_page(sl2hmfn);
    ASSERT(sl2e != NULL);
    ASSERT(sizeof (l2_pgentry_t) == sizeof (shadow_l2e_t));
    
#if CONFIG_PAGING_LEVELS == 3

    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));

    /* Install the per-domain mappings for this domain */
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        sl2e[shadow_l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            shadow_l2e_from_mfn(
                page_to_mfn(virt_to_page(d->arch.mm_perdomain_pt) + i),
                __PAGE_HYPERVISOR);
    
    /* We don't set up a linear mapping here because we can't until this
     * l2h is installed in an l3e.  sh_update_linear_entries() handles
     * the linear mappings when CR3 (and so the fourth l3e) is loaded.  
     * We zero them here, just as a safety measure.
     */
    for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
        sl2e[shadow_l2_table_offset(LINEAR_PT_VIRT_START) + i] =
            shadow_l2e_empty();
    for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
        sl2e[shadow_l2_table_offset(SH_LINEAR_PT_VIRT_START) + i] =
            shadow_l2e_empty();

    if ( shadow_mode_translate(d) )
    {
        /* Install the domain-specific p2m table */
        l3_pgentry_t *p2m;
        ASSERT(pagetable_get_pfn(d->arch.phys_table) != 0);
        p2m = sh_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
        for ( i = 0; i < MACHPHYS_MBYTES>>1; i++ )
        {
            sl2e[shadow_l2_table_offset(RO_MPT_VIRT_START) + i] =
                (l3e_get_flags(p2m[i]) & _PAGE_PRESENT)
                ? shadow_l2e_from_mfn(_mfn(l3e_get_pfn(p2m[i])),
                                      __PAGE_HYPERVISOR)
                : shadow_l2e_empty();
        }
        sh_unmap_domain_page(p2m);
    }

#else

    /* Copy the common Xen mappings from the idle domain */
    memcpy(
        &sl2e[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
        &compat_idle_pg_table_l2[l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
        COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*sl2e));

#endif
    
    sh_unmap_domain_page(sl2e);
}
#endif


#if CONFIG_PAGING_LEVELS == 2 && GUEST_PAGING_LEVELS == 2
void sh_install_xen_entries_in_l2(struct vcpu *v, mfn_t gl2mfn, mfn_t sl2mfn)
{
    struct domain *d = v->domain;
    shadow_l2e_t *sl2e;
    int i;

    sl2e = sh_map_domain_page(sl2mfn);
    ASSERT(sl2e != NULL);
    ASSERT(sizeof (l2_pgentry_t) == sizeof (shadow_l2e_t));
    
    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl2e[L2_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));

    /* Install the per-domain mappings for this domain */
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        sl2e[shadow_l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            shadow_l2e_from_mfn(
                page_to_mfn(virt_to_page(d->arch.mm_perdomain_pt) + i),
                __PAGE_HYPERVISOR);

    /* Linear mapping */
    sl2e[shadow_l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
        shadow_l2e_from_mfn(sl2mfn, __PAGE_HYPERVISOR);

    if ( shadow_mode_translate(v->domain) && !shadow_mode_external(v->domain) )
    {
        // linear tables may not be used with translated PV guests
        sl2e[shadow_l2_table_offset(LINEAR_PT_VIRT_START)] =
            shadow_l2e_empty();
    }
    else
    {
        sl2e[shadow_l2_table_offset(LINEAR_PT_VIRT_START)] =
            shadow_l2e_from_mfn(gl2mfn, __PAGE_HYPERVISOR);
    }

    if ( shadow_mode_translate(d) )
    {
        /* install domain-specific P2M table */
        sl2e[shadow_l2_table_offset(RO_MPT_VIRT_START)] =
            shadow_l2e_from_mfn(pagetable_get_mfn(d->arch.phys_table),
                                __PAGE_HYPERVISOR);
    }

    sh_unmap_domain_page(sl2e);
}
#endif



/**************************************************************************/
/* Create a shadow of a given guest page.
 */
static mfn_t
sh_make_shadow(struct vcpu *v, mfn_t gmfn, u32 shadow_type)
{
    mfn_t smfn = shadow_alloc(v->domain, shadow_type, mfn_x(gmfn));
    SHADOW_DEBUG(MAKE_SHADOW, "(%05lx, %u)=>%05lx\n",
                  mfn_x(gmfn), shadow_type, mfn_x(smfn));

    if ( shadow_type != SH_type_l2_32_shadow 
         && shadow_type != SH_type_l2_pae_shadow 
         && shadow_type != SH_type_l2h_pae_shadow 
         && shadow_type != SH_type_l4_64_shadow )
        /* Lower-level shadow, not yet linked form a higher level */
        mfn_to_shadow_page(smfn)->up = 0;

#if GUEST_PAGING_LEVELS == 4
#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL) 
    if ( shadow_type == SH_type_l4_64_shadow &&
         unlikely(v->domain->arch.paging.shadow.opt_flags & SHOPT_LINUX_L3_TOPLEVEL) )
    {
        /* We're shadowing a new l4, but we've been assuming the guest uses
         * only one l4 per vcpu and context switches using an l4 entry. 
         * Count the number of active l4 shadows.  If there are enough
         * of them, decide that this isn't an old linux guest, and stop
         * pinning l3es.  This is not very quick but it doesn't happen
         * very often. */
        struct list_head *l, *t;
        struct shadow_page_info *sp;
        struct vcpu *v2;
        int l4count = 0, vcpus = 0;
        list_for_each(l, &v->domain->arch.paging.shadow.pinned_shadows)
        {
            sp = list_entry(l, struct shadow_page_info, list);
            if ( sp->type == SH_type_l4_64_shadow )
                l4count++;
        }
        for_each_vcpu ( v->domain, v2 ) 
            vcpus++;
        if ( l4count > 2 * vcpus ) 
        {
            /* Unpin all the pinned l3 tables, and don't pin any more. */
            list_for_each_safe(l, t, &v->domain->arch.paging.shadow.pinned_shadows)
            {
                sp = list_entry(l, struct shadow_page_info, list);
                if ( sp->type == SH_type_l3_64_shadow )
                    sh_unpin(v, shadow_page_to_mfn(sp));
            }
            v->domain->arch.paging.shadow.opt_flags &= ~SHOPT_LINUX_L3_TOPLEVEL;
        }
    }
#endif
#endif

    // Create the Xen mappings...
    if ( !shadow_mode_external(v->domain) )
    {
        switch (shadow_type) 
        {
#if CONFIG_PAGING_LEVELS == 4 && GUEST_PAGING_LEVELS == 4
        case SH_type_l4_shadow:
            sh_install_xen_entries_in_l4(v, gmfn, smfn); break;
#endif
#if CONFIG_PAGING_LEVELS >= 3 && GUEST_PAGING_LEVELS >= 3
        case SH_type_l2h_shadow:
#ifdef CONFIG_COMPAT
            ASSERT( IS_COMPAT(v->domain) );
#endif
            sh_install_xen_entries_in_l2h(v, smfn); break;
#endif
#if CONFIG_PAGING_LEVELS == 2 && GUEST_PAGING_LEVELS == 2
        case SH_type_l2_shadow:
            sh_install_xen_entries_in_l2(v, gmfn, smfn); break;
#endif
        default: /* Do nothing */ break;
        }
    }

    shadow_promote(v, gmfn, shadow_type);
    set_shadow_status(v, gmfn, shadow_type, smfn);

    return smfn;
}

/* Make a splintered superpage shadow */
static mfn_t
make_fl1_shadow(struct vcpu *v, gfn_t gfn)
{
    mfn_t smfn = shadow_alloc(v->domain, SH_type_fl1_shadow,
                               (unsigned long) gfn_x(gfn));

    SHADOW_DEBUG(MAKE_SHADOW, "(%" SH_PRI_gfn ")=>%" PRI_mfn "\n",
                  gfn_x(gfn), mfn_x(smfn));

    set_fl1_shadow_status(v, gfn, smfn);
    return smfn;
}


#if SHADOW_PAGING_LEVELS == GUEST_PAGING_LEVELS
mfn_t
sh_make_monitor_table(struct vcpu *v)
{
    struct domain *d = v->domain;

    ASSERT(pagetable_get_pfn(v->arch.monitor_table) == 0);
    
    /* Guarantee we can get the memory we need */
    shadow_prealloc(d, SHADOW_MAX_ORDER);

#if CONFIG_PAGING_LEVELS == 4    
    {
        mfn_t m4mfn;
        m4mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        sh_install_xen_entries_in_l4(v, m4mfn, m4mfn);
        /* Remember the level of this table */
        mfn_to_page(m4mfn)->shadow_flags = 4;
#if SHADOW_PAGING_LEVELS < 4
        // Install a monitor l3 table in slot 0 of the l4 table.
        // This is used for shadow linear maps.
        {
            mfn_t m3mfn; 
            l4_pgentry_t *l4e;
            m3mfn = shadow_alloc(d, SH_type_monitor_table, 0);
            mfn_to_page(m3mfn)->shadow_flags = 3;
            l4e = sh_map_domain_page(m4mfn);
            l4e[0] = l4e_from_pfn(mfn_x(m3mfn), __PAGE_HYPERVISOR);
            sh_unmap_domain_page(l4e);
            if ( pv_32bit_guest(v) )
            {
                // Install a monitor l2 table in slot 3 of the l3 table.
                // This is used for all Xen entries.
                mfn_t m2mfn;
                l3_pgentry_t *l3e;
                m2mfn = shadow_alloc(d, SH_type_monitor_table, 0);
                mfn_to_page(m2mfn)->shadow_flags = 2;
                l3e = sh_map_domain_page(m3mfn);
                l3e[3] = l3e_from_pfn(mfn_x(m2mfn), _PAGE_PRESENT);
                sh_install_xen_entries_in_l2h(v, m2mfn);
                sh_unmap_domain_page(l3e);
            }
        }
#endif /* SHADOW_PAGING_LEVELS < 4 */
        return m4mfn;
    }

#elif CONFIG_PAGING_LEVELS == 3

    {
        mfn_t m3mfn, m2mfn; 
        l3_pgentry_t *l3e;
        l2_pgentry_t *l2e;
        int i;

        m3mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        /* Remember the level of this table */
        mfn_to_page(m3mfn)->shadow_flags = 3;

        // Install a monitor l2 table in slot 3 of the l3 table.
        // This is used for all Xen entries, including linear maps
        m2mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        mfn_to_page(m2mfn)->shadow_flags = 2;
        l3e = sh_map_domain_page(m3mfn);
        l3e[3] = l3e_from_pfn(mfn_x(m2mfn), _PAGE_PRESENT);
        sh_install_xen_entries_in_l2h(v, m2mfn);
        /* Install the monitor's own linear map */
        l2e = sh_map_domain_page(m2mfn);
        for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
            l2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
                (l3e_get_flags(l3e[i]) & _PAGE_PRESENT) 
                ? l2e_from_pfn(l3e_get_pfn(l3e[i]), __PAGE_HYPERVISOR) 
                : l2e_empty();
        sh_unmap_domain_page(l2e);
        sh_unmap_domain_page(l3e);

        SHADOW_PRINTK("new monitor table: %#lx\n", mfn_x(m3mfn));
        return m3mfn;
    }

#elif CONFIG_PAGING_LEVELS == 2

    {
        mfn_t m2mfn;
        m2mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        sh_install_xen_entries_in_l2(v, m2mfn, m2mfn);
        /* Remember the level of this table */
        mfn_to_page(m2mfn)->shadow_flags = 2;
        return m2mfn;
    }

#else
#error this should not happen
#endif /* CONFIG_PAGING_LEVELS */
}
#endif /* SHADOW_PAGING_LEVELS == GUEST_PAGING_LEVELS */

/**************************************************************************/
/* These functions also take a virtual address and return the level-N
 * shadow table mfn and entry, but they create the shadow pagetables if
 * they are needed.  The "demand" argument is non-zero when handling
 * a demand fault (so we know what to do about accessed bits &c).
 * If the necessary tables are not present in the guest, they return NULL. */

/* N.B. The use of GUEST_PAGING_LEVELS here is correct.  If the shadow has
 * more levels than the guest, the upper levels are always fixed and do not 
 * reflect any information from the guest, so we do not use these functions 
 * to access them. */

#if GUEST_PAGING_LEVELS >= 4
static shadow_l4e_t * shadow_get_and_create_l4e(struct vcpu *v, 
                                                walk_t *gw, 
                                                mfn_t *sl4mfn)
{
    /* There is always a shadow of the top level table.  Get it. */
    *sl4mfn = pagetable_get_mfn(v->arch.shadow_table[0]);
    /* Reading the top level table is always valid. */
    return sh_linear_l4_table(v) + shadow_l4_linear_offset(gw->va);
}

static shadow_l3e_t * shadow_get_and_create_l3e(struct vcpu *v, 
                                                walk_t *gw, 
                                                mfn_t *sl3mfn,
                                                fetch_type_t ft)
{
    mfn_t sl4mfn;
    shadow_l4e_t *sl4e;
    if ( !mfn_valid(gw->l3mfn) ) return NULL; /* No guest page. */
    /* Get the l4e */
    sl4e = shadow_get_and_create_l4e(v, gw, &sl4mfn);
    ASSERT(sl4e != NULL);
    if ( shadow_l4e_get_flags(*sl4e) & _PAGE_PRESENT ) 
    {
        *sl3mfn = shadow_l4e_get_mfn(*sl4e);
        ASSERT(mfn_valid(*sl3mfn));
    } 
    else 
    {
        int r;
        shadow_l4e_t new_sl4e;
        /* No l3 shadow installed: find and install it. */
        *sl3mfn = get_shadow_status(v, gw->l3mfn, SH_type_l3_shadow);
        if ( !mfn_valid(*sl3mfn) ) 
        {
            /* No l3 shadow of this page exists at all: make one. */
            *sl3mfn = sh_make_shadow(v, gw->l3mfn, SH_type_l3_shadow);
        }
        /* Install the new sl3 table in the sl4e */
        l4e_propagate_from_guest(v, gw->l4e, gw->l4mfn, 
                                 *sl3mfn, &new_sl4e, ft);
        r = shadow_set_l4e(v, sl4e, new_sl4e, sl4mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);
        if ( r & SHADOW_SET_ERROR )
            return NULL;
    }
    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l3_table(v) + shadow_l3_linear_offset(gw->va);
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


static shadow_l2e_t * shadow_get_and_create_l2e(struct vcpu *v, 
                                                walk_t *gw, 
                                                mfn_t *sl2mfn,
                                                fetch_type_t ft)
{
#if GUEST_PAGING_LEVELS >= 4 /* 64bit... */
    mfn_t sl3mfn = _mfn(INVALID_MFN);
    shadow_l3e_t *sl3e;
    if ( !mfn_valid(gw->l2mfn) ) return NULL; /* No guest page. */
    /* Get the l3e */
    sl3e = shadow_get_and_create_l3e(v, gw, &sl3mfn, ft);
    if ( sl3e == NULL ) return NULL; 
    if ( shadow_l3e_get_flags(*sl3e) & _PAGE_PRESENT ) 
    {
        *sl2mfn = shadow_l3e_get_mfn(*sl3e);
        ASSERT(mfn_valid(*sl2mfn));
    } 
    else 
    {
        int r;
        shadow_l3e_t new_sl3e;
        unsigned int t = SH_type_l2_shadow;

#ifdef CONFIG_COMPAT
        /* Tag compat L2 containing hypervisor (m2p) mappings */
        if ( IS_COMPAT(v->domain) &&
             guest_l4_table_offset(gw->va) == 0 &&
             guest_l3_table_offset(gw->va) == 3 )
            t = SH_type_l2h_shadow;
#endif
        /* No l2 shadow installed: find and install it. */
        *sl2mfn = get_shadow_status(v, gw->l2mfn, t);
        if ( !mfn_valid(*sl2mfn) ) 
        {
            /* No l2 shadow of this page exists at all: make one. */
            *sl2mfn = sh_make_shadow(v, gw->l2mfn, t);
        }
        /* Install the new sl2 table in the sl3e */
        l3e_propagate_from_guest(v, gw->l3e, gw->l3mfn, 
                                 *sl2mfn, &new_sl3e, ft);
        r = shadow_set_l3e(v, sl3e, new_sl3e, sl3mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);
        if ( r & SHADOW_SET_ERROR )
            return NULL;        
    }
    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#elif GUEST_PAGING_LEVELS == 3 /* PAE... */
    /* We never demand-shadow PAE l3es: they are only created in
     * sh_update_cr3().  Check if the relevant sl3e is present. */
    shadow_l3e_t *sl3e = ((shadow_l3e_t *)&v->arch.paging.shadow.l3table) 
        + shadow_l3_linear_offset(gw->va);
    if ( !(shadow_l3e_get_flags(*sl3e) & _PAGE_PRESENT) ) 
        return NULL;
    *sl2mfn = shadow_l3e_get_mfn(*sl3e);
    ASSERT(mfn_valid(*sl2mfn));
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#else /* 32bit... */
    /* There is always a shadow of the top level table.  Get it. */
    *sl2mfn = pagetable_get_mfn(v->arch.shadow_table[0]);
    /* This next line is important: the guest l2 has a 16k
     * shadow, we need to return the right mfn of the four. This
     * call will set it for us as a side-effect. */
    (void) shadow_l2_index(sl2mfn, guest_index(gw->l2e));
    /* Reading the top level table is always valid. */
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#endif 
}


static shadow_l1e_t * shadow_get_and_create_l1e(struct vcpu *v, 
                                                walk_t *gw, 
                                                mfn_t *sl1mfn,
                                                fetch_type_t ft)
{
    mfn_t sl2mfn;
    shadow_l2e_t *sl2e;

    /* Get the l2e */
    sl2e = shadow_get_and_create_l2e(v, gw, &sl2mfn, ft);
    if ( sl2e == NULL ) return NULL;
    /* Install the sl1 in the l2e if it wasn't there or if we need to
     * re-do it to fix a PSE dirty bit. */
    if ( shadow_l2e_get_flags(*sl2e) & _PAGE_PRESENT 
         && likely(ft != ft_demand_write
                   || (guest_l2e_get_flags(*gw->l2e) & _PAGE_DIRTY) 
                   || !(guest_l2e_get_flags(*gw->l2e) & _PAGE_PSE)) )
    {
        *sl1mfn = shadow_l2e_get_mfn(*sl2e);
        ASSERT(mfn_valid(*sl1mfn));
    } 
    else 
    {
        shadow_l2e_t new_sl2e;
        int r, flags = guest_l2e_get_flags(*gw->l2e);
        /* No l1 shadow installed: find and install it. */
        if ( !(flags & _PAGE_PRESENT) )
            return NULL; /* No guest page. */
        if ( guest_supports_superpages(v) && (flags & _PAGE_PSE) ) 
        {
            /* Splintering a superpage */
            gfn_t l2gfn = guest_l2e_get_gfn(*gw->l2e);
            *sl1mfn = get_fl1_shadow_status(v, l2gfn);
            if ( !mfn_valid(*sl1mfn) ) 
            {
                /* No fl1 shadow of this superpage exists at all: make one. */
                *sl1mfn = make_fl1_shadow(v, l2gfn);
            }
        } 
        else 
        {
            /* Shadowing an actual guest l1 table */
            if ( !mfn_valid(gw->l2mfn) ) return NULL; /* No guest page. */
            *sl1mfn = get_shadow_status(v, gw->l1mfn, SH_type_l1_shadow);
            if ( !mfn_valid(*sl1mfn) ) 
            {
                /* No l1 shadow of this page exists at all: make one. */
                *sl1mfn = sh_make_shadow(v, gw->l1mfn, SH_type_l1_shadow);
            }
        }
        /* Install the new sl1 table in the sl2e */
        l2e_propagate_from_guest(v, gw->l2e, gw->l2mfn, 
                                 *sl1mfn, &new_sl2e, ft);
        r = shadow_set_l2e(v, sl2e, new_sl2e, sl2mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);        
        if ( r & SHADOW_SET_ERROR )
            return NULL;
        /* This next line is important: in 32-on-PAE and 32-on-64 modes,
         * the guest l1 table has an 8k shadow, and we need to return
         * the right mfn of the pair. This call will set it for us as a
         * side-effect.  (In all other cases, it's a no-op and will be
         * compiled out.) */
        (void) shadow_l1_index(sl1mfn, guest_l1_table_offset(gw->va));
    }
    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l1_table(v) + shadow_l1_linear_offset(gw->va);
}



/**************************************************************************/
/* Destructors for shadow tables: 
 * Unregister the shadow, decrement refcounts of any entries present in it,
 * and release the memory.
 *
 * N.B. These destructors do not clear the contents of the shadows.
 *      This allows us to delay TLB shootdowns until the page is being reused.
 *      See shadow_alloc() and shadow_free() for how this is handled.
 */

#if GUEST_PAGING_LEVELS >= 4
void sh_destroy_l4_shadow(struct vcpu *v, mfn_t smfn)
{
    shadow_l4e_t *sl4e;
    u32 t = mfn_to_shadow_page(smfn)->type;
    mfn_t gmfn, sl4mfn;

    SHADOW_DEBUG(DESTROY_SHADOW,
                  "%s(%05lx)\n", __func__, mfn_x(smfn));
    ASSERT(t == SH_type_l4_shadow);

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = _mfn(mfn_to_shadow_page(smfn)->backpointer);
    delete_shadow_status(v, gmfn, t, smfn);
    shadow_demote(v, gmfn, t);
    /* Decrement refcounts of all the old entries */
    sl4mfn = smfn; 
    SHADOW_FOREACH_L4E(sl4mfn, sl4e, 0, 0, v->domain, {
        if ( shadow_l4e_get_flags(*sl4e) & _PAGE_PRESENT ) 
        {
            sh_put_ref(v, shadow_l4e_get_mfn(*sl4e),
                       (((paddr_t)mfn_x(sl4mfn)) << PAGE_SHIFT) 
                       | ((unsigned long)sl4e & ~PAGE_MASK));
        }
    });
    
    /* Put the memory back in the pool */
    shadow_free(v->domain, smfn);
}

void sh_destroy_l3_shadow(struct vcpu *v, mfn_t smfn)
{
    shadow_l3e_t *sl3e;
    u32 t = mfn_to_shadow_page(smfn)->type;
    mfn_t gmfn, sl3mfn;

    SHADOW_DEBUG(DESTROY_SHADOW,
                  "%s(%05lx)\n", __func__, mfn_x(smfn));
    ASSERT(t == SH_type_l3_shadow);

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = _mfn(mfn_to_shadow_page(smfn)->backpointer);
    delete_shadow_status(v, gmfn, t, smfn);
    shadow_demote(v, gmfn, t);

    /* Decrement refcounts of all the old entries */
    sl3mfn = smfn; 
    SHADOW_FOREACH_L3E(sl3mfn, sl3e, 0, 0, {
        if ( shadow_l3e_get_flags(*sl3e) & _PAGE_PRESENT ) 
            sh_put_ref(v, shadow_l3e_get_mfn(*sl3e),
                        (((paddr_t)mfn_x(sl3mfn)) << PAGE_SHIFT) 
                        | ((unsigned long)sl3e & ~PAGE_MASK));
    });

    /* Put the memory back in the pool */
    shadow_free(v->domain, smfn);
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


void sh_destroy_l2_shadow(struct vcpu *v, mfn_t smfn)
{
    shadow_l2e_t *sl2e;
    u32 t = mfn_to_shadow_page(smfn)->type;
    mfn_t gmfn, sl2mfn;

    SHADOW_DEBUG(DESTROY_SHADOW,
                  "%s(%05lx)\n", __func__, mfn_x(smfn));

#if GUEST_PAGING_LEVELS >= 3
    ASSERT(t == SH_type_l2_shadow || t == SH_type_l2h_shadow);
#else
    ASSERT(t == SH_type_l2_shadow);
#endif

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = _mfn(mfn_to_shadow_page(smfn)->backpointer);
    delete_shadow_status(v, gmfn, t, smfn);
    shadow_demote(v, gmfn, t);

    /* Decrement refcounts of all the old entries */
    sl2mfn = smfn;
    SHADOW_FOREACH_L2E(sl2mfn, sl2e, 0, 0, v->domain, {
        if ( shadow_l2e_get_flags(*sl2e) & _PAGE_PRESENT ) 
            sh_put_ref(v, shadow_l2e_get_mfn(*sl2e),
                        (((paddr_t)mfn_x(sl2mfn)) << PAGE_SHIFT) 
                        | ((unsigned long)sl2e & ~PAGE_MASK));
    });

    /* Put the memory back in the pool */
    shadow_free(v->domain, smfn);
}

void sh_destroy_l1_shadow(struct vcpu *v, mfn_t smfn)
{
    struct domain *d = v->domain;
    shadow_l1e_t *sl1e;
    u32 t = mfn_to_shadow_page(smfn)->type;

    SHADOW_DEBUG(DESTROY_SHADOW,
                  "%s(%05lx)\n", __func__, mfn_x(smfn));
    ASSERT(t == SH_type_l1_shadow || t == SH_type_fl1_shadow);

    /* Record that the guest page isn't shadowed any more (in this type) */
    if ( t == SH_type_fl1_shadow )
    {
        gfn_t gfn = _gfn(mfn_to_shadow_page(smfn)->backpointer);
        delete_fl1_shadow_status(v, gfn, smfn);
    }
    else 
    {
        mfn_t gmfn = _mfn(mfn_to_shadow_page(smfn)->backpointer);
        delete_shadow_status(v, gmfn, t, smfn);
        shadow_demote(v, gmfn, t);
    }
    
    if ( shadow_mode_refcounts(d) )
    {
        /* Decrement refcounts of all the old entries */
        mfn_t sl1mfn = smfn; 
        SHADOW_FOREACH_L1E(sl1mfn, sl1e, 0, 0, {
            if ( (shadow_l1e_get_flags(*sl1e) & _PAGE_PRESENT)
                 && !sh_l1e_is_magic(*sl1e) )
                shadow_put_page_from_l1e(*sl1e, d);
        });
    }
    
    /* Put the memory back in the pool */
    shadow_free(v->domain, smfn);
}

#if SHADOW_PAGING_LEVELS == GUEST_PAGING_LEVELS
void sh_destroy_monitor_table(struct vcpu *v, mfn_t mmfn)
{
    struct domain *d = v->domain;
    ASSERT(mfn_to_shadow_page(mmfn)->type == SH_type_monitor_table);

#if (CONFIG_PAGING_LEVELS == 4) && (SHADOW_PAGING_LEVELS != 4)
    /* Need to destroy the l3 monitor page in slot 0 too */
    {
        mfn_t m3mfn;
        l4_pgentry_t *l4e = sh_map_domain_page(mmfn);
        ASSERT(l4e_get_flags(l4e[0]) & _PAGE_PRESENT);
        m3mfn = _mfn(l4e_get_pfn(l4e[0]));
        if ( pv_32bit_guest(v) )
        {
            /* Need to destroy the l2 monitor page in slot 3 too */
            l3_pgentry_t *l3e = sh_map_domain_page(m3mfn);
            ASSERT(l3e_get_flags(l3e[3]) & _PAGE_PRESENT);
            shadow_free(d, _mfn(l3e_get_pfn(l3e[3])));
            sh_unmap_domain_page(l3e);
        }
        shadow_free(d, m3mfn);
        sh_unmap_domain_page(l4e);
    }
#elif CONFIG_PAGING_LEVELS == 3
    /* Need to destroy the l2 monitor page in slot 4 too */
    {
        l3_pgentry_t *l3e = sh_map_domain_page(mmfn);
        ASSERT(l3e_get_flags(l3e[3]) & _PAGE_PRESENT);
        shadow_free(d, _mfn(l3e_get_pfn(l3e[3])));
        sh_unmap_domain_page(l3e);
    }
#endif

    /* Put the memory back in the pool */
    shadow_free(d, mmfn);
}
#endif

/**************************************************************************/
/* Functions to destroy non-Xen mappings in a pagetable hierarchy.
 * These are called from common code when we are running out of shadow
 * memory, and unpinning all the top-level shadows hasn't worked. 
 *
 * This implementation is pretty crude and slow, but we hope that it won't 
 * be called very often. */

#if GUEST_PAGING_LEVELS == 2

void sh_unhook_32b_mappings(struct vcpu *v, mfn_t sl2mfn)
{    
    shadow_l2e_t *sl2e;
    SHADOW_FOREACH_L2E(sl2mfn, sl2e, 0, 0, v->domain, {
        (void) shadow_set_l2e(v, sl2e, shadow_l2e_empty(), sl2mfn);
    });
}

#elif GUEST_PAGING_LEVELS == 3

void sh_unhook_pae_mappings(struct vcpu *v, mfn_t sl2mfn)
/* Walk a PAE l2 shadow, unhooking entries from all the subshadows */
{
    shadow_l2e_t *sl2e;
    SHADOW_FOREACH_L2E(sl2mfn, sl2e, 0, 0, v->domain, {
        (void) shadow_set_l2e(v, sl2e, shadow_l2e_empty(), sl2mfn);
    });
}

#elif GUEST_PAGING_LEVELS == 4

void sh_unhook_64b_mappings(struct vcpu *v, mfn_t sl4mfn)
{
    shadow_l4e_t *sl4e;
    SHADOW_FOREACH_L4E(sl4mfn, sl4e, 0, 0, v->domain, {
        (void) shadow_set_l4e(v, sl4e, shadow_l4e_empty(), sl4mfn);
    });
}

#endif

/**************************************************************************/
/* Internal translation functions.
 * These functions require a pointer to the shadow entry that will be updated.
 */

/* These functions take a new guest entry, translate it to shadow and write 
 * the shadow entry.
 *
 * They return the same bitmaps as the shadow_set_lXe() functions.
 */

#if GUEST_PAGING_LEVELS >= 4
static int validate_gl4e(struct vcpu *v, void *new_ge, mfn_t sl4mfn, void *se)
{
    shadow_l4e_t new_sl4e;
    guest_l4e_t *new_gl4e = new_ge;
    shadow_l4e_t *sl4p = se;
    mfn_t sl3mfn = _mfn(INVALID_MFN);
    int result = 0;

    perfc_incrc(shadow_validate_gl4e_calls);

    if ( guest_l4e_get_flags(*new_gl4e) & _PAGE_PRESENT )
    {
        gfn_t gl3gfn = guest_l4e_get_gfn(*new_gl4e);
        mfn_t gl3mfn = vcpu_gfn_to_mfn(v, gl3gfn);
        if ( mfn_valid(gl3mfn) )
            sl3mfn = get_shadow_status(v, gl3mfn, SH_type_l3_shadow);
        else
            result |= SHADOW_SET_ERROR;
    }
    l4e_propagate_from_guest(v, new_gl4e, _mfn(INVALID_MFN),
                             sl3mfn, &new_sl4e, ft_prefetch);

    // check for updates to xen reserved slots
    if ( !shadow_mode_external(v->domain) )
    {
        int shadow_index = (((unsigned long)sl4p & ~PAGE_MASK) /
                            sizeof(shadow_l4e_t));
        int reserved_xen_slot = !is_guest_l4_slot(v->domain, shadow_index);

        if ( unlikely(reserved_xen_slot) )
        {
            // attempt by the guest to write to a xen reserved slot
            //
            SHADOW_PRINTK("%s out-of-range update "
                           "sl4mfn=%05lx index=0x%x val=%" SH_PRI_pte "\n",
                           __func__, mfn_x(sl4mfn), shadow_index, new_sl4e.l4);
            if ( shadow_l4e_get_flags(new_sl4e) & _PAGE_PRESENT )
            {
                SHADOW_ERROR("out-of-range l4e update\n");
                result |= SHADOW_SET_ERROR;
            }

            // do not call shadow_set_l4e...
            return result;
        }
    }

    result |= shadow_set_l4e(v, sl4p, new_sl4e, sl4mfn);
    return result;
}


static int validate_gl3e(struct vcpu *v, void *new_ge, mfn_t sl3mfn, void *se)
{
    shadow_l3e_t new_sl3e;
    guest_l3e_t *new_gl3e = new_ge;
    shadow_l3e_t *sl3p = se;
    mfn_t sl2mfn = _mfn(INVALID_MFN);
    int result = 0;

    perfc_incrc(shadow_validate_gl3e_calls);

    if ( guest_l3e_get_flags(*new_gl3e) & _PAGE_PRESENT )
    {
        gfn_t gl2gfn = guest_l3e_get_gfn(*new_gl3e);
        mfn_t gl2mfn = vcpu_gfn_to_mfn(v, gl2gfn);
        if ( mfn_valid(gl2mfn) )
            sl2mfn = get_shadow_status(v, gl2mfn, SH_type_l2_shadow);
        else
            result |= SHADOW_SET_ERROR;
    }
    l3e_propagate_from_guest(v, new_gl3e, _mfn(INVALID_MFN), 
                             sl2mfn, &new_sl3e, ft_prefetch);
    result |= shadow_set_l3e(v, sl3p, new_sl3e, sl3mfn);

    return result;
}
#endif // GUEST_PAGING_LEVELS >= 4

static int validate_gl2e(struct vcpu *v, void *new_ge, mfn_t sl2mfn, void *se)
{
    shadow_l2e_t new_sl2e;
    guest_l2e_t *new_gl2e = new_ge;
    shadow_l2e_t *sl2p = se;
    mfn_t sl1mfn = _mfn(INVALID_MFN);
    int result = 0;

    perfc_incrc(shadow_validate_gl2e_calls);

    if ( guest_l2e_get_flags(*new_gl2e) & _PAGE_PRESENT )
    {
        gfn_t gl1gfn = guest_l2e_get_gfn(*new_gl2e);
        if ( guest_supports_superpages(v) &&
             (guest_l2e_get_flags(*new_gl2e) & _PAGE_PSE) )
        {
            // superpage -- need to look up the shadow L1 which holds the
            // splitters...
            sl1mfn = get_fl1_shadow_status(v, gl1gfn);
#if 0
            // XXX - it's possible that we want to do some kind of prefetch
            // for superpage fl1's here, but this is *not* on the demand path,
            // so we'll hold off trying that for now...
            //
            if ( !mfn_valid(sl1mfn) )
                sl1mfn = make_fl1_shadow(v, gl1gfn);
#endif
        }
        else
        {
            mfn_t gl1mfn = vcpu_gfn_to_mfn(v, gl1gfn);
            if ( mfn_valid(gl1mfn) )
                sl1mfn = get_shadow_status(v, gl1mfn, SH_type_l1_shadow);
            else
                result |= SHADOW_SET_ERROR;
        }
    }
    l2e_propagate_from_guest(v, new_gl2e, _mfn(INVALID_MFN),
                             sl1mfn, &new_sl2e, ft_prefetch);

    // check for updates to xen reserved slots in PV guests...
    // XXX -- need to revisit this for PV 3-on-4 guests.
    //
#if SHADOW_PAGING_LEVELS < 4
#if CONFIG_PAGING_LEVELS == SHADOW_PAGING_LEVELS
    if ( !shadow_mode_external(v->domain) )
    {
        int shadow_index = (((unsigned long)sl2p & ~PAGE_MASK) /
                            sizeof(shadow_l2e_t));
        int reserved_xen_slot;

#if SHADOW_PAGING_LEVELS == 3
        reserved_xen_slot = 
            ((mfn_to_shadow_page(sl2mfn)->type == SH_type_l2h_pae_shadow) &&
             (shadow_index 
              >= (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1))));
#else /* SHADOW_PAGING_LEVELS == 2 */
        reserved_xen_slot = (shadow_index >= L2_PAGETABLE_FIRST_XEN_SLOT);
#endif

        if ( unlikely(reserved_xen_slot) )
        {
            // attempt by the guest to write to a xen reserved slot
            //
            SHADOW_PRINTK("%s out-of-range update "
                           "sl2mfn=%05lx index=0x%x val=%" SH_PRI_pte "\n",
                           __func__, mfn_x(sl2mfn), shadow_index, new_sl2e.l2);
            if ( shadow_l2e_get_flags(new_sl2e) & _PAGE_PRESENT )
            {
                SHADOW_ERROR("out-of-range l2e update\n");
                result |= SHADOW_SET_ERROR;
            }

            // do not call shadow_set_l2e...
            return result;
        }
    }
#endif /* CONFIG_PAGING_LEVELS == SHADOW_PAGING_LEVELS */
#endif /* SHADOW_PAGING_LEVELS < 4 */

    result |= shadow_set_l2e(v, sl2p, new_sl2e, sl2mfn);

    return result;
}

static int validate_gl1e(struct vcpu *v, void *new_ge, mfn_t sl1mfn, void *se)
{
    shadow_l1e_t new_sl1e;
    guest_l1e_t *new_gl1e = new_ge;
    shadow_l1e_t *sl1p = se;
    gfn_t gfn;
    mfn_t gmfn;
    int result = 0, mmio;

    perfc_incrc(shadow_validate_gl1e_calls);

    gfn = guest_l1e_get_gfn(*new_gl1e);
    gmfn = vcpu_gfn_to_mfn(v, gfn);

    mmio = (is_hvm_vcpu(v) && paging_vcpu_mode_translate(v) && !mfn_valid(gmfn));
    l1e_propagate_from_guest(v, new_gl1e, _mfn(INVALID_MFN), gmfn, &new_sl1e, 
                             ft_prefetch, mmio);
    
    result |= shadow_set_l1e(v, sl1p, new_sl1e, sl1mfn);
    return result;
}


/**************************************************************************/
/* Functions which translate and install the shadows of arbitrary guest 
 * entries that we have just seen the guest write. */


static inline int 
sh_map_and_validate(struct vcpu *v, mfn_t gmfn,
                     void *new_gp, u32 size, u32 sh_type, 
                     u32 (*shadow_index)(mfn_t *smfn, u32 idx),
                     int (*validate_ge)(struct vcpu *v, void *ge, 
                                        mfn_t smfn, void *se))
/* Generic function for mapping and validating. */
{
    mfn_t smfn, smfn2, map_mfn;
    shadow_l1e_t *sl1p;
    u32 shadow_idx, guest_idx;
    int result = 0;

    /* Align address and size to guest entry boundaries */
    size += (unsigned long)new_gp & (sizeof (guest_l1e_t) - 1);
    new_gp = (void *)((unsigned long)new_gp & ~(sizeof (guest_l1e_t) - 1));
    size = (size + sizeof (guest_l1e_t) - 1) & ~(sizeof (guest_l1e_t) - 1);
    ASSERT(size + (((unsigned long)new_gp) & ~PAGE_MASK) <= PAGE_SIZE);

    /* Map the shadow page */
    smfn = get_shadow_status(v, gmfn, sh_type);
    ASSERT(mfn_valid(smfn)); /* Otherwise we would not have been called */
    guest_idx = guest_index(new_gp);
    map_mfn = smfn;
    shadow_idx = shadow_index(&map_mfn, guest_idx);
    sl1p = map_shadow_page(map_mfn);

    /* Validate one entry at a time */
    while ( size )
    {
        smfn2 = smfn;
        guest_idx = guest_index(new_gp);
        shadow_idx = shadow_index(&smfn2, guest_idx);
        if ( mfn_x(smfn2) != mfn_x(map_mfn) )
        {
            /* We have moved to another page of the shadow */
            map_mfn = smfn2;
            unmap_shadow_page(sl1p);
            sl1p = map_shadow_page(map_mfn);
        }
        result |= validate_ge(v,
                              new_gp,
                              map_mfn,
                              &sl1p[shadow_idx]);
        size -= sizeof(guest_l1e_t);
        new_gp += sizeof(guest_l1e_t);
    }
    unmap_shadow_page(sl1p);
    return result;
}


int
sh_map_and_validate_gl4e(struct vcpu *v, mfn_t gl4mfn,
                          void *new_gl4p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 4
    return sh_map_and_validate(v, gl4mfn, new_gl4p, size, 
                                SH_type_l4_shadow, 
                                shadow_l4_index, 
                                validate_gl4e);
#else // ! GUEST_PAGING_LEVELS >= 4
    SHADOW_PRINTK("called in wrong paging mode!\n");
    BUG();
    return 0;
#endif 
}
    
int
sh_map_and_validate_gl3e(struct vcpu *v, mfn_t gl3mfn,
                          void *new_gl3p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 4
    return sh_map_and_validate(v, gl3mfn, new_gl3p, size, 
                                SH_type_l3_shadow, 
                                shadow_l3_index, 
                                validate_gl3e);
#else // ! GUEST_PAGING_LEVELS >= 4
    SHADOW_PRINTK("called in wrong paging mode!\n");
    BUG();
    return 0;
#endif
}

int
sh_map_and_validate_gl2e(struct vcpu *v, mfn_t gl2mfn,
                          void *new_gl2p, u32 size)
{
    return sh_map_and_validate(v, gl2mfn, new_gl2p, size, 
                                SH_type_l2_shadow, 
                                shadow_l2_index, 
                                validate_gl2e);
}

int
sh_map_and_validate_gl2he(struct vcpu *v, mfn_t gl2mfn,
                           void *new_gl2p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 3
    return sh_map_and_validate(v, gl2mfn, new_gl2p, size, 
                                SH_type_l2h_shadow, 
                                shadow_l2_index, 
                                validate_gl2e);
#else /* Non-PAE guests don't have different kinds of l2 table */
    SHADOW_PRINTK("called in wrong paging mode!\n");
    BUG();
    return 0;
#endif
}

int
sh_map_and_validate_gl1e(struct vcpu *v, mfn_t gl1mfn,
                          void *new_gl1p, u32 size)
{
    return sh_map_and_validate(v, gl1mfn, new_gl1p, size, 
                                SH_type_l1_shadow, 
                                shadow_l1_index, 
                                validate_gl1e);
}


/**************************************************************************/
/* Optimization: If we see two emulated writes of zeros to the same
 * page-table without another kind of page fault in between, we guess
 * that this is a batch of changes (for process destruction) and
 * unshadow the page so we don't take a pagefault on every entry.  This
 * should also make finding writeable mappings of pagetables much
 * easier. */

/* Look to see if this is the second emulated write in a row to this
 * page, and unshadow/unhook if it is */
static inline void check_for_early_unshadow(struct vcpu *v, mfn_t gmfn)
{
#if SHADOW_OPTIMIZATIONS & SHOPT_EARLY_UNSHADOW
    if ( v->arch.paging.shadow.last_emulated_mfn == mfn_x(gmfn) &&
         sh_mfn_is_a_page_table(gmfn) )
    {
        u32 flags = mfn_to_page(gmfn)->shadow_flags;
        if ( !(flags & (SHF_L2_32|SHF_L2_PAE|SHF_L2H_PAE|SHF_L4_64)) )
        {
            perfc_incrc(shadow_early_unshadow);
            sh_remove_shadows(v, gmfn, 1, 0 /* Fast, can fail to unshadow */ );
        } 
    }
    v->arch.paging.shadow.last_emulated_mfn = mfn_x(gmfn);
#endif
}

/* Stop counting towards early unshadows, as we've seen a real page fault */
static inline void reset_early_unshadow(struct vcpu *v)
{
#if SHADOW_OPTIMIZATIONS & SHOPT_EARLY_UNSHADOW
    v->arch.paging.shadow.last_emulated_mfn = INVALID_MFN;
#endif
}



/**************************************************************************/
/* Optimization: Prefetch multiple L1 entries.  This is called after we have 
 * demand-faulted a shadow l1e in the fault handler, to see if it's
 * worth fetching some more.
 */

#if SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH

/* XXX magic number */
#define PREFETCH_DISTANCE 32

static void sh_prefetch(struct vcpu *v, walk_t *gw, 
                        shadow_l1e_t *ptr_sl1e, mfn_t sl1mfn)
{
    int i, dist, mmio;
    gfn_t gfn;
    mfn_t gmfn;
    guest_l1e_t gl1e;
    shadow_l1e_t sl1e;
    u32 gflags;

    /* Prefetch no further than the end of the _shadow_ l1 MFN */
    dist = (PAGE_SIZE - ((unsigned long)ptr_sl1e & ~PAGE_MASK)) / sizeof sl1e;
    /* And no more than a maximum fetches-per-fault */
    if ( dist > PREFETCH_DISTANCE )
        dist = PREFETCH_DISTANCE;

    for ( i = 1; i < dist ; i++ ) 
    {
        /* No point in prefetching if there's already a shadow */
        if ( ptr_sl1e[i].l1 != 0 )
            break;

        if ( gw->l1e )
        {
            /* Normal guest page; grab the next guest entry */
            gl1e = gw->l1e[i];
            /* Not worth continuing if we hit an entry that will need another
             * fault for A/D-bit propagation anyway */
            gflags = guest_l1e_get_flags(gl1e);
            if ( (gflags & _PAGE_PRESENT) 
                 && (!(gflags & _PAGE_ACCESSED)
                     || ((gflags & _PAGE_RW) && !(gflags & _PAGE_DIRTY))) )
                break;
        } 
        else 
        {
            /* Fragmented superpage, unless we've been called wrongly */
            ASSERT(guest_l2e_get_flags(*gw->l2e) & _PAGE_PSE);
            /* Increment the l1e's GFN by the right number of guest pages */
            gl1e = guest_l1e_from_gfn(
                _gfn(gfn_x(guest_l1e_get_gfn(gw->eff_l1e)) + i), 
                guest_l1e_get_flags(gw->eff_l1e));
        }

        /* Look at the gfn that the l1e is pointing at */
        gfn = guest_l1e_get_gfn(gl1e);
        gmfn = vcpu_gfn_to_mfn(v, gfn);
        mmio = ( is_hvm_vcpu(v) 
                 && paging_vcpu_mode_translate(v) 
                 && mmio_space(gfn_to_paddr(gfn)) );

        /* Propagate the entry.  Safe to use a pointer to our local 
         * gl1e, since this is not a demand-fetch so there will be no 
         * write-back to the guest. */
        l1e_propagate_from_guest(v, &gl1e, _mfn(INVALID_MFN),
                                 gmfn, &sl1e, ft_prefetch, mmio);
        (void) shadow_set_l1e(v, ptr_sl1e + i, sl1e, sl1mfn);
    }
}

#endif /* SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH */


/**************************************************************************/
/* Entry points into the shadow code */

/* Called from pagefault handler in Xen, and from the HVM trap handlers
 * for pagefaults.  Returns 1 if this fault was an artefact of the
 * shadow code (and the guest should retry) or 0 if it is not (and the
 * fault should be handled elsewhere or passed to the guest). */

static int sh_page_fault(struct vcpu *v, 
                          unsigned long va, 
                          struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;
    walk_t gw;
    u32 accumulated_gflags;
    gfn_t gfn;
    mfn_t gmfn, sl1mfn=_mfn(0);
    shadow_l1e_t sl1e, *ptr_sl1e;
    paddr_t gpa;
    struct sh_emulate_ctxt emul_ctxt;
    struct x86_emulate_ops *emul_ops;
    int r, mmio;
    fetch_type_t ft = 0;

    SHADOW_PRINTK("d:v=%u:%u va=%#lx err=%u\n",
                   v->domain->domain_id, v->vcpu_id, va, regs->error_code);

    perfc_incrc(shadow_fault);
    //
    // XXX: Need to think about eventually mapping superpages directly in the
    //      shadow (when possible), as opposed to splintering them into a
    //      bunch of 4K maps.
    //

#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH) && SHADOW_PAGING_LEVELS > 2
    if ( (regs->error_code & PFEC_reserved_bit) )
    {
        /* The only reasons for reserved bits to be set in shadow entries 
         * are the two "magic" shadow_l1e entries. */
        if ( likely((__copy_from_user(&sl1e, 
                                      (sh_linear_l1_table(v) 
                                       + shadow_l1_linear_offset(va)),
                                      sizeof(sl1e)) == 0)
                    && sh_l1e_is_magic(sl1e)) )
        {
            if ( sh_l1e_is_gnp(sl1e) )
            {
                if ( likely(!is_hvm_domain(d) ||
                            paging_vcpu_mode_translate(v)) )
                { 
                    /* Not-present in a guest PT: pass to the guest as
                     * a not-present fault (by flipping two bits). */
                    ASSERT(regs->error_code & PFEC_page_present);
                    regs->error_code ^= (PFEC_reserved_bit|PFEC_page_present);
                    perfc_incrc(shadow_fault_fast_gnp);
                    SHADOW_PRINTK("fast path not-present\n");
                    return 0;
                }
                else 
                {
                    /* Not-present in the P2M: MMIO */
                    gpa = va;
                }
            }
            else
            {
                /* Magic MMIO marker: extract gfn for MMIO address */
                ASSERT(sh_l1e_is_mmio(sl1e));
                gpa = (((paddr_t)(gfn_x(sh_l1e_mmio_get_gfn(sl1e)))) 
                       << PAGE_SHIFT) 
                    | (va & ~PAGE_MASK);
            }
            perfc_incrc(shadow_fault_fast_mmio);
            SHADOW_PRINTK("fast path mmio %#"PRIpaddr"\n", gpa);
            reset_early_unshadow(v);
            handle_mmio(gpa);
            return EXCRET_fault_fixed;
        }
        else
        {
            /* This should be exceptionally rare: another vcpu has fixed
             * the tables between the fault and our reading the l1e. 
             * Retry and let the hardware give us the right fault next time. */
            perfc_incrc(shadow_fault_fast_fail);
            SHADOW_PRINTK("fast path false alarm!\n");            
            return EXCRET_fault_fixed;
        }
    }
#endif /* SHOPT_FAST_FAULT_PATH */

    /* Detect if this page fault happened while we were already in Xen
     * doing a shadow operation.  If that happens, the only thing we can
     * do is let Xen's normal fault handlers try to fix it.  In any case, 
     * a diagnostic trace of the fault will be more useful than 
     * a BUG() when we try to take the lock again. */
    if ( unlikely(shadow_locked_by_me(d)) )
    {
        SHADOW_ERROR("Recursive shadow fault: lock was taken by %s\n",
                     d->arch.paging.shadow.locker_function);
        return 0;
    }

    shadow_lock(d);
    
    shadow_audit_tables(v);
                   
    if ( guest_walk_tables(v, va, &gw, 1) != 0 )
    {
        SHADOW_PRINTK("malformed guest pagetable!");
        print_gw(&gw);
    }

    sh_audit_gw(v, &gw);

    // We do not look at the gw->l1e, as that will not exist for superpages.
    // Instead, we use the gw->eff_l1e...
    //
    // We need not check all the levels of the guest page table entries for
    // present vs not-present, as the eff_l1e will always be not present if
    // one of the higher level entries is not present.
    //
    if ( unlikely(!(guest_l1e_get_flags(gw.eff_l1e) & _PAGE_PRESENT)) )
    {
        if ( is_hvm_domain(d) && !paging_vcpu_mode_translate(v) )
        {
            /* Not present in p2m map, means this is mmio */
            gpa = va;
            goto mmio;
        }

        perfc_incrc(shadow_fault_bail_not_present);
        goto not_a_shadow_fault;
    }

    // All levels of the guest page table are now known to be present.
    accumulated_gflags = accumulate_guest_flags(v, &gw);

    // Check for attempts to access supervisor-only pages from user mode,
    // i.e. ring 3.  Such errors are not caused or dealt with by the shadow
    // code.
    //
    if ( (regs->error_code & PFEC_user_mode) &&
         !(accumulated_gflags & _PAGE_USER) )
    {
        /* illegal user-mode access to supervisor-only page */
        perfc_incrc(shadow_fault_bail_user_supervisor);
        goto not_a_shadow_fault;
    }

    // Was it a write fault?
    ft = ((regs->error_code & PFEC_write_access)
          ? ft_demand_write : ft_demand_read);
    if ( ft == ft_demand_write )
    {
        if ( unlikely(!(accumulated_gflags & _PAGE_RW)) )
        {
            perfc_incrc(shadow_fault_bail_ro_mapping);
            goto not_a_shadow_fault;
        }
    }
    else // must have been either an insn fetch or read fault
    {
        // Check for NX bit violations: attempts to execute code that is
        // marked "do not execute".  Such errors are not caused or dealt with
        // by the shadow code.
        //
        if ( regs->error_code & PFEC_insn_fetch )
        {
            if ( accumulated_gflags & _PAGE_NX_BIT )
            {
                /* NX prevented this code fetch */
                perfc_incrc(shadow_fault_bail_nx);
                goto not_a_shadow_fault;
            }
        }
    }

    /* What mfn is the guest trying to access? */
    gfn = guest_l1e_get_gfn(gw.eff_l1e);
    gmfn = vcpu_gfn_to_mfn(v, gfn);
    mmio = (is_hvm_domain(d)
            && paging_vcpu_mode_translate(v) 
            && mmio_space(gfn_to_paddr(gfn)));

    if ( !mmio && !mfn_valid(gmfn) )
    {
        perfc_incrc(shadow_fault_bail_bad_gfn);
        SHADOW_PRINTK("BAD gfn=%"SH_PRI_gfn" gmfn=%"PRI_mfn"\n", 
                      gfn_x(gfn), mfn_x(gmfn));
        goto not_a_shadow_fault;
    }

    /* Make sure there is enough free shadow memory to build a chain of
     * shadow tables: one SHADOW_MAX_ORDER chunk will always be enough
     * to allocate all we need.  (We never allocate a top-level shadow
     * on this path, only a 32b l1, pae l2+1 or 64b l3+2+1) */
    shadow_prealloc(d, SHADOW_MAX_ORDER);

    /* Acquire the shadow.  This must happen before we figure out the rights 
     * for the shadow entry, since we might promote a page here. */
    ptr_sl1e = shadow_get_and_create_l1e(v, &gw, &sl1mfn, ft);
    if ( unlikely(ptr_sl1e == NULL) ) 
    {
        /* Couldn't get the sl1e!  Since we know the guest entries
         * are OK, this can only have been caused by a failed
         * shadow_set_l*e(), which will have crashed the guest.  
         * Get out of the fault handler immediately. */
        ASSERT(test_bit(_DOMF_dying, &d->domain_flags));
        unmap_walk(v, &gw); 
        shadow_unlock(d);
        return 0;
    }

    /* Calculate the shadow entry and write it */
    l1e_propagate_from_guest(v, (gw.l1e) ? gw.l1e : &gw.eff_l1e, gw.l1mfn, 
                             gmfn, &sl1e, ft, mmio);
    r = shadow_set_l1e(v, ptr_sl1e, sl1e, sl1mfn);

#if SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH
    /* Prefetch some more shadow entries */
    sh_prefetch(v, &gw, ptr_sl1e, sl1mfn);
#endif

    /* Need to emulate accesses to page tables */
    if ( sh_mfn_is_a_page_table(gmfn) )
    {
        if ( ft == ft_demand_write )
        {
            perfc_incrc(shadow_fault_emulate_write);
            goto emulate;
        }
        else if ( shadow_mode_trap_reads(d) && ft == ft_demand_read )
        {
            perfc_incrc(shadow_fault_emulate_read);
            goto emulate;
        }
    }

    if ( mmio ) 
    {
        gpa = guest_walk_to_gpa(&gw);
        goto mmio;
    }

    perfc_incrc(shadow_fault_fixed);
    d->arch.paging.shadow.fault_count++;
    reset_early_unshadow(v);

 done:
    sh_audit_gw(v, &gw);
    unmap_walk(v, &gw);
    SHADOW_PRINTK("fixed\n");
    shadow_audit_tables(v);
    shadow_unlock(d);
    return EXCRET_fault_fixed;

 emulate:
    if ( !shadow_mode_refcounts(d) || !guest_mode(regs) )
        goto not_a_shadow_fault;

    if ( is_hvm_domain(d) )
    {
        /*
         * If we are in the middle of injecting an exception or interrupt then
         * we should not emulate: it is not the instruction at %eip that caused
         * the fault. Furthermore it is almost certainly the case the handler
         * stack is currently considered to be a page table, so we should
         * unshadow the faulting page before exiting.
         */
        if ( unlikely(hvm_event_injection_faulted(v)) )
        {
            gdprintk(XENLOG_DEBUG, "write to pagetable during event "
                     "injection: cr2=%#lx, mfn=%#lx\n", 
                     va, mfn_x(gmfn));
            sh_remove_shadows(v, gmfn, 0 /* thorough */, 1 /* must succeed */);
            goto done;
        }

        hvm_store_cpu_guest_regs(v, regs, NULL);
    }

    SHADOW_PRINTK("emulate: eip=%#lx esp=%#lx\n", 
                  (unsigned long)regs->eip, (unsigned long)regs->esp);

    emul_ops = shadow_init_emulation(&emul_ctxt, regs);

    /*
     * We do not emulate user writes. Instead we use them as a hint that the
     * page is no longer a page table. This behaviour differs from native, but
     * it seems very unlikely that any OS grants user access to page tables.
     */
    r = X86EMUL_UNHANDLEABLE;
    if ( !(regs->error_code & PFEC_user_mode) )
        r = x86_emulate(&emul_ctxt.ctxt, emul_ops);

    /*
     * NB. We do not unshadow on X86EMUL_EXCEPTION. It's not clear that it
     * would be a good unshadow hint. If we *do* decide to unshadow-on-fault
     * then it must be 'failable': we cannot require the unshadow to succeed.
     */
    if ( r == X86EMUL_UNHANDLEABLE )
    {
        SHADOW_PRINTK("emulator failure, unshadowing mfn %#lx\n", 
                       mfn_x(gmfn));
        perfc_incrc(shadow_fault_emulate_failed);
        /* If this is actually a page table, then we have a bug, and need 
         * to support more operations in the emulator.  More likely, 
         * though, this is a hint that this page should not be shadowed. */
        sh_remove_shadows(v, gmfn, 0 /* thorough */, 1 /* must succeed */);
    }

    /* Emulator has changed the user registers: write back */
    if ( is_hvm_domain(d) )
        hvm_load_cpu_guest_regs(v, regs);
    goto done;

 mmio:
    if ( !guest_mode(regs) )
        goto not_a_shadow_fault;
    perfc_incrc(shadow_fault_mmio);
    sh_audit_gw(v, &gw);
    unmap_walk(v, &gw);
    SHADOW_PRINTK("mmio %#"PRIpaddr"\n", gpa);
    shadow_audit_tables(v);
    reset_early_unshadow(v);
    shadow_unlock(d);
    handle_mmio(gpa);
    return EXCRET_fault_fixed;

 not_a_shadow_fault:
    sh_audit_gw(v, &gw);
    unmap_walk(v, &gw);
    SHADOW_PRINTK("not a shadow fault\n");
    shadow_audit_tables(v);
    reset_early_unshadow(v);
    shadow_unlock(d);
    return 0;
}


static int
sh_invlpg(struct vcpu *v, unsigned long va)
/* Called when the guest requests an invlpg.  Returns 1 if the invlpg
 * instruction should be issued on the hardware, or 0 if it's safe not
 * to do so. */
{
    shadow_l2e_t sl2e;
    
    perfc_incrc(shadow_invlpg);

    /* First check that we can safely read the shadow l2e.  SMP/PAE linux can
     * run as high as 6% of invlpg calls where we haven't shadowed the l2 
     * yet. */
#if SHADOW_PAGING_LEVELS == 4
    {
        shadow_l3e_t sl3e;
        if ( !(shadow_l4e_get_flags(
                   sh_linear_l4_table(v)[shadow_l4_linear_offset(va)])
               & _PAGE_PRESENT) )
            return 0;
        /* This must still be a copy-from-user because we don't have the
         * shadow lock, and the higher-level shadows might disappear
         * under our feet. */
        if ( __copy_from_user(&sl3e, (sh_linear_l3_table(v) 
                                      + shadow_l3_linear_offset(va)),
                              sizeof (sl3e)) != 0 )
        {
            perfc_incrc(shadow_invlpg_fault);
            return 0;
        }
        if ( (!shadow_l3e_get_flags(sl3e) & _PAGE_PRESENT) )
            return 0;
    }
#elif SHADOW_PAGING_LEVELS == 3
    if ( !(l3e_get_flags(v->arch.paging.shadow.l3table[shadow_l3_linear_offset(va)])
           & _PAGE_PRESENT) )
        // no need to flush anything if there's no SL2...
        return 0;
#endif

    /* This must still be a copy-from-user because we don't have the shadow
     * lock, and the higher-level shadows might disappear under our feet. */
    if ( __copy_from_user(&sl2e, 
                          sh_linear_l2_table(v) + shadow_l2_linear_offset(va),
                          sizeof (sl2e)) != 0 )
    {
        perfc_incrc(shadow_invlpg_fault);
        return 0;
    }

    // If there's nothing shadowed for this particular sl2e, then
    // there is no need to do an invlpg, either...
    //
    if ( !(shadow_l2e_get_flags(sl2e) & _PAGE_PRESENT) )
        return 0;

    // Check to see if the SL2 is a splintered superpage...
    // If so, then we'll need to flush the entire TLB (because that's
    // easier than invalidating all of the individual 4K pages).
    //
    if ( mfn_to_shadow_page(shadow_l2e_get_mfn(sl2e))->type
         == SH_type_fl1_shadow )
    {
        local_flush_tlb();
        return 0;
    }

    return 1;
}

static unsigned long
sh_gva_to_gfn(struct vcpu *v, unsigned long va)
/* Called to translate a guest virtual address to what the *guest*
 * pagetables would map it to. */
{
    walk_t gw;
    gfn_t gfn;

    guest_walk_tables(v, va, &gw, 0);
    gfn = guest_walk_to_gfn(&gw);
    unmap_walk(v, &gw);

    return gfn_x(gfn);
}


static inline void
sh_update_linear_entries(struct vcpu *v)
/* Sync up all the linear mappings for this vcpu's pagetables */
{
    struct domain *d = v->domain;

    /* Linear pagetables in PV guests
     * ------------------------------
     *
     * Guest linear pagetables, which map the guest pages, are at
     * LINEAR_PT_VIRT_START.  Shadow linear pagetables, which map the
     * shadows, are at SH_LINEAR_PT_VIRT_START.  Most of the time these
     * are set up at shadow creation time, but (of course!) the PAE case
     * is subtler.  Normal linear mappings are made by having an entry
     * in the top-level table that points to itself (shadow linear) or
     * to the guest top-level table (guest linear).  For PAE, to set up
     * a linear map requires us to copy the four top-level entries into 
     * level-2 entries.  That means that every time we change a PAE l3e,
     * we need to reflect the change into the copy.
     *
     * Linear pagetables in HVM guests
     * -------------------------------
     *
     * For HVM guests, the linear pagetables are installed in the monitor
     * tables (since we can't put them in the shadow).  Shadow linear
     * pagetables, which map the shadows, are at SH_LINEAR_PT_VIRT_START,
     * and we use the linear pagetable slot at LINEAR_PT_VIRT_START for 
     * a linear pagetable of the monitor tables themselves.  We have 
     * the same issue of having to re-copy PAE l3 entries whevever we use
     * PAE shadows. 
     *
     * Because HVM guests run on the same monitor tables regardless of the 
     * shadow tables in use, the linear mapping of the shadow tables has to 
     * be updated every time v->arch.shadow_table changes. 
     */

    /* Don't try to update the monitor table if it doesn't exist */
    if ( shadow_mode_external(d) 
         && pagetable_get_pfn(v->arch.monitor_table) == 0 ) 
        return;

#if (CONFIG_PAGING_LEVELS == 4) && (SHADOW_PAGING_LEVELS == 4)
    
    /* For PV, one l4e points at the guest l4, one points at the shadow
     * l4.  No maintenance required. 
     * For HVM, just need to update the l4e that points to the shadow l4. */

    if ( shadow_mode_external(d) )
    {
        /* Use the linear map if we can; otherwise make a new mapping */
        if ( v == current ) 
        {
            __linear_l4_table[l4_linear_offset(SH_LINEAR_PT_VIRT_START)] = 
                l4e_from_pfn(pagetable_get_pfn(v->arch.shadow_table[0]),
                             __PAGE_HYPERVISOR);
        } 
        else
        { 
            l4_pgentry_t *ml4e;
            ml4e = sh_map_domain_page(pagetable_get_mfn(v->arch.monitor_table));
            ml4e[l4_table_offset(SH_LINEAR_PT_VIRT_START)] = 
                l4e_from_pfn(pagetable_get_pfn(v->arch.shadow_table[0]),
                             __PAGE_HYPERVISOR);
            sh_unmap_domain_page(ml4e);
        }
    }

#elif (CONFIG_PAGING_LEVELS == 4) && (SHADOW_PAGING_LEVELS == 3)

    /* PV: XXX
     *
     * HVM: To give ourselves a linear map of the  shadows, we need to
     * extend a PAE shadow to 4 levels.  We do this by  having a monitor
     * l3 in slot 0 of the monitor l4 table, and  copying the PAE l3
     * entries into it.  Then, by having the monitor l4e for shadow
     * pagetables also point to the monitor l4, we can use it to access
     * the shadows.
     */

    if ( shadow_mode_external(d) )
    {
        /* Install copies of the shadow l3es into the monitor l3 table.
         * The monitor l3 table is hooked into slot 0 of the monitor
         * l4 table, so we use l3 linear indices 0 to 3 */
        shadow_l3e_t *sl3e;
        l3_pgentry_t *ml3e;
        mfn_t l3mfn;
        int i;

        /* Use linear mappings if we can; otherwise make new mappings */
        if ( v == current ) 
        {
            ml3e = __linear_l3_table;
            l3mfn = _mfn(l4e_get_pfn(__linear_l4_table[0]));
        }
        else 
        {   
            l4_pgentry_t *ml4e;
            ml4e = sh_map_domain_page(pagetable_get_mfn(v->arch.monitor_table));
            ASSERT(l4e_get_flags(ml4e[0]) & _PAGE_PRESENT);
            l3mfn = _mfn(l4e_get_pfn(ml4e[0]));
            ml3e = sh_map_domain_page(l3mfn);
            sh_unmap_domain_page(ml4e);
        }

        /* Shadow l3 tables are made up by sh_update_cr3 */
        sl3e = v->arch.paging.shadow.l3table;

        for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
        {
            ml3e[i] = 
                (shadow_l3e_get_flags(sl3e[i]) & _PAGE_PRESENT) 
                ? l3e_from_pfn(mfn_x(shadow_l3e_get_mfn(sl3e[i])), 
                               __PAGE_HYPERVISOR) 
                : l3e_empty();
        }

        if ( v != current ) 
            sh_unmap_domain_page(ml3e);
    }
    else
        domain_crash(d); /* XXX */

#elif CONFIG_PAGING_LEVELS == 3

    /* PV: need to copy the guest's l3 entries into the guest-linear-map l2
     * entries in the shadow, and the shadow's l3 entries into the 
     * shadow-linear-map l2 entries in the shadow.  This is safe to do 
     * because Xen does not let guests share high-slot l2 tables between l3s,
     * so we know we're not treading on anyone's toes. 
     *
     * HVM: need to copy the shadow's l3 entries into the
     * shadow-linear-map l2 entries in the monitor table.  This is safe
     * because we have one monitor table for each vcpu.  The monitor's
     * own l3es don't need to be copied because they never change.  
     * XXX That might change if we start stuffing things into the rest
     * of the monitor's virtual address space. 
     */ 
    {
        l2_pgentry_t *l2e, new_l2e;
        shadow_l3e_t *guest_l3e = NULL, *shadow_l3e;
        int i;
        int unmap_l2e = 0;

#if GUEST_PAGING_LEVELS == 2

        /* Shadow l3 tables were built by sh_update_cr3 */
        BUG_ON(!shadow_mode_external(d)); /* PV 2-on-3 is unsupported */
        shadow_l3e = (shadow_l3e_t *)&v->arch.paging.shadow.l3table;
        
#else /* GUEST_PAGING_LEVELS == 3 */
        
        shadow_l3e = (shadow_l3e_t *)&v->arch.paging.shadow.l3table;
        guest_l3e = (guest_l3e_t *)&v->arch.paging.shadow.gl3e;

#endif /* GUEST_PAGING_LEVELS */
        
        /* Choose where to write the entries, using linear maps if possible */
        if ( shadow_mode_external(d) )
        {
            if ( v == current )
            {
                /* From the monitor tables, it's safe to use linear maps
                 * to update monitor l2s */
                l2e = __linear_l2_table + (3 * L2_PAGETABLE_ENTRIES);
            }
            else
            {
                /* Map the monitor table's high l2 */
                l3_pgentry_t *l3e;
                l3e = sh_map_domain_page(
                    pagetable_get_mfn(v->arch.monitor_table));
                ASSERT(l3e_get_flags(l3e[3]) & _PAGE_PRESENT);
                l2e = sh_map_domain_page(_mfn(l3e_get_pfn(l3e[3])));
                unmap_l2e = 1;
                sh_unmap_domain_page(l3e);
            }
        }
        else 
        {
            /* Map the shadow table's high l2 */
            ASSERT(shadow_l3e_get_flags(shadow_l3e[3]) & _PAGE_PRESENT);
            l2e = sh_map_domain_page(shadow_l3e_get_mfn(shadow_l3e[3]));
            unmap_l2e = 1;
        }
        
        /* Write linear mapping of guest (only in PV, and only when 
         * not translated). */
        if ( !shadow_mode_translate(d) )
        {
            for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
            {
                new_l2e = 
                    ((shadow_l3e_get_flags(guest_l3e[i]) & _PAGE_PRESENT)
                     ? l2e_from_pfn(mfn_x(shadow_l3e_get_mfn(guest_l3e[i])),
                                    __PAGE_HYPERVISOR) 
                     : l2e_empty());
                safe_write_entry(
                    &l2e[l2_table_offset(LINEAR_PT_VIRT_START) + i],
                    &new_l2e);
            }
        }
        
        /* Write linear mapping of shadow. */
        for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
        {
            new_l2e = (shadow_l3e_get_flags(shadow_l3e[i]) & _PAGE_PRESENT) 
                ? l2e_from_pfn(mfn_x(shadow_l3e_get_mfn(shadow_l3e[i])),
                               __PAGE_HYPERVISOR) 
                : l2e_empty();
            safe_write_entry(
                &l2e[l2_table_offset(SH_LINEAR_PT_VIRT_START) + i],
                &new_l2e);
        }
        
        if ( unmap_l2e )
            sh_unmap_domain_page(l2e);
    }

#elif CONFIG_PAGING_LEVELS == 2

    /* For PV, one l2e points at the guest l2, one points at the shadow
     * l2. No maintenance required. 
     * For HVM, just need to update the l2e that points to the shadow l2. */

    if ( shadow_mode_external(d) )
    {
        /* Use the linear map if we can; otherwise make a new mapping */
        if ( v == current ) 
        {
            __linear_l2_table[l2_linear_offset(SH_LINEAR_PT_VIRT_START)] = 
                l2e_from_pfn(pagetable_get_pfn(v->arch.shadow_table[0]),
                             __PAGE_HYPERVISOR);
        } 
        else
        { 
            l2_pgentry_t *ml2e;
            ml2e = sh_map_domain_page(pagetable_get_mfn(v->arch.monitor_table));
            ml2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] = 
                l2e_from_pfn(pagetable_get_pfn(v->arch.shadow_table[0]),
                             __PAGE_HYPERVISOR);
            sh_unmap_domain_page(ml2e);
        }
    }

#else
#error this should not happen
#endif
}


/* Removes vcpu->arch.paging.shadow.guest_vtable and vcpu->arch.shadow_table[].
 * Does all appropriate management/bookkeeping/refcounting/etc...
 */
static void
sh_detach_old_tables(struct vcpu *v)
{
    mfn_t smfn;
    int i = 0;

    ////
    //// vcpu->arch.paging.shadow.guest_vtable
    ////

#if GUEST_PAGING_LEVELS == 3
    /* PAE guests don't have a mapping of the guest top-level table */
    ASSERT(v->arch.paging.shadow.guest_vtable == NULL);
#else
    if ( v->arch.paging.shadow.guest_vtable )
    {
        struct domain *d = v->domain;
        if ( shadow_mode_external(d) || shadow_mode_translate(d) )
            sh_unmap_domain_page_global(v->arch.paging.shadow.guest_vtable);
        v->arch.paging.shadow.guest_vtable = NULL;
    }
#endif


    ////
    //// vcpu->arch.shadow_table[]
    ////

#if GUEST_PAGING_LEVELS == 3
    /* PAE guests have four shadow_table entries */
    for ( i = 0 ; i < 4 ; i++ )
#endif
    {
        smfn = pagetable_get_mfn(v->arch.shadow_table[i]);
        if ( mfn_x(smfn) )
            sh_put_ref(v, smfn, 0);
        v->arch.shadow_table[i] = pagetable_null();
    }
}

/* Set up the top-level shadow and install it in slot 'slot' of shadow_table */
static void
sh_set_toplevel_shadow(struct vcpu *v, 
                       int slot,
                       mfn_t gmfn, 
                       unsigned int root_type) 
{
    mfn_t smfn;
    pagetable_t old_entry, new_entry;

    struct domain *d = v->domain;
    
    /* Remember the old contents of this slot */
    old_entry = v->arch.shadow_table[slot];

    /* Now figure out the new contents: is this a valid guest MFN? */
    if ( !mfn_valid(gmfn) )
    {
        new_entry = pagetable_null();
        goto install_new_entry;
    }

    /* Guest mfn is valid: shadow it and install the shadow */
    smfn = get_shadow_status(v, gmfn, root_type);
    if ( !mfn_valid(smfn) )
    {
        /* Make sure there's enough free shadow memory. */
        shadow_prealloc(d, SHADOW_MAX_ORDER); 
        /* Shadow the page. */
        smfn = sh_make_shadow(v, gmfn, root_type);
    }
    ASSERT(mfn_valid(smfn));
    
#if SHADOW_OPTIMIZATIONS & SHOPT_EARLY_UNSHADOW
    /* Once again OK to unhook entries from this table if we see fork/exit */
#if CONFIG_PAGING_LEVELS == 4
    if ( IS_COMPAT(d) )
        ASSERT(!sh_mfn_is_a_page_table(gmfn));
    else
#endif
        ASSERT(sh_mfn_is_a_page_table(gmfn));
    mfn_to_page(gmfn)->shadow_flags &= ~SHF_unhooked_mappings;
#endif

    /* Pin the shadow and put it (back) on the list of top-level shadows */
    if ( sh_pin(v, smfn) == 0 )
    {
        SHADOW_ERROR("can't pin %#lx as toplevel shadow\n", mfn_x(smfn));
        domain_crash(v->domain);
    }

    /* Take a ref to this page: it will be released in sh_detach_old_tables()
     * or the next call to set_toplevel_shadow() */
    if ( !sh_get_ref(v, smfn, 0) )
    {
        SHADOW_ERROR("can't install %#lx as toplevel shadow\n", mfn_x(smfn));
        domain_crash(v->domain);
    }

    new_entry = pagetable_from_mfn(smfn);

 install_new_entry:
    /* Done.  Install it */
    SHADOW_PRINTK("%u/%u [%u] gmfn %#"PRI_mfn" smfn %#"PRI_mfn"\n",
                  GUEST_PAGING_LEVELS, SHADOW_PAGING_LEVELS, slot,
                  mfn_x(gmfn), mfn_x(pagetable_get_mfn(new_entry)));
    v->arch.shadow_table[slot] = new_entry;

    /* Decrement the refcount of the old contents of this slot */
    if ( !pagetable_is_null(old_entry) )
        sh_put_ref(v, pagetable_get_mfn(old_entry), 0);
}


static void
sh_update_cr3(struct vcpu *v, int do_locking)
/* Updates vcpu->arch.cr3 after the guest has changed CR3.
 * Paravirtual guests should set v->arch.guest_table (and guest_table_user,
 * if appropriate).
 * HVM guests should also make sure hvm_get_guest_cntl_reg(v, 3) works;
 * this function will call hvm_update_guest_cr3() to tell them where the 
 * shadow tables are.
 * If do_locking != 0, assume we are being called from outside the 
 * shadow code, and must take and release the shadow lock; otherwise 
 * that is the caller's responsibility.
 */
{
    struct domain *d = v->domain;
    mfn_t gmfn;
#if GUEST_PAGING_LEVELS == 3
    guest_l3e_t *gl3e;
    u32 guest_idx=0;
    int i;
#endif

    /* Don't do anything on an uninitialised vcpu */
    if ( !is_hvm_domain(d) && !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
    {
        ASSERT(v->arch.cr3 == 0);
        return;
    }

    if ( do_locking ) shadow_lock(v->domain);

    ASSERT(shadow_locked_by_me(v->domain));
    ASSERT(v->arch.paging.mode);

    ////
    //// vcpu->arch.guest_table is already set
    ////
    
#ifndef NDEBUG 
    /* Double-check that the HVM code has sent us a sane guest_table */
    if ( is_hvm_domain(d) )
    {
        gfn_t gfn;

        ASSERT(shadow_mode_external(d));

        // Is paging enabled on this vcpu?
        if ( paging_vcpu_mode_translate(v) )
        {
            gfn = _gfn(paddr_to_pfn(hvm_get_guest_ctrl_reg(v, 3)));
            gmfn = vcpu_gfn_to_mfn(v, gfn);
            ASSERT(mfn_valid(gmfn));
            ASSERT(pagetable_get_pfn(v->arch.guest_table) == mfn_x(gmfn));
        } 
        else 
        {
            /* Paging disabled: guest_table points at (part of) p2m */
#if SHADOW_PAGING_LEVELS != 3 /* in 3-on-4, guest-table is in slot 0 of p2m */
            /* For everything else, they sould be the same */
            ASSERT(v->arch.guest_table.pfn == d->arch.phys_table.pfn);
#endif
        }
    }
#endif

    SHADOW_PRINTK("d=%u v=%u guest_table=%05lx\n",
                   d->domain_id, v->vcpu_id, 
                   (unsigned long)pagetable_get_pfn(v->arch.guest_table));

#if GUEST_PAGING_LEVELS == 4
    if ( !(v->arch.flags & TF_kernel_mode) && !IS_COMPAT(v->domain) )
        gmfn = pagetable_get_mfn(v->arch.guest_table_user);
    else
#endif
        gmfn = pagetable_get_mfn(v->arch.guest_table);


    ////
    //// vcpu->arch.paging.shadow.guest_vtable
    ////
#if GUEST_PAGING_LEVELS == 4
    if ( shadow_mode_external(d) || shadow_mode_translate(d) )
    {
        if ( v->arch.paging.shadow.guest_vtable )
            sh_unmap_domain_page_global(v->arch.paging.shadow.guest_vtable);
        v->arch.paging.shadow.guest_vtable = sh_map_domain_page_global(gmfn);
    }
    else
        v->arch.paging.shadow.guest_vtable = __linear_l4_table;
#elif GUEST_PAGING_LEVELS == 3
     /* On PAE guests we don't use a mapping of the guest's own top-level
      * table.  We cache the current state of that table and shadow that,
      * until the next CR3 write makes us refresh our cache. */
     ASSERT(v->arch.paging.shadow.guest_vtable == NULL);
 
     if ( shadow_mode_external(d) && paging_vcpu_mode_translate(v) ) 
         /* Paging enabled: find where in the page the l3 table is */
         guest_idx = guest_index((void *)hvm_get_guest_ctrl_reg(v, 3));
    else
        /* Paging disabled or PV: l3 is at the start of a page */ 
        guest_idx = 0; 
     
     // Ignore the low 2 bits of guest_idx -- they are really just
     // cache control.
     guest_idx &= ~3;
     
     gl3e = ((guest_l3e_t *)sh_map_domain_page(gmfn)) + guest_idx;
     for ( i = 0; i < 4 ; i++ )
         v->arch.paging.shadow.gl3e[i] = gl3e[i];
     sh_unmap_domain_page(gl3e);
#elif GUEST_PAGING_LEVELS == 2
    if ( shadow_mode_external(d) || shadow_mode_translate(d) )
    {
        if ( v->arch.paging.shadow.guest_vtable )
            sh_unmap_domain_page_global(v->arch.paging.shadow.guest_vtable);
        v->arch.paging.shadow.guest_vtable = sh_map_domain_page_global(gmfn);
    }
    else
        v->arch.paging.shadow.guest_vtable = __linear_l2_table;
#else
#error this should never happen
#endif

#if 0
    printk("%s %s %d gmfn=%05lx shadow.guest_vtable=%p\n",
           __func__, __FILE__, __LINE__, gmfn, v->arch.paging.shadow.guest_vtable);
#endif

    ////
    //// vcpu->arch.shadow_table[]
    ////

    /* We revoke write access to the new guest toplevel page(s) before we
     * replace the old shadow pagetable(s), so that we can safely use the 
     * (old) shadow linear maps in the writeable mapping heuristics. */
#if GUEST_PAGING_LEVELS == 2
    if ( sh_remove_write_access(v, gmfn, 2, 0) != 0 )
        flush_tlb_mask(v->domain->domain_dirty_cpumask); 
    sh_set_toplevel_shadow(v, 0, gmfn, SH_type_l2_shadow);
#elif GUEST_PAGING_LEVELS == 3
    /* PAE guests have four shadow_table entries, based on the 
     * current values of the guest's four l3es. */
    {
        int flush = 0;
        gfn_t gl2gfn;
        mfn_t gl2mfn;
        guest_l3e_t *gl3e = (guest_l3e_t*)&v->arch.paging.shadow.gl3e;
        /* First, make all four entries read-only. */
        for ( i = 0; i < 4; i++ )
        {
            if ( guest_l3e_get_flags(gl3e[i]) & _PAGE_PRESENT )
            {
                gl2gfn = guest_l3e_get_gfn(gl3e[i]);
                gl2mfn = vcpu_gfn_to_mfn(v, gl2gfn);
                flush |= sh_remove_write_access(v, gl2mfn, 2, 0); 
            }
        }
        if ( flush ) 
            flush_tlb_mask(v->domain->domain_dirty_cpumask);
        /* Now install the new shadows. */
        for ( i = 0; i < 4; i++ ) 
        {
            if ( guest_l3e_get_flags(gl3e[i]) & _PAGE_PRESENT )
            {
                gl2gfn = guest_l3e_get_gfn(gl3e[i]);
                gl2mfn = vcpu_gfn_to_mfn(v, gl2gfn);
                sh_set_toplevel_shadow(v, i, gl2mfn, (i == 3) 
                                       ? SH_type_l2h_shadow 
                                       : SH_type_l2_shadow);
            }
            else
                /* The guest is not present: clear out the shadow. */
                sh_set_toplevel_shadow(v, i, _mfn(INVALID_MFN), 0); 
        }
    }
#elif GUEST_PAGING_LEVELS == 4
    if ( sh_remove_write_access(v, gmfn, 4, 0) != 0 )
        flush_tlb_mask(v->domain->domain_dirty_cpumask);
    sh_set_toplevel_shadow(v, 0, gmfn, SH_type_l4_shadow);
#else
#error This should never happen 
#endif

#if (CONFIG_PAGING_LEVELS == 3) && (GUEST_PAGING_LEVELS == 3)
#endif

    /// 
    /// v->arch.paging.shadow.l3table
    ///
#if SHADOW_PAGING_LEVELS == 3
        {
            mfn_t smfn;
            int i;
            for ( i = 0; i < 4; i++ )
            {
#if GUEST_PAGING_LEVELS == 2
                /* 2-on-3: make a PAE l3 that points at the four-page l2 */
                smfn = _mfn(pagetable_get_pfn(v->arch.shadow_table[0]) + i);
#else
                /* 3-on-3: make a PAE l3 that points at the four l2 pages */
                smfn = pagetable_get_mfn(v->arch.shadow_table[i]);
#endif
                v->arch.paging.shadow.l3table[i] = 
                    (mfn_x(smfn) == 0) 
                    ? shadow_l3e_empty()
                    : shadow_l3e_from_mfn(smfn, _PAGE_PRESENT);
            }
        }
#endif /* SHADOW_PAGING_LEVELS == 3 */


    ///
    /// v->arch.cr3
    ///
    if ( shadow_mode_external(d) )
    {
        make_cr3(v, pagetable_get_pfn(v->arch.monitor_table));
    }
    else // not shadow_mode_external...
    {
        /* We don't support PV except guest == shadow == config levels */
        BUG_ON(GUEST_PAGING_LEVELS != SHADOW_PAGING_LEVELS);
#if SHADOW_PAGING_LEVELS == 3
        /* 2-on-3 or 3-on-3: Use the PAE shadow l3 table we just fabricated.
         * Don't use make_cr3 because (a) we know it's below 4GB, and
         * (b) it's not necessarily page-aligned, and make_cr3 takes a pfn */
        ASSERT(virt_to_maddr(&v->arch.paging.shadow.l3table) <= 0xffffffe0ULL);
        v->arch.cr3 = virt_to_maddr(&v->arch.paging.shadow.l3table);
#else
        /* 2-on-2 or 4-on-4: Just use the shadow top-level directly */
        make_cr3(v, pagetable_get_pfn(v->arch.shadow_table[0]));
#endif
    }


    ///
    /// v->arch.hvm_vcpu.hw_cr3
    ///
    if ( shadow_mode_external(d) )
    {
        ASSERT(is_hvm_domain(d));
#if SHADOW_PAGING_LEVELS == 3
        /* 2-on-3 or 3-on-3: Use the PAE shadow l3 table we just fabricated */
        hvm_update_guest_cr3(v, virt_to_maddr(&v->arch.paging.shadow.l3table));
#else
        /* 2-on-2 or 4-on-4: Just use the shadow top-level directly */
        hvm_update_guest_cr3(v, pagetable_get_paddr(v->arch.shadow_table[0]));
#endif
    }

    /* Fix up the linear pagetable mappings */
    sh_update_linear_entries(v);

    /* Release the lock, if we took it (otherwise it's the caller's problem) */
    if ( do_locking ) shadow_unlock(v->domain);
}


/**************************************************************************/
/* Functions to revoke guest rights */

#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
static int sh_guess_wrmap(struct vcpu *v, unsigned long vaddr, mfn_t gmfn)
/* Look up this vaddr in the current shadow and see if it's a writeable
 * mapping of this gmfn.  If so, remove it.  Returns 1 if it worked. */
{
    shadow_l1e_t sl1e, *sl1p;
    shadow_l2e_t *sl2p;
#if SHADOW_PAGING_LEVELS >= 3
    shadow_l3e_t *sl3p;
#if SHADOW_PAGING_LEVELS >= 4
    shadow_l4e_t *sl4p;
#endif
#endif
    mfn_t sl1mfn;
    int r;

    /* Carefully look in the shadow linear map for the l1e we expect */
#if SHADOW_PAGING_LEVELS >= 4
    sl4p = sh_linear_l4_table(v) + shadow_l4_linear_offset(vaddr);
    if ( !(shadow_l4e_get_flags(*sl4p) & _PAGE_PRESENT) )
        return 0;
    sl3p = sh_linear_l3_table(v) + shadow_l3_linear_offset(vaddr);
    if ( !(shadow_l3e_get_flags(*sl3p) & _PAGE_PRESENT) )
        return 0;
#elif SHADOW_PAGING_LEVELS == 3
    sl3p = ((shadow_l3e_t *) v->arch.paging.shadow.l3table) 
        + shadow_l3_linear_offset(vaddr);
    if ( !(shadow_l3e_get_flags(*sl3p) & _PAGE_PRESENT) )
        return 0;
#endif
    sl2p = sh_linear_l2_table(v) + shadow_l2_linear_offset(vaddr);
    if ( !(shadow_l2e_get_flags(*sl2p) & _PAGE_PRESENT) )
        return 0;
    sl1p = sh_linear_l1_table(v) + shadow_l1_linear_offset(vaddr);
    sl1e = *sl1p;
    if ( ((shadow_l1e_get_flags(sl1e) & (_PAGE_PRESENT|_PAGE_RW))
          != (_PAGE_PRESENT|_PAGE_RW))
         || (mfn_x(shadow_l1e_get_mfn(sl1e)) != mfn_x(gmfn)) )
        return 0;

    /* Found it!  Need to remove its write permissions. */
    sl1mfn = shadow_l2e_get_mfn(*sl2p);
    sl1e = shadow_l1e_remove_flags(sl1e, _PAGE_RW);
    r = shadow_set_l1e(v, sl1p, sl1e, sl1mfn);
    ASSERT( !(r & SHADOW_SET_ERROR) );
    return 1;
}
#endif

int sh_rm_write_access_from_l1(struct vcpu *v, mfn_t sl1mfn,
                               mfn_t readonly_mfn)
/* Excises all writeable mappings to readonly_mfn from this l1 shadow table */
{
    shadow_l1e_t *sl1e;
    int done = 0;
    int flags;
    mfn_t base_sl1mfn = sl1mfn; /* Because sl1mfn changes in the foreach */
    
    SHADOW_FOREACH_L1E(sl1mfn, sl1e, 0, done, 
    {
        flags = shadow_l1e_get_flags(*sl1e);
        if ( (flags & _PAGE_PRESENT) 
             && (flags & _PAGE_RW) 
             && (mfn_x(shadow_l1e_get_mfn(*sl1e)) == mfn_x(readonly_mfn)) )
        {
            shadow_l1e_t ro_sl1e = shadow_l1e_remove_flags(*sl1e, _PAGE_RW);
            (void) shadow_set_l1e(v, sl1e, ro_sl1e, sl1mfn);
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC 
            /* Remember the last shadow that we shot a writeable mapping in */
            v->arch.paging.shadow.last_writeable_pte_smfn = mfn_x(base_sl1mfn);
#endif
            if ( (mfn_to_page(readonly_mfn)->u.inuse.type_info
                  & PGT_count_mask) == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}


int sh_rm_mappings_from_l1(struct vcpu *v, mfn_t sl1mfn, mfn_t target_mfn)
/* Excises all mappings to guest frame from this shadow l1 table */
{
    shadow_l1e_t *sl1e;
    int done = 0;
    int flags;
    
    SHADOW_FOREACH_L1E(sl1mfn, sl1e, 0, done, 
    {
        flags = shadow_l1e_get_flags(*sl1e);
        if ( (flags & _PAGE_PRESENT) 
             && (mfn_x(shadow_l1e_get_mfn(*sl1e)) == mfn_x(target_mfn)) )
        {
            (void) shadow_set_l1e(v, sl1e, shadow_l1e_empty(), sl1mfn);
            if ( (mfn_to_page(target_mfn)->count_info & PGC_count_mask) == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

/**************************************************************************/
/* Functions to excise all pointers to shadows from higher-level shadows. */

void sh_clear_shadow_entry(struct vcpu *v, void *ep, mfn_t smfn)
/* Blank out a single shadow entry */
{
    switch ( mfn_to_shadow_page(smfn)->type )
    {
    case SH_type_l1_shadow:
        (void) shadow_set_l1e(v, ep, shadow_l1e_empty(), smfn); break;
    case SH_type_l2_shadow:
#if GUEST_PAGING_LEVELS >= 3
    case SH_type_l2h_shadow:
#endif
        (void) shadow_set_l2e(v, ep, shadow_l2e_empty(), smfn); break;
#if GUEST_PAGING_LEVELS >= 4
    case SH_type_l3_shadow:
        (void) shadow_set_l3e(v, ep, shadow_l3e_empty(), smfn); break;
    case SH_type_l4_shadow:
        (void) shadow_set_l4e(v, ep, shadow_l4e_empty(), smfn); break;
#endif
    default: BUG(); /* Called with the wrong kind of shadow. */
    }
}

int sh_remove_l1_shadow(struct vcpu *v, mfn_t sl2mfn, mfn_t sl1mfn)
/* Remove all mappings of this l1 shadow from this l2 shadow */
{
    shadow_l2e_t *sl2e;
    int done = 0;
    int flags;
    
    SHADOW_FOREACH_L2E(sl2mfn, sl2e, 0, done, v->domain, 
    {
        flags = shadow_l2e_get_flags(*sl2e);
        if ( (flags & _PAGE_PRESENT) 
             && (mfn_x(shadow_l2e_get_mfn(*sl2e)) == mfn_x(sl1mfn)) )
        {
            (void) shadow_set_l2e(v, sl2e, shadow_l2e_empty(), sl2mfn);
            if ( mfn_to_shadow_page(sl1mfn)->type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

#if GUEST_PAGING_LEVELS >= 4
int sh_remove_l2_shadow(struct vcpu *v, mfn_t sl3mfn, mfn_t sl2mfn)
/* Remove all mappings of this l2 shadow from this l3 shadow */
{
    shadow_l3e_t *sl3e;
    int done = 0;
    int flags;
    
    SHADOW_FOREACH_L3E(sl3mfn, sl3e, 0, done, 
    {
        flags = shadow_l3e_get_flags(*sl3e);
        if ( (flags & _PAGE_PRESENT) 
             && (mfn_x(shadow_l3e_get_mfn(*sl3e)) == mfn_x(sl2mfn)) )
        {
            (void) shadow_set_l3e(v, sl3e, shadow_l3e_empty(), sl3mfn);
            if ( mfn_to_shadow_page(sl2mfn)->type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

int sh_remove_l3_shadow(struct vcpu *v, mfn_t sl4mfn, mfn_t sl3mfn)
/* Remove all mappings of this l3 shadow from this l4 shadow */
{
    shadow_l4e_t *sl4e;
    int done = 0;
    int flags;
    
    SHADOW_FOREACH_L4E(sl4mfn, sl4e, 0, done, v->domain,
    {
        flags = shadow_l4e_get_flags(*sl4e);
        if ( (flags & _PAGE_PRESENT) 
             && (mfn_x(shadow_l4e_get_mfn(*sl4e)) == mfn_x(sl3mfn)) )
        {
            (void) shadow_set_l4e(v, sl4e, shadow_l4e_empty(), sl4mfn);
            if ( mfn_to_shadow_page(sl3mfn)->type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}
#endif /* 64bit guest */ 

/**************************************************************************/
/* Handling HVM guest writes to pagetables  */

/* Check that the user is allowed to perform this write. 
 * Returns a mapped pointer to write to, and the mfn it's on,
 * or NULL for error. */
static inline void * emulate_map_dest(struct vcpu *v,
                                      unsigned long vaddr,
                                      struct sh_emulate_ctxt *sh_ctxt,
                                      mfn_t *mfnp)
{
    walk_t gw;
    u32 flags, errcode;
    gfn_t gfn;
    mfn_t mfn;

    guest_walk_tables(v, vaddr, &gw, 1);
    flags = accumulate_guest_flags(v, &gw);
    gfn = guest_l1e_get_gfn(gw.eff_l1e);
    mfn = vcpu_gfn_to_mfn(v, gfn);
    sh_audit_gw(v, &gw);
    unmap_walk(v, &gw);

    if ( !(flags & _PAGE_PRESENT) )
    {
        errcode = 0;
        goto page_fault;
    }

    if ( !(flags & _PAGE_RW) ||
         (!(flags & _PAGE_USER) && ring_3(sh_ctxt->ctxt.regs)) )
    {
        errcode = PFEC_page_present;
        goto page_fault;
    }

    if ( !mfn_valid(mfn) )
        return NULL;

    *mfnp = mfn;
    return sh_map_domain_page(mfn) + (vaddr & ~PAGE_MASK);

 page_fault:
    errcode |= PFEC_write_access;
    if ( is_hvm_vcpu(v) )
        hvm_inject_exception(TRAP_page_fault, errcode, vaddr);
    else
        propagate_page_fault(vaddr, errcode);
    return NULL;
}

static int safe_not_to_verify_write(mfn_t gmfn, void *dst, void *src, 
                                    int bytes)
{
#if (SHADOW_OPTIMIZATIONS & SHOPT_SKIP_VERIFY)
    struct page_info *pg = mfn_to_page(gmfn);
    if ( !(pg->shadow_flags & SHF_32) 
         && ((unsigned long)dst & 7) == 0 )
    {
        /* Not shadowed 32-bit: aligned 64-bit writes that leave the
         * present bit unset are safe to ignore. */
        if ( (*(u64*)src & _PAGE_PRESENT) == 0 
             && (*(u64*)dst & _PAGE_PRESENT) == 0 )
            return 1;
    }
    else if ( !(pg->shadow_flags & (SHF_PAE|SHF_64)) 
              && ((unsigned long)dst & 3) == 0 )
    {
        /* Not shadowed PAE/64-bit: aligned 32-bit writes that leave the
         * present bit unset are safe to ignore. */
        if ( (*(u32*)src & _PAGE_PRESENT) == 0 
             && (*(u32*)dst & _PAGE_PRESENT) == 0 )
            return 1;        
    }
#endif
    return 0;
}


int
sh_x86_emulate_write(struct vcpu *v, unsigned long vaddr, void *src,
                      u32 bytes, struct sh_emulate_ctxt *sh_ctxt)
{
    mfn_t mfn;
    void *addr;
    int skip;

    if ( vaddr & (bytes-1) )
        return X86EMUL_UNHANDLEABLE;

    ASSERT(shadow_locked_by_me(v->domain));
    ASSERT(((vaddr & ~PAGE_MASK) + bytes) <= PAGE_SIZE);

    if ( (addr = emulate_map_dest(v, vaddr, sh_ctxt, &mfn)) == NULL )
        return X86EMUL_EXCEPTION;

    skip = safe_not_to_verify_write(mfn, addr, src, bytes);
    memcpy(addr, src, bytes);
    if ( !skip ) sh_validate_guest_pt_write(v, mfn, addr, bytes);

    /* If we are writing zeros to this page, might want to unshadow */
    if ( likely(bytes >= 4) && (*(u32 *)addr == 0) && is_lo_pte(vaddr) )
        check_for_early_unshadow(v, mfn);

    sh_unmap_domain_page(addr);
    shadow_audit_tables(v);
    return X86EMUL_OKAY;
}

int
sh_x86_emulate_cmpxchg(struct vcpu *v, unsigned long vaddr, 
                        unsigned long old, unsigned long new,
                        unsigned int bytes, struct sh_emulate_ctxt *sh_ctxt)
{
    mfn_t mfn;
    void *addr;
    unsigned long prev;
    int rv = X86EMUL_OKAY, skip;

    ASSERT(shadow_locked_by_me(v->domain));
    ASSERT(bytes <= sizeof(unsigned long));

    if ( vaddr & (bytes-1) )
        return X86EMUL_UNHANDLEABLE;

    if ( (addr = emulate_map_dest(v, vaddr, sh_ctxt, &mfn)) == NULL )
        return X86EMUL_EXCEPTION;

    skip = safe_not_to_verify_write(mfn, &new, &old, bytes);

    switch ( bytes )
    {
    case 1: prev = cmpxchg(((u8 *)addr), old, new);  break;
    case 2: prev = cmpxchg(((u16 *)addr), old, new); break;
    case 4: prev = cmpxchg(((u32 *)addr), old, new); break;
    case 8: prev = cmpxchg(((u64 *)addr), old, new); break;
    default:
        SHADOW_PRINTK("cmpxchg of size %i is not supported\n", bytes);
        prev = ~old;
    }

    if ( prev == old )
    {
        if ( !skip ) sh_validate_guest_pt_write(v, mfn, addr, bytes);
    }
    else
        rv = X86EMUL_CMPXCHG_FAILED;

    SHADOW_DEBUG(EMULATE, "va %#lx was %#lx expected %#lx"
                  " wanted %#lx now %#lx bytes %u\n",
                  vaddr, prev, old, new, *(unsigned long *)addr, bytes);

    /* If we are writing zeros to this page, might want to unshadow */
    if ( likely(bytes >= 4) && (*(u32 *)addr == 0) && is_lo_pte(vaddr) )
        check_for_early_unshadow(v, mfn);

    sh_unmap_domain_page(addr);
    shadow_audit_tables(v);
    return rv;
}

int
sh_x86_emulate_cmpxchg8b(struct vcpu *v, unsigned long vaddr, 
                          unsigned long old_lo, unsigned long old_hi,
                          unsigned long new_lo, unsigned long new_hi,
                          struct sh_emulate_ctxt *sh_ctxt)
{
    mfn_t mfn;
    void *addr;
    u64 old, new, prev;
    int rv = X86EMUL_OKAY, skip;

    ASSERT(shadow_locked_by_me(v->domain));

    if ( vaddr & 7 )
        return X86EMUL_UNHANDLEABLE;

    if ( (addr = emulate_map_dest(v, vaddr, sh_ctxt, &mfn)) == NULL )
        return X86EMUL_EXCEPTION;

    old = (((u64) old_hi) << 32) | (u64) old_lo;
    new = (((u64) new_hi) << 32) | (u64) new_lo;
    skip = safe_not_to_verify_write(mfn, &new, &old, 8);
    prev = cmpxchg(((u64 *)addr), old, new);

    if ( prev == old )
    {
        if ( !skip ) sh_validate_guest_pt_write(v, mfn, addr, 8);
    }
    else
        rv = X86EMUL_CMPXCHG_FAILED;

    /* If we are writing zeros to this page, might want to unshadow */
    if ( *(u32 *)addr == 0 )
        check_for_early_unshadow(v, mfn);

    sh_unmap_domain_page(addr);
    shadow_audit_tables(v);
    return rv;
}


/**************************************************************************/
/* Audit tools */

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES

#define AUDIT_FAIL(_level, _fmt, _a...) do {                               \
    printk("Shadow %u-on-%u audit failed at level %i, index %i\n"         \
           "gl" #_level "mfn = %" PRI_mfn                              \
           " sl" #_level "mfn = %" PRI_mfn                             \
           " &gl" #_level "e = %p &sl" #_level "e = %p"                    \
           " gl" #_level "e = %" SH_PRI_gpte                              \
           " sl" #_level "e = %" SH_PRI_pte "\nError: " _fmt "\n",        \
           GUEST_PAGING_LEVELS, SHADOW_PAGING_LEVELS,                      \
           _level, guest_index(gl ## _level ## e),                         \
           mfn_x(gl ## _level ## mfn), mfn_x(sl ## _level ## mfn),         \
           gl ## _level ## e, sl ## _level ## e,                           \
           gl ## _level ## e->l ## _level, sl ## _level ## e->l ## _level, \
           ##_a);                                                          \
    BUG();                                                                 \
    done = 1;                                                              \
} while (0)


static char * sh_audit_flags(struct vcpu *v, int level,
                              int gflags, int sflags) 
/* Common code for auditing flag bits */
{
    if ( (sflags & _PAGE_PRESENT) && !(gflags & _PAGE_PRESENT) )
        return "shadow is present but guest is not present";
    if ( (sflags & _PAGE_GLOBAL) && !is_hvm_vcpu(v) ) 
        return "global bit set in PV shadow";
    if ( level == 2 && (sflags & _PAGE_PSE) )
        return "PS bit set in shadow";
#if SHADOW_PAGING_LEVELS == 3
    if ( level == 3 ) return NULL; /* All the other bits are blank in PAEl3 */
#endif
    if ( (sflags & _PAGE_PRESENT) && !(gflags & _PAGE_ACCESSED) ) 
        return "accessed bit not propagated";
    if ( (level == 1 || (level == 2 && (gflags & _PAGE_PSE)))
         && ((sflags & _PAGE_RW) && !(gflags & _PAGE_DIRTY)) ) 
        return "dirty bit not propagated";
    if ( (sflags & _PAGE_USER) != (gflags & _PAGE_USER) ) 
        return "user/supervisor bit does not match";
    if ( (sflags & _PAGE_NX_BIT) != (gflags & _PAGE_NX_BIT) ) 
        return "NX bit does not match";
    if ( (sflags & _PAGE_RW) && !(gflags & _PAGE_RW) ) 
        return "shadow grants write access but guest does not";
    return NULL;
}

static inline mfn_t
audit_gfn_to_mfn(struct vcpu *v, gfn_t gfn, mfn_t gmfn)
/* Convert this gfn to an mfn in the manner appropriate for the
 * guest pagetable it's used in (gmfn) */ 
{
    if ( !shadow_mode_translate(v->domain) )
        return _mfn(gfn_x(gfn));
    
    if ( (mfn_to_page(gmfn)->u.inuse.type_info & PGT_type_mask)
         != PGT_writable_page ) 
        return _mfn(gfn_x(gfn)); /* This is a paging-disabled shadow */
    else 
        return gfn_to_mfn(v->domain, gfn_x(gfn));
} 


int sh_audit_l1_table(struct vcpu *v, mfn_t sl1mfn, mfn_t x)
{
    guest_l1e_t *gl1e, *gp;
    shadow_l1e_t *sl1e;
    mfn_t mfn, gmfn, gl1mfn;
    gfn_t gfn;
    char *s;
    int done = 0;
    
    /* Follow the backpointer */
    gl1mfn = _mfn(mfn_to_shadow_page(sl1mfn)->backpointer);
    gl1e = gp = sh_map_domain_page(gl1mfn);
    SHADOW_FOREACH_L1E(sl1mfn, sl1e, &gl1e, done, {

        if ( sh_l1e_is_magic(*sl1e) ) 
        {
#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH) && SHADOW_PAGING_LEVELS > 2
            if ( sh_l1e_is_gnp(*sl1e) )
            {
                if ( guest_l1e_get_flags(*gl1e) & _PAGE_PRESENT )
                    AUDIT_FAIL(1, "shadow is GNP magic but guest is present");
            } 
            else 
            {
                ASSERT(sh_l1e_is_mmio(*sl1e));
                gfn = sh_l1e_mmio_get_gfn(*sl1e);
                if ( gfn_x(gfn) != gfn_x(guest_l1e_get_gfn(*gl1e)) )
                    AUDIT_FAIL(1, "shadow MMIO gfn is %" SH_PRI_gfn 
                               " but guest gfn is %" SH_PRI_gfn,
                               gfn_x(gfn),
                               gfn_x(guest_l1e_get_gfn(*gl1e)));
            }
#endif
        }
        else 
        {
            s = sh_audit_flags(v, 1, guest_l1e_get_flags(*gl1e),
                               shadow_l1e_get_flags(*sl1e));
            if ( s ) AUDIT_FAIL(1, "%s", s);
            
            if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
            {
                gfn = guest_l1e_get_gfn(*gl1e);
                mfn = shadow_l1e_get_mfn(*sl1e);
                gmfn = audit_gfn_to_mfn(v, gfn, gl1mfn);
                if ( mfn_x(gmfn) != mfn_x(mfn) )
                    AUDIT_FAIL(1, "bad translation: gfn %" SH_PRI_gfn
                               " --> %" PRI_mfn " != mfn %" PRI_mfn,
                               gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
            }
        }
    });
    sh_unmap_domain_page(gp);
    return done;
}

int sh_audit_fl1_table(struct vcpu *v, mfn_t sl1mfn, mfn_t x)
{
    guest_l1e_t *gl1e, e;
    shadow_l1e_t *sl1e;
    mfn_t gl1mfn = _mfn(INVALID_MFN);
    int f;
    int done = 0;

    /* fl1 has no useful backpointer: all we can check are flags */
    e = guest_l1e_from_gfn(_gfn(0), 0); gl1e = &e; /* Needed for macro */
    SHADOW_FOREACH_L1E(sl1mfn, sl1e, 0, done, {
        f = shadow_l1e_get_flags(*sl1e);
        f &= ~(_PAGE_AVAIL0|_PAGE_AVAIL1|_PAGE_AVAIL2);
        if ( !(f == 0 
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                        _PAGE_ACCESSED|_PAGE_DIRTY) 
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_ACCESSED|_PAGE_DIRTY)
               || sh_l1e_is_magic(*sl1e)) )
            AUDIT_FAIL(1, "fl1e has bad flags");
    });
    return 0;
}

int sh_audit_l2_table(struct vcpu *v, mfn_t sl2mfn, mfn_t x)
{
    guest_l2e_t *gl2e, *gp;
    shadow_l2e_t *sl2e;
    mfn_t mfn, gmfn, gl2mfn;
    gfn_t gfn;
    char *s;
    int done = 0;

    /* Follow the backpointer */
    gl2mfn = _mfn(mfn_to_shadow_page(sl2mfn)->backpointer);
    gl2e = gp = sh_map_domain_page(gl2mfn);
    SHADOW_FOREACH_L2E(sl2mfn, sl2e, &gl2e, done, v->domain, {

        s = sh_audit_flags(v, 2, guest_l2e_get_flags(*gl2e),
                            shadow_l2e_get_flags(*sl2e));
        if ( s ) AUDIT_FAIL(2, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            gfn = guest_l2e_get_gfn(*gl2e);
            mfn = shadow_l2e_get_mfn(*sl2e);
            gmfn = (guest_l2e_get_flags(*gl2e) & _PAGE_PSE)  
                ? get_fl1_shadow_status(v, gfn)
                : get_shadow_status(v, audit_gfn_to_mfn(v, gfn, gl2mfn), 
                                    SH_type_l1_shadow);
            if ( mfn_x(gmfn) != mfn_x(mfn) )
                AUDIT_FAIL(2, "bad translation: gfn %" SH_PRI_gfn
                           " (--> %" PRI_mfn ")"
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn), 
                           (guest_l2e_get_flags(*gl2e) & _PAGE_PSE) ? 0
                           : mfn_x(audit_gfn_to_mfn(v, gfn, gl2mfn)),
                           mfn_x(gmfn), mfn_x(mfn));
        }
    });
    sh_unmap_domain_page(gp);
    return 0;
}

#if GUEST_PAGING_LEVELS >= 4
int sh_audit_l3_table(struct vcpu *v, mfn_t sl3mfn, mfn_t x)
{
    guest_l3e_t *gl3e, *gp;
    shadow_l3e_t *sl3e;
    mfn_t mfn, gmfn, gl3mfn;
    gfn_t gfn;
    char *s;
    int done = 0;

    /* Follow the backpointer */
    gl3mfn = _mfn(mfn_to_shadow_page(sl3mfn)->backpointer);
    gl3e = gp = sh_map_domain_page(gl3mfn);
    SHADOW_FOREACH_L3E(sl3mfn, sl3e, &gl3e, done, {

        s = sh_audit_flags(v, 3, guest_l3e_get_flags(*gl3e),
                            shadow_l3e_get_flags(*sl3e));
        if ( s ) AUDIT_FAIL(3, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            gfn = guest_l3e_get_gfn(*gl3e);
            mfn = shadow_l3e_get_mfn(*sl3e);
            gmfn = get_shadow_status(v, audit_gfn_to_mfn(v, gfn, gl3mfn), 
                                     ((GUEST_PAGING_LEVELS == 3 ||
                                       IS_COMPAT(v->domain))
                                      && !shadow_mode_external(v->domain)
                                      && (guest_index(gl3e) % 4) == 3)
                                     ? SH_type_l2h_shadow
                                     : SH_type_l2_shadow);
            if ( mfn_x(gmfn) != mfn_x(mfn) )
                AUDIT_FAIL(3, "bad translation: gfn %" SH_PRI_gfn
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
        }
    });
    sh_unmap_domain_page(gp);
    return 0;
}

int sh_audit_l4_table(struct vcpu *v, mfn_t sl4mfn, mfn_t x)
{
    guest_l4e_t *gl4e, *gp;
    shadow_l4e_t *sl4e;
    mfn_t mfn, gmfn, gl4mfn;
    gfn_t gfn;
    char *s;
    int done = 0;

    /* Follow the backpointer */
    gl4mfn = _mfn(mfn_to_shadow_page(sl4mfn)->backpointer);
    gl4e = gp = sh_map_domain_page(gl4mfn);
    SHADOW_FOREACH_L4E(sl4mfn, sl4e, &gl4e, done, v->domain,
    {
        s = sh_audit_flags(v, 4, guest_l4e_get_flags(*gl4e),
                            shadow_l4e_get_flags(*sl4e));
        if ( s ) AUDIT_FAIL(4, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            gfn = guest_l4e_get_gfn(*gl4e);
            mfn = shadow_l4e_get_mfn(*sl4e);
            gmfn = get_shadow_status(v, audit_gfn_to_mfn(v, gfn, gl4mfn), 
                                     SH_type_l3_shadow);
            if ( mfn_x(gmfn) != mfn_x(mfn) )
                AUDIT_FAIL(4, "bad translation: gfn %" SH_PRI_gfn
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
        }
    });
    sh_unmap_domain_page(gp);
    return 0;
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


#undef AUDIT_FAIL

#endif /* Audit code */

/**************************************************************************/
/* Entry points into this mode of the shadow code.
 * This will all be mangled by the preprocessor to uniquify everything. */
struct paging_mode sh_paging_mode = {
    .page_fault                    = sh_page_fault, 
    .invlpg                        = sh_invlpg,
    .gva_to_gfn                    = sh_gva_to_gfn,
    .update_cr3                    = sh_update_cr3,
    .update_paging_modes           = shadow_update_paging_modes,
    .write_p2m_entry               = shadow_write_p2m_entry,
    .write_guest_entry             = shadow_write_guest_entry,
    .cmpxchg_guest_entry           = shadow_cmpxchg_guest_entry,
    .guest_map_l1e                 = sh_guest_map_l1e,
    .guest_get_eff_l1e             = sh_guest_get_eff_l1e,
    .guest_levels                  = GUEST_PAGING_LEVELS,
    .shadow.detach_old_tables      = sh_detach_old_tables,
    .shadow.x86_emulate_write      = sh_x86_emulate_write,
    .shadow.x86_emulate_cmpxchg    = sh_x86_emulate_cmpxchg,
    .shadow.x86_emulate_cmpxchg8b  = sh_x86_emulate_cmpxchg8b,
    .shadow.make_monitor_table     = sh_make_monitor_table,
    .shadow.destroy_monitor_table  = sh_destroy_monitor_table,
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    .shadow.guess_wrmap            = sh_guess_wrmap,
#endif
    .shadow.shadow_levels          = SHADOW_PAGING_LEVELS,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
