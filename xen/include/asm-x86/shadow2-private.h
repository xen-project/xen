/******************************************************************************
 * arch/x86/shadow2-private.h
 *
 * Shadow2 code that is private, and does not need to be multiply compiled.
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

#ifndef _XEN_SHADOW2_PRIVATE_H
#define _XEN_SHADOW2_PRIVATE_H

// In order to override the definition of mfn_to_page, we make sure page.h has
// been included...
#include <asm/page.h>
#include <xen/domain_page.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/support.h>


/******************************************************************************
 * Definitions for the use of the "available" bits in the shadow PTEs.
 *
 * Review of the low 12 bits of a shadow page table entry:
 *
 *         in a guest:                      in a shadow:
 * Bit 11: _PAGE_AVAIL2, aka _PAGE_GNTTAB
 * Bit 10: _PAGE_AVAIL1                     _PAGE_SHADOW_RW ("SW" below)
 * Bit  9: _PAGE_AVAIL0                     _PAGE_SHADOW_PRESENT ("SP" below)
 * Bit  8: _PAGE_GLOBAL                     _PAGE_SHADOW_MMIO ("MMIO" below),
 *                                          aka _PAGE_SHADOW_GUEST_NOT_PRESENT
 * Bit  7: _PAGE_PSE, aka _PAGE_PAT
 * Bit  6: _PAGE_DIRTY
 * Bit  5: _PAGE_ACCESSED
 * Bit  4: _PAGE_PCD
 * Bit  3: _PAGE_PWT
 * Bit  2: _PAGE_USER
 * Bit  1: _PAGE_RW ("GW" below)
 * Bit  0: _PAGE_PRESENT ("GP" below)
 *
 * Given a guest entry, as shown below, we can expect the following in the
 * corresponding shadow entry:
 *
 * Guest entry  Shadow entry      Commentary
 * -----------  ----------------  ---------------------------------------------
 *       Maps     
 * GP GW  IO    GP SP GW SW MMIO 
 * -- -- ----   -- -- -- -- ----
 *  -  -   -     0  0  0  0   0   The guest entry has not yet been shadowed.
 *  0  -   -     0  0  0  0   1   The guest entry is marked not-present.
 *  1  1  no     ?  1  ?  1   0   Writable entry in the guest.
 *  1  0  no     ?  1  0  0   0   Read-only entry in the guest.
 *  1  1  yes    0  1  ?  1   1   Writable MMIO mapping in the guest.
 *  1  0  yes    0  1  0  0   1   Read-only MMIO mapping in the guest.
 *
 * Normally, we would expect that GP=1 in the guest to imply GP=1 in the
 * shadow, and similarly for GW=1.  However, various functionality that may be
 * implemented via the shadow can cause GP or GW to be cleared in such cases.
 * A & D bit emulation is a prime example of such functionality.
 *
 * If _PAGE_SHADOW_PRESENT is zero, then the _PAGE_PRESENT bit in that same
 * entry will always be zero, too.

 * Bit 11 is used in debug builds as the _PAGE_GNTTAB bit in PV guests.  It is
 * currently available for random (ab)use in shadow entries.
 *
 * Bit 8 (the global bit) could be propagated from an HVM guest to the shadow,
 * but currently there is no benefit, as the guest's TLB is flushed on every
 * transition of CR3 anyway due to the HVM exit/re-entry.
 *
 * In shadow entries in which the _PAGE_SHADOW_PRESENT is set, bit 8 is used
 * as the _PAGE_SHADOW_MMIO bit.  In such entries, if _PAGE_SHADOW_MMIO is
 * set, then the entry contains the *gfn* directly from the corresponding
 * guest entry (not an mfn!!).
 *
 * Bit 7 is set in a guest L2 to signify a superpage entry.  The current
 * shadow code splinters superpage mappings into 512 or 1024 4K mappings; the
 * resulting shadow L1 table is called an FL1.  Note that there is no guest
 * page that corresponds to an FL1.
 *
 * Bit 7 in a guest L1 is the PAT2 bit.  Currently we do not support PAT in
 * this shadow code.
 *
 * Bit 6 is the dirty bit.
 *
 * Bit 5 is the accessed bit.
 *
 * Bit 4 is the cache disable bit.  If set in a guest, the hardware is
 * supposed to refuse to cache anything found via this entry.  It can be set
 * in an L4e, L3e, L2e, or L1e.  This shadow code currently does not support
 * cache disable bits.  They are silently ignored.
 *
 * Bit 4 is a guest L1 is also the PAT1 bit.  Currently we do not support PAT
 * in this shadow code.
 *
 * Bit 3 is the cache write-thru bit.  If set in a guest, the hardware is
 * supposed to use write-thru instead of write-back caching for anything found
 * via this entry.  It can be set in an L4e, L3e, L2e, or L1e.  This shadow
 * code currently does not support cache write-thru bits.  They are silently
 * ignored.
 *
 * Bit 3 is a guest L1 is also the PAT0 bit.  Currently we do not support PAT
 * in this shadow code.
 *
 * Bit 2 is the user bit.
 *
 * Bit 1 is the read-write bit.
 *
 * Bit 0 is the present bit.
 */

// Copy of the _PAGE_RW bit from the guest's PTE, appropriately zero'ed by
// the appropriate shadow rules.
#define _PAGE_SHADOW_RW                 _PAGE_AVAIL1

// Copy of the _PAGE_PRESENT bit from the guest's PTE
#define _PAGE_SHADOW_PRESENT            _PAGE_AVAIL0

// The matching guest entry maps MMIO space
#define _PAGE_SHADOW_MMIO               _PAGE_GLOBAL

// Shadow flags value used when the guest is not present
#define _PAGE_SHADOW_GUEST_NOT_PRESENT  _PAGE_GLOBAL


/******************************************************************************
 * Debug and error-message output
 */
#define SHADOW2_PRINTK(_f, _a...)                                     \
    debugtrace_printk("sh2: %s(): " _f, __func__, ##_a)
#define SHADOW2_ERROR(_f, _a...)                                      \
    printk("sh2 error: %s(): " _f, __func__, ##_a)
#define SHADOW2_DEBUG(flag, _f, _a...)                                \
    do {                                                              \
        if (SHADOW2_DEBUG_ ## flag)                                   \
            debugtrace_printk("sh2debug: %s(): " _f, __func__, ##_a); \
    } while (0)

// The flags for use with SHADOW2_DEBUG:
#define SHADOW2_DEBUG_PROPAGATE         0
#define SHADOW2_DEBUG_MAKE_SHADOW       0
#define SHADOW2_DEBUG_DESTROY_SHADOW    0
#define SHADOW2_DEBUG_P2M               0
#define SHADOW2_DEBUG_A_AND_D           0
#define SHADOW2_DEBUG_EMULATE           0
#define SHADOW2_DEBUG_LOGDIRTY          1


/******************************************************************************
 * Auditing routines 
 */

#if SHADOW2_AUDIT & SHADOW2_AUDIT_ENTRIES_FULL
extern void shadow2_audit_tables(struct vcpu *v);
#else
#define shadow2_audit_tables(_v) do {} while(0)
#endif

#if SHADOW2_AUDIT & SHADOW2_AUDIT_P2M
extern void shadow2_audit_p2m(struct domain *d);
#else
#define shadow2_audit_p2m(_d) do {} while(0)
#endif


/******************************************************************************
 * Mechanism for double-checking the optimized pagefault path: this
 * structure contains a record of actions taken by the fault handling
 * code.  In paranoid mode, the fast-path code fills out one of these
 * structures (but doesn't take any actual action) and then the normal 
 * path fills in another.  When the fault handler finishes, the 
 * two are compared */

#ifdef SHADOW2_OPTIMIZATION_PARANOIA

typedef struct shadow2_action_log sh2_log_t;
struct shadow2_action_log {
    paddr_t ad[CONFIG_PAGING_LEVELS];  /* A & D bits propagated here */
    paddr_t mmio;                      /* Address of an mmio operation */
    int rv;                            /* Result of the fault handler */
};

/* There are two logs, one for the fast path, one for the normal path */
enum sh2_log_type { log_slow = 0, log_fast= 1 };

/* Alloc and zero the logs */
static inline void sh2_init_log(struct vcpu *v) 
{
    if ( unlikely(!v->arch.shadow2_action_log) ) 
        v->arch.shadow2_action_log = xmalloc_array(sh2_log_t, 2);
    ASSERT(v->arch.shadow2_action_log);
    memset(v->arch.shadow2_action_log, 0, 2 * sizeof (sh2_log_t));
}

/* Log an A&D-bit update */
static inline void sh2_log_ad(struct vcpu *v, paddr_t e, unsigned int level)
{
    v->arch.shadow2_action_log[v->arch.shadow2_action_index].ad[level] = e;
}

/* Log an MMIO address */
static inline void sh2_log_mmio(struct vcpu *v, paddr_t m)
{
    v->arch.shadow2_action_log[v->arch.shadow2_action_index].mmio = m;
}

/* Log the result */
static inline void sh2_log_rv(struct vcpu *v, int rv)
{
    v->arch.shadow2_action_log[v->arch.shadow2_action_index].rv = rv;
}

/* Set which mode we're in */
static inline void sh2_set_log_mode(struct vcpu *v, enum sh2_log_type t) 
{
    v->arch.shadow2_action_index = t;
}

/* Know not to take action, because we're only checking the mechanism */
static inline int sh2_take_no_action(struct vcpu *v) 
{
    return (v->arch.shadow2_action_index == log_fast);
}

#else /* Non-paranoid mode: these logs do not exist */

#define sh2_init_log(_v) do { (void)(_v); } while(0)
#define sh2_set_log_mode(_v,_t) do { (void)(_v); } while(0)
#define sh2_log_ad(_v,_e,_l) do { (void)(_v),(void)(_e),(void)(_l); } while (0)
#define sh2_log_mmio(_v,_m) do { (void)(_v),(void)(_m); } while (0)
#define sh2_log_rv(_v,_r) do { (void)(_v),(void)(_r); } while (0)
#define sh2_take_no_action(_v) (((void)(_v)), 0)

#endif /* SHADOW2_OPTIMIZATION_PARANOIA */


/******************************************************************************
 * Macro for dealing with the naming of the internal names of the
 * shadow code's external entry points.
 */
#define SHADOW2_INTERNAL_NAME_HIDDEN(name, shadow_levels, guest_levels) \
    name ## __shadow_ ## shadow_levels ## _guest_ ## guest_levels
#define SHADOW2_INTERNAL_NAME(name, shadow_levels, guest_levels) \
    SHADOW2_INTERNAL_NAME_HIDDEN(name, shadow_levels, guest_levels)

#if CONFIG_PAGING_LEVELS == 2
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 2
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 2 */

#if CONFIG_PAGING_LEVELS == 3
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 3
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 3
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 3 */

#if CONFIG_PAGING_LEVELS == 4
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 3
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 3
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 4
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  4
#define SHADOW_LEVELS 4
#include <asm/shadow2-multi.h>
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 4 */


/******************************************************************************
 * Various function declarations 
 */

/* x86 emulator support */
extern struct x86_emulate_ops shadow2_emulator_ops;

/* Hash table functions */
mfn_t shadow2_hash_lookup(struct vcpu *v, unsigned long n, u8 t);
void  shadow2_hash_insert(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn);
void  shadow2_hash_delete(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn);

/* shadow promotion */
void shadow2_promote(struct vcpu *v, mfn_t gmfn, u32 type);
void shadow2_demote(struct vcpu *v, mfn_t gmfn, u32 type);

/* Shadow page allocation functions */
void  shadow2_prealloc(struct domain *d, unsigned int order);
mfn_t shadow2_alloc(struct domain *d, 
                    u32 shadow_type,
                    unsigned long backpointer);
void  shadow2_free(struct domain *d, mfn_t smfn);

/* Function to convert a shadow to log-dirty */
void shadow2_convert_to_log_dirty(struct vcpu *v, mfn_t smfn);

/* Dispatcher function: call the per-mode function that will unhook the
 * non-Xen mappings in this top-level shadow mfn */
void shadow2_unhook_mappings(struct vcpu *v, mfn_t smfn);

/* Re-sync copies of PAE shadow L3 tables if they have been changed */
void sh2_pae_recopy(struct domain *d);

/* Install the xen mappings in various flavours of shadow */
void sh2_install_xen_entries_in_l4(struct vcpu *v, mfn_t gl4mfn, mfn_t sl4mfn);
void sh2_install_xen_entries_in_l2h(struct vcpu *v, mfn_t sl2hmfn);
void sh2_install_xen_entries_in_l3(struct vcpu *v, mfn_t gl3mfn, mfn_t sl3mfn);
void sh2_install_xen_entries_in_l2(struct vcpu *v, mfn_t gl2mfn, mfn_t sl2mfn);


/******************************************************************************
 * MFN/page-info handling 
 */

// Override mfn_to_page from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_to_page
#define mfn_to_page(_mfn) (frame_table + mfn_x(_mfn))

// Override page_to_mfn from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))

// Override mfn_valid from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)

// Provide mfn_t-aware versions of common xen functions
static inline void *
sh2_map_domain_page(mfn_t mfn)
{
    /* XXX Using the monitor-table as a map will happen here  */
    return map_domain_page(mfn_x(mfn));
}

static inline void 
sh2_unmap_domain_page(void *p) 
{
    /* XXX Using the monitor-table as a map will happen here  */
    unmap_domain_page(p);
}

static inline void *
sh2_map_domain_page_global(mfn_t mfn)
{
    /* XXX Using the monitor-table as a map will happen here  */
    return map_domain_page_global(mfn_x(mfn));
}

static inline void 
sh2_unmap_domain_page_global(void *p) 
{
    /* XXX Using the monitor-table as a map will happen here  */
    unmap_domain_page_global(p);
}

static inline int
sh2_mfn_is_dirty(struct domain *d, mfn_t gmfn)
/* Is this guest page dirty?  Call only in log-dirty mode. */
{
    unsigned long pfn;
    ASSERT(shadow2_mode_log_dirty(d));
    ASSERT(d->arch.shadow_dirty_bitmap != NULL);

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));
    if ( likely(VALID_M2P(pfn))
         && likely(pfn < d->arch.shadow_dirty_bitmap_size) 
         && test_bit(pfn, d->arch.shadow_dirty_bitmap) )
        return 1;

    return 0;
}

static inline int
sh2_mfn_is_a_page_table(mfn_t gmfn)
{
    struct page_info *page = mfn_to_page(gmfn);
    struct domain *owner;
    unsigned long type_info;

    if ( !valid_mfn(gmfn) )
        return 0;

    owner = page_get_owner(page);
    if ( owner && shadow2_mode_refcounts(owner) 
         && (page->count_info & PGC_page_table) )
        return 1; 

    type_info = page->u.inuse.type_info & PGT_type_mask;
    return type_info && (type_info <= PGT_l4_page_table);
}


/**************************************************************************/
/* Shadow-page refcounting. See comment in shadow2-common.c about the  
 * use of struct page_info fields for shadow pages */

void sh2_destroy_shadow(struct vcpu *v, mfn_t smfn);

/* Increase the refcount of a shadow page.  Arguments are the mfn to refcount, 
 * and the physical address of the shadow entry that holds the ref (or zero
 * if the ref is held by something else) */
static inline void sh2_get_ref(mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct page_info *page = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));

    x = page->count_info & PGC_SH2_count_mask;
    nx = x + 1;

    if ( unlikely(nx & ~PGC_SH2_count_mask) )
    {
        SHADOW2_PRINTK("shadow ref overflow, gmfn=%" PRtype_info " smfn=%lx\n",
                       page->u.inuse.type_info, mfn_x(smfn));
        domain_crash_synchronous();
    }
    
    /* Guarded by the shadow lock, so no need for atomic update */
    page->count_info &= ~PGC_SH2_count_mask;
    page->count_info |= nx;

    /* We remember the first shadow entry that points to each shadow. */
    if ( entry_pa != 0 && page->up == 0 ) 
        page->up = entry_pa;
}


/* Decrease the refcount of a shadow page.  As for get_ref, takes the
 * physical address of the shadow entry that held this reference. */
static inline void sh2_put_ref(struct vcpu *v, mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct page_info *page = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(page_get_owner(page) == NULL);

    /* If this is the entry in the up-pointer, remove it */
    if ( entry_pa != 0 && page->up == entry_pa ) 
        page->up = 0;

    x = page->count_info & PGC_SH2_count_mask;
    nx = x - 1;

    if ( unlikely(x == 0) ) 
    {
        SHADOW2_PRINTK("shadow ref underflow, smfn=%lx oc=%08x t=%" 
                       PRtype_info "\n",
                       mfn_x(smfn),
                       page->count_info & PGC_SH2_count_mask,
                       page->u.inuse.type_info);
        domain_crash_synchronous();
    }

    /* Guarded by the shadow lock, so no need for atomic update */
    page->count_info &= ~PGC_SH2_count_mask;
    page->count_info |= nx;

    if ( unlikely(nx == 0) ) 
        sh2_destroy_shadow(v, smfn);
}


/* Pin a shadow page: take an extra refcount and set the pin bit. */
static inline void sh2_pin(mfn_t smfn)
{
    struct page_info *page;
    
    ASSERT(mfn_valid(smfn));
    page = mfn_to_page(smfn);
    if ( !(page->count_info & PGC_SH2_pinned) ) 
    {
        sh2_get_ref(smfn, 0);
        page->count_info |= PGC_SH2_pinned;
    }
}

/* Unpin a shadow page: unset the pin bit and release the extra ref. */
static inline void sh2_unpin(struct vcpu *v, mfn_t smfn)
{
    struct page_info *page;
    
    ASSERT(mfn_valid(smfn));
    page = mfn_to_page(smfn);
    if ( page->count_info & PGC_SH2_pinned )
    {
        page->count_info &= ~PGC_SH2_pinned;
        sh2_put_ref(v, smfn, 0);
    }
}

/**************************************************************************/
/* CPU feature support querying */

static inline int
guest_supports_superpages(struct vcpu *v)
{
    return hvm_guest(v) && (hvm_get_guest_ctrl_reg(v, 4) & X86_CR4_PSE);
}

static inline int
guest_supports_nx(struct vcpu *v)
{
    if ( !hvm_guest(v) )
        return cpu_has_nx;

    // XXX - fix this!
    return 1;
}

/**************************************************************************/
/* Guest physmap (p2m) support */

/* Read our own P2M table, checking in the linear pagetables first to be
 * sure that we will succeed.  Call this function if you expect it to
 * fail often, as it avoids page faults.  If you expect to succeed, use
 * vcpu_gfn_to_mfn, which copy_from_user()s the entry */
static inline mfn_t
vcpu_gfn_to_mfn_nofault(struct vcpu *v, unsigned long gfn)
{
    unsigned long entry_addr = (unsigned long) &phys_to_machine_mapping[gfn];
#if CONFIG_PAGING_LEVELS >= 4
    l4_pgentry_t *l4e;
    l3_pgentry_t *l3e;
#endif
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;

    ASSERT(current == v);
    if ( !shadow2_vcpu_mode_translate(v) )
        return _mfn(gfn);

#if CONFIG_PAGING_LEVELS > 2
    if ( gfn > (RO_MPT_VIRT_END - RO_MPT_VIRT_START) / sizeof(l1_pgentry_t) ) 
        /* This pfn is higher than the p2m map can hold */
        return _mfn(INVALID_MFN);
#endif
    
    /* Walk the linear pagetables.  Note that this is *not* the same as 
     * the walk in sh2_gfn_to_mfn_foreign, which is walking the p2m map */
#if CONFIG_PAGING_LEVELS >= 4
    l4e = __linear_l4_table + l4_linear_offset(entry_addr);
    if ( !(l4e_get_flags(*l4e) & _PAGE_PRESENT) ) return _mfn(INVALID_MFN);
    l3e = __linear_l3_table + l3_linear_offset(entry_addr);
    if ( !(l3e_get_flags(*l3e) & _PAGE_PRESENT) ) return _mfn(INVALID_MFN);
#endif
    l2e = __linear_l2_table + l2_linear_offset(entry_addr);
    if ( !(l2e_get_flags(*l2e) & _PAGE_PRESENT) ) return _mfn(INVALID_MFN);
    l1e = __linear_l1_table + l1_linear_offset(entry_addr);
    if ( !(l1e_get_flags(*l1e) & _PAGE_PRESENT) ) return _mfn(INVALID_MFN);

    /* Safe to look at this part of the table */
    if ( l1e_get_flags(phys_to_machine_mapping[gfn])  & _PAGE_PRESENT )
        return _mfn(l1e_get_pfn(phys_to_machine_mapping[gfn]));
    
    return _mfn(INVALID_MFN);
}


#endif /* _XEN_SHADOW2_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
