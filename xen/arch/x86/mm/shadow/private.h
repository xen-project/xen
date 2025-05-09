/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/shadow/private.h
 *
 * Shadow code that is private, and does not need to be multiply compiled.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#ifndef _XEN_SHADOW_PRIVATE_H
#define _XEN_SHADOW_PRIVATE_H

// In order to override the definition of mfn_to_page, we make sure page.h has
// been included...
#include <asm/page.h>
#include <xen/domain_page.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/support.h>
#include <asm/atomic.h>

#include "../mm-locks.h"

/******************************************************************************
 * Levels of self-test and paranoia
 */

#define SHADOW_AUDIT_HASH           0x01  /* Check current hash bucket */
#define SHADOW_AUDIT_HASH_FULL      0x02  /* Check every hash bucket */
#define SHADOW_AUDIT_ENTRIES        0x04  /* Check this walk's shadows */
#define SHADOW_AUDIT_ENTRIES_FULL   0x08  /* Check every shadow */
#define SHADOW_AUDIT_ENTRIES_MFNS   0x10  /* Check gfn-mfn map in shadows */

#ifdef NDEBUG
#define SHADOW_AUDIT                   0
#define SHADOW_AUDIT_ENABLE            0
#else
#define SHADOW_AUDIT                0x15  /* Basic audit of all */
#define SHADOW_AUDIT_ENABLE         shadow_audit_enable
extern int shadow_audit_enable;
#endif

/******************************************************************************
 * Levels of optimization
 */

#define SHOPT_WRITABLE_HEURISTIC  0x01  /* Guess at RW PTEs via linear maps */
#define SHOPT_EARLY_UNSHADOW      0x02  /* Unshadow l1s on fork or exit */
#define SHOPT_FAST_FAULT_PATH     0x04  /* Fast-path MMIO and not-present */
#define SHOPT_PREFETCH            0x08  /* Shadow multiple entries per fault */
#define SHOPT_LINUX_L3_TOPLEVEL   0x10  /* Pin l3es on early 64bit linux */
#define SHOPT_SKIP_VERIFY         0x20  /* Skip PTE v'fy when safe to do so */
#define SHOPT_VIRTUAL_TLB         0x40  /* Cache guest v->p translations */
#define SHOPT_FAST_EMULATION      0x80  /* Fast write emulation */
#define SHOPT_OUT_OF_SYNC        0x100  /* Allow guest writes to L1 PTs */

#ifdef CONFIG_HVM
#define SHADOW_OPTIMIZATIONS     0x1ff
#else
#define SHADOW_OPTIMIZATIONS     (0x1ff & ~(SHOPT_OUT_OF_SYNC | \
                                            SHOPT_FAST_EMULATION))
#endif


/******************************************************************************
 * Debug and error-message output
 */

#define SHADOW_PRINTK(_f, _a...)                                     \
    debugtrace_printk("sh: %s(): " _f, __func__, ##_a)
#define SHADOW_DEBUG(flag, _f, _a...)                                \
    do {                                                              \
        if (SHADOW_DEBUG_ ## flag)                                   \
            debugtrace_printk("shdebug: %s(): " _f, __func__, ##_a); \
    } while (0)

// The flags for use with SHADOW_DEBUG:
#define SHADOW_DEBUG_PROPAGATE         1
#define SHADOW_DEBUG_MAKE_SHADOW       1
#define SHADOW_DEBUG_DESTROY_SHADOW    1
#define SHADOW_DEBUG_A_AND_D           1
#define SHADOW_DEBUG_EMULATE           1
#define SHADOW_DEBUG_P2M               1
#define SHADOW_DEBUG_LOGDIRTY          0

/******************************************************************************
 * Tracing
 */
DECLARE_PER_CPU(uint32_t,trace_shadow_path_flags);

#define TRACE_SHADOW_PATH_FLAG(_x)                      \
    do {                                                \
        this_cpu(trace_shadow_path_flags) |= (1<<(_x));      \
    } while(0)

#define TRACE_CLEAR_PATH_FLAGS                  \
    this_cpu(trace_shadow_path_flags) = 0

enum {
    TRCE_SFLAG_SET_AD,
    TRCE_SFLAG_SET_A,
    TRCE_SFLAG_SHADOW_L1_GET_REF,
    TRCE_SFLAG_SHADOW_L1_PUT_REF,
    TRCE_SFLAG_L2_PROPAGATE,
    TRCE_SFLAG_SET_CHANGED,
    TRCE_SFLAG_SET_FLUSH,
    TRCE_SFLAG_SET_ERROR,
    TRCE_SFLAG_DEMOTE,
    TRCE_SFLAG_PROMOTE,
    TRCE_SFLAG_WRMAP,
    TRCE_SFLAG_WRMAP_GUESS_FOUND,
    TRCE_SFLAG_WRMAP_BRUTE_FORCE,
    TRCE_SFLAG_EARLY_UNSHADOW,
    TRCE_SFLAG_EMULATION_2ND_PT_WRITTEN,
    TRCE_SFLAG_EMULATION_LAST_FAILED,
    TRCE_SFLAG_EMULATE_FULL_PT,
    TRCE_SFLAG_PREALLOC_UNHOOK,
    TRCE_SFLAG_UNSYNC,
    TRCE_SFLAG_OOS_FIXUP_ADD,
    TRCE_SFLAG_OOS_FIXUP_EVICT,
};


/* Size (in bytes) of a guest PTE */
#if GUEST_PAGING_LEVELS >= 3
# define GUEST_PTE_SIZE 8
#else
# define GUEST_PTE_SIZE 4
#endif

/******************************************************************************
 * Auditing routines
 */

extern void shadow_audit_tables(struct vcpu *v);

/******************************************************************************
 * Macro for dealing with the naming of the internal names of the
 * shadow code's external entry points.
 */
#define SHADOW_INTERNAL_NAME_(name, kind, value)        \
    name ## __ ## kind ## _ ## value
#define SHADOW_INTERNAL_NAME(name, guest_levels)        \
    SHADOW_INTERNAL_NAME_(name, guest, guest_levels)
#define SHADOW_SH_NAME(name, shadow_levels)             \
    SHADOW_INTERNAL_NAME_(name, sh, shadow_levels)

#define GUEST_LEVELS  2
#include "multi.h"
#undef GUEST_LEVELS

#define GUEST_LEVELS  3
#include "multi.h"
#undef GUEST_LEVELS

#define GUEST_LEVELS  4
#include "multi.h"
#undef GUEST_LEVELS

/* Shadow type codes */
#define SH_type_none           (0U) /* on the shadow free list */
#define SH_type_min_shadow     (1U)
#ifdef CONFIG_HVM
#define SH_type_l1_32_shadow   (1U) /* shadowing a 32-bit L1 guest page */
#define SH_type_fl1_32_shadow  (2U) /* L1 shadow for a 32b 4M superpage */
#define SH_type_l2_32_shadow   (3U) /* shadowing a 32-bit L2 guest page */
#define SH_type_l1_pae_shadow  (4U) /* shadowing a pae L1 page */
#define SH_type_fl1_pae_shadow (5U) /* L1 shadow for pae 2M superpg */
#define SH_type_l2_pae_shadow  (6U) /* shadowing a pae L2-low page */
#define SH_type_l1_64_shadow   (7U) /* shadowing a 64-bit L1 page */
#define SH_type_fl1_64_shadow  (8U) /* L1 shadow for 64-bit 2M superpg */
#define SH_type_l2_64_shadow   (9U) /* shadowing a 64-bit L2 page */
#define SH_type_l2h_64_shadow (10U) /* shadowing a compat PAE L2 high page */
#define SH_type_l3_64_shadow  (11U) /* shadowing a 64-bit L3 page */
#define SH_type_l4_64_shadow  (12U) /* shadowing a 64-bit L4 page */
#define SH_type_max_shadow    (12U)
#define SH_type_p2m_table     (13U) /* in use as the p2m table */
#define SH_type_monitor_table (14U) /* in use as a monitor table */
#define SH_type_oos_snapshot  (15U) /* in use as OOS snapshot */
#define SH_type_unused        (16U)
#else
#define SH_type_l1_32_shadow   SH_type_unused
#define SH_type_fl1_32_shadow  SH_type_unused
#define SH_type_l2_32_shadow   SH_type_unused
#define SH_type_l1_pae_shadow  SH_type_unused
#define SH_type_fl1_pae_shadow SH_type_unused
#define SH_type_l2_pae_shadow  SH_type_unused
#define SH_type_l1_64_shadow   1U /* shadowing a 64-bit L1 page */
#define SH_type_fl1_64_shadow  2U /* L1 shadow for 64-bit 2M superpg */
#define SH_type_l2_64_shadow   3U /* shadowing a 64-bit L2 page */
#define SH_type_l2h_64_shadow  4U /* shadowing a compat PAE L2 high page */
#define SH_type_l3_64_shadow   5U /* shadowing a 64-bit L3 page */
#define SH_type_l4_64_shadow   6U /* shadowing a 64-bit L4 page */
#define SH_type_max_shadow     6U
#define SH_type_p2m_table      7U /* in use as the p2m table */
#define SH_type_unused         8U
#endif

#ifndef CONFIG_PV32 /* Unused (but uglier to #ifdef above): */
#undef SH_type_l2h_64_shadow
#endif

/*
 * What counts as a pinnable shadow?
 */

static inline int sh_type_is_pinnable(struct domain *d, unsigned int t)
{
    /* Top-level shadow types in each mode can be pinned, so that they
     * persist even when not currently in use in a guest CR3 */
    if ( t == SH_type_l2_32_shadow
         || t == SH_type_l2_pae_shadow
         || t == SH_type_l4_64_shadow )
        return 1;

#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL)
    /* Early 64-bit linux used three levels of pagetables for the guest
     * and context switched by changing one l4 entry in a per-cpu l4
     * page.  When we're shadowing those kernels, we have to pin l3
     * shadows so they don't just evaporate on every context switch.
     * For all other guests, we'd rather use the up-pointer field in l3s. */
    if ( unlikely((d->arch.paging.shadow.opt_flags & SHOPT_LINUX_L3_TOPLEVEL)
                  && t == SH_type_l3_64_shadow) )
        return 1;
#endif

    /* Everything else is not pinnable, and can use the "up" pointer */
    return 0;
}

static inline int sh_type_has_up_pointer(struct domain *d, unsigned int t)
{
    /* Multi-page shadows don't have up-pointers */
    if ( t == SH_type_l1_32_shadow
         || t == SH_type_fl1_32_shadow
         || t == SH_type_l2_32_shadow )
        return 0;
    /* Pinnable shadows don't have up-pointers either */
    return !sh_type_is_pinnable(d, t);
}

static inline void sh_terminate_list(struct page_list_head *tmp_list)
{
#ifndef PAGE_LIST_NULL
    /* The temporary list-head is on our stack.  Invalidate the
     * pointers to it in the shadows, just to get a clean failure if
     * we accidentally follow them. */
    tmp_list->prev->next = LIST_POISON1;
    tmp_list->next->prev = LIST_POISON2;
#endif
}

/*
 * Definitions for the shadow_flags field in page_info.
 * These flags are stored on *guest* pages...
 * Bits 1-13 are encodings for the shadow types.
 */
#define SHF_page_type_mask \
    (((1u << (SH_type_max_shadow + 1u)) - 1u) - \
     ((1u << SH_type_min_shadow) - 1u))

#ifdef CONFIG_HVM
#define SHF_L1_32   (1u << SH_type_l1_32_shadow)
#define SHF_FL1_32  (1u << SH_type_fl1_32_shadow)
#define SHF_L2_32   (1u << SH_type_l2_32_shadow)
#define SHF_L1_PAE  (1u << SH_type_l1_pae_shadow)
#define SHF_FL1_PAE (1u << SH_type_fl1_pae_shadow)
#define SHF_L2_PAE  (1u << SH_type_l2_pae_shadow)
#else
#define SHF_L1_32   0
#define SHF_FL1_32  0
#define SHF_L2_32   0
#define SHF_L1_PAE  0
#define SHF_FL1_PAE 0
#define SHF_L2_PAE  0
#endif
#define SHF_L1_64   (1u << SH_type_l1_64_shadow)
#define SHF_FL1_64  (1u << SH_type_fl1_64_shadow)
#define SHF_L2_64   (1u << SH_type_l2_64_shadow)
#ifdef CONFIG_PV32
#define SHF_L2H_64  (1u << SH_type_l2h_64_shadow)
#else
#define SHF_L2H_64  0
#endif
#define SHF_L3_64   (1u << SH_type_l3_64_shadow)
#define SHF_L4_64   (1u << SH_type_l4_64_shadow)

#define SHF_32  (SHF_L1_32|SHF_FL1_32|SHF_L2_32)
#define SHF_PAE (SHF_L1_PAE|SHF_FL1_PAE|SHF_L2_PAE)
#define SHF_64  (SHF_L1_64|SHF_FL1_64|SHF_L2_64|SHF_L2H_64|SHF_L3_64|SHF_L4_64)

#define SHF_L1_ANY  (SHF_L1_32|SHF_L1_PAE|SHF_L1_64)
#define SHF_FL1_ANY (SHF_FL1_32|SHF_FL1_PAE|SHF_FL1_64)

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
/* Marks a guest L1 page table which is shadowed but not write-protected.
 * If set, then *only* L1 shadows (SHF_L1_*) are allowed.
 *
 * out_of_sync indicates that the shadow tables may not reflect the
 * guest tables.  If it is clear, then the shadow tables *must* reflect
 * the guest tables.
 *
 * oos_may_write indicates that a page may have writable mappings.
 *
 * Most of the time the flags are synonymous.  There is a short period of time
 * during resync that oos_may_write is clear but out_of_sync is not.  If a
 * codepath is called during that time and is sensitive to oos issues, it may
 * need to use the second flag.
 */
#define SHF_out_of_sync (1u << (SH_type_max_shadow + 1))
#define SHF_oos_may_write (1u << (SH_type_max_shadow + 2))

static inline int sh_page_has_multiple_shadows(struct page_info *pg)
{
    u32 shadows;
    if ( !(pg->count_info & PGC_shadowed_pt) )
        return 0;
    shadows = pg->shadow_flags & SHF_page_type_mask;
    /* More than one type bit set in shadow-flags? */
    return shadows && (shadows & (shadows - 1));
}

/* The caller must verify this is reasonable to call; i.e., valid mfn,
 * domain is translated, &c */
static inline int page_is_out_of_sync(struct page_info *p)
{
    return (p->count_info & PGC_shadowed_pt)
        && (p->shadow_flags & SHF_out_of_sync);
}

static inline int mfn_is_out_of_sync(mfn_t gmfn)
{
    return page_is_out_of_sync(mfn_to_page(gmfn));
}

static inline int page_oos_may_write(struct page_info *p)
{
    return (p->count_info & PGC_shadowed_pt)
        && (p->shadow_flags & SHF_oos_may_write);
}

static inline int mfn_oos_may_write(mfn_t gmfn)
{
    return page_oos_may_write(mfn_to_page(gmfn));
}
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC) */

/* Figure out the size (in pages) of a given shadow type */
extern const uint8_t sh_type_to_size[SH_type_unused];
static inline unsigned int
shadow_size(unsigned int shadow_type)
{
#ifdef CONFIG_HVM
    ASSERT(shadow_type < ARRAY_SIZE(sh_type_to_size));
    return sh_type_to_size[shadow_type];
#else
    ASSERT(shadow_type < SH_type_unused);
    return shadow_type != SH_type_none;
#endif
}

/******************************************************************************
 * Various function declarations
 */

/* Hash table functions */
mfn_t shadow_hash_lookup(struct domain *d, unsigned long n, unsigned int t);
void  shadow_hash_insert(struct domain *d,
                         unsigned long n, unsigned int t, mfn_t smfn);
bool  shadow_hash_delete(struct domain *d,
                         unsigned long n, unsigned int t, mfn_t smfn);

/* shadow promotion */
void shadow_promote(struct domain *d, mfn_t gmfn, u32 type);
void shadow_demote(struct domain *d, mfn_t gmfn, u32 type);

/* Shadow page allocation functions */
bool __must_check shadow_prealloc(struct domain *d, unsigned int shadow_type,
                                  unsigned int count);
mfn_t shadow_alloc(struct domain *d,
                    u32 shadow_type,
                    unsigned long backpointer);
void  shadow_free(struct domain *d, mfn_t smfn);

/* Set up the top-level shadow and install it in slot 'slot' of shadow_table */
pagetable_t sh_set_toplevel_shadow(struct vcpu *v,
                                   unsigned int slot,
                                   mfn_t gmfn,
                                   unsigned int root_type,
                                   mfn_t (*make_shadow)(struct vcpu *v,
                                                        mfn_t gmfn,
                                                        uint32_t shadow_type));

/* Update the shadows in response to a pagetable write from Xen */
int sh_validate_guest_entry(struct vcpu *v, mfn_t gmfn, void *entry, u32 size);

#ifdef CONFIG_HVM
/* Remove all writeable mappings of a guest frame from the shadows.
 * Returns non-zero if we need to flush TLBs.
 * level and fault_addr desribe how we found this to be a pagetable;
 * level==0 means we have some other reason for revoking write access. */
extern int sh_remove_write_access(struct domain *d, mfn_t readonly_mfn,
                                  unsigned int level,
                                  unsigned long fault_addr);
#else
static inline int sh_remove_write_access(struct domain *d, mfn_t readonly_mfn,
                                         unsigned int level,
                                         unsigned long fault_addr)
{
    ASSERT(!shadow_mode_refcounts(d));
    return 0;
}
#endif

/* Unhook the non-Xen mappings in this top-level shadow mfn.
 * With user_only == 1, unhooks only the user-mode mappings. */
void shadow_unhook_mappings(struct domain *d, mfn_t smfn, int user_only);

/*
 * sh_{make,destroy}_monitor_table() depend only on the number of shadow
 * levels.
 */
mfn_t sh_make_monitor_table(const struct vcpu *v, unsigned int shadow_levels);
void sh_destroy_monitor_table(const struct vcpu *v, mfn_t mmfn,
                              unsigned int shadow_levels);

/* VRAM dirty tracking helpers. */
void shadow_vram_get_mfn(mfn_t mfn, unsigned int l1f,
                         mfn_t sl1mfn, const void *sl1e,
                         const struct domain *d);
void shadow_vram_put_mfn(mfn_t mfn, unsigned int l1f,
                         mfn_t sl1mfn, const void *sl1e,
                         const struct domain *d);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
/* Allow a shadowed page to go out of sync */
int sh_unsync(struct vcpu *v, mfn_t gmfn);

/* Pull an out-of-sync page back into sync. */
void sh_resync(struct domain *d, mfn_t gmfn);

void oos_fixup_add(struct domain *d, mfn_t gmfn, mfn_t smfn, unsigned long off);

/* Pull all out-of-sync shadows back into sync.  If skip != 0, we try
 * to avoid resyncing where we think we can get away with it. */

void sh_resync_all(struct vcpu *v, int skip, int this, int others);

static inline void
shadow_resync_all(struct vcpu *v)
{
    sh_resync_all(v, 0 /* skip */, 1 /* this */, 1 /* others */);
}

static inline void
shadow_resync_current_vcpu(struct vcpu *v)
{
    sh_resync_all(v, 0 /* skip */, 1 /* this */, 0 /* others */);
}

static inline void
shadow_sync_other_vcpus(struct vcpu *v)
{
    sh_resync_all(v, 1 /* skip */, 0 /* this */, 1 /* others */);
}

void oos_audit_hash_is_present(struct domain *d, mfn_t gmfn);
mfn_t oos_snapshot_lookup(struct domain *d, mfn_t gmfn);

#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC) */

/* Deliberately free all the memory we can: tear down all of d's shadows. */
void shadow_blow_tables(struct domain *d);

/*
 * Remove all mappings of a guest frame from the shadow tables.
 * Returns non-zero if we need to flush TLBs.
 */
int sh_remove_all_mappings(struct domain *d, mfn_t gmfn, gfn_t gfn);

/******************************************************************************
 * Flags used in the return value of the shadow_set_lXe() functions...
 */

/* We actually wrote something new to the shadow */
#define SHADOW_SET_CHANGED            0x1
/* Caller should flush TLBs to clear the old entry */
#define SHADOW_SET_FLUSH              0x2
/* Something went wrong: the shadow entry was invalid or refcount failed */
#define SHADOW_SET_ERROR              0x4


/******************************************************************************
 * MFN/page-info handling
 */

#define backpointer(sp) _mfn(pdx_to_pfn((unsigned long)(sp)->v.sh.back))
static inline unsigned long __backpointer(const struct page_info *sp)
{
    switch (sp->u.sh.type)
    {
#ifdef CONFIG_HVM
    case SH_type_fl1_32_shadow:
    case SH_type_fl1_pae_shadow:
#endif
    case SH_type_fl1_64_shadow:
        return sp->v.sh.back;
    }
    return pdx_to_pfn(sp->v.sh.back);
}

static inline int
sh_mfn_is_a_page_table(mfn_t gmfn)
{
    const struct page_info *page;
    struct domain *owner;
    unsigned long type_info;

    if ( !mfn_valid(gmfn) )
        return 0;

    page = mfn_to_page(gmfn);
    owner = page_get_owner(page);
    if ( owner && shadow_mode_refcounts(owner)
         && (page->count_info & PGC_shadowed_pt) )
        return 1;

    type_info = page->u.inuse.type_info & PGT_type_mask;
    return type_info && (type_info <= PGT_l4_page_table);
}

/**************************************************************************/
/* Shadow-page refcounting. */

void sh_destroy_shadow(struct domain *d, mfn_t smfn);

/* Increase the refcount of a shadow page.  Arguments are the mfn to refcount,
 * and the physical address of the shadow entry that holds the ref (or zero
 * if the ref is held by something else).
 * Returns 0 for failure, 1 for success. */
static inline int sh_get_ref(struct domain *d, mfn_t smfn, paddr_t entry_pa)
{
    unsigned long x, nx;
    struct page_info *sp = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(sp->u.sh.head);

    x = sp->u.sh.count;
    nx = x + 1;

    if ( unlikely(nx >= (1UL << PAGE_SH_REFCOUNT_WIDTH)) )
    {
        SHADOW_PRINTK("shadow ref overflow, gmfn=%lx smfn=%lx\n",
                       __backpointer(sp), mfn_x(smfn));
        return 0;
    }

    /* Guarded by the paging lock, so no need for atomic update */
    sp->u.sh.count = nx;

    /* We remember the first shadow entry that points to each shadow. */
    if ( !sp->up && sh_type_has_up_pointer(d, sp->u.sh.type) )
        sp->up = entry_pa;

    return 1;
}


/* Decrease the refcount of a shadow page.  As for get_ref, takes the
 * physical address of the shadow entry that held this reference. */
static inline void sh_put_ref(struct domain *d, mfn_t smfn, paddr_t entry_pa)
{
    unsigned long x, nx;
    struct page_info *sp = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(sp->u.sh.head);
    ASSERT(!(sp->count_info & PGC_count_mask));

    /* If this is the entry in the up-pointer, remove it */
    if ( sp->up == entry_pa )
    {
        ASSERT(!entry_pa || sh_type_has_up_pointer(d, sp->u.sh.type));
        sp->up = 0;
    }

    x = sp->u.sh.count;
    nx = x - 1;

    if ( unlikely(x == 0) )
    {
        printk(XENLOG_ERR "shadow ref underflow, smfn=%"PRI_mfn" oc=%#lx t=%#x\n",
               mfn_x(smfn), sp->u.sh.count + 0UL, sp->u.sh.type);
        BUG();
    }

    /* Guarded by the paging lock, so no need for atomic update */
    sp->u.sh.count = nx;

    if ( unlikely(nx == 0) )
        sh_destroy_shadow(d, smfn);
}


/* Walk the list of pinned shadows, from the tail forwards,
 * skipping the non-head-page entries */
static inline struct page_info *
prev_pinned_shadow(struct page_info *page,
                   const struct domain *d)
{
    struct page_info *p;
    const struct page_list_head *pin_list;

    pin_list = &d->arch.paging.shadow.pinned_shadows;

    if ( page_list_empty(pin_list) || page == page_list_first(pin_list) )
        return NULL;

    if ( page == NULL ) /* If no current place, start at the tail */
        p = page_list_last(pin_list);
    else
        p = page_list_prev(page, pin_list);
    /* Skip over the non-tail parts of multi-page shadows */
    if ( p && p->u.sh.type == SH_type_l2_32_shadow )
    {
        p = page_list_prev(p, pin_list);
        ASSERT(p && p->u.sh.type == SH_type_l2_32_shadow);
        p = page_list_prev(p, pin_list);
        ASSERT(p && p->u.sh.type == SH_type_l2_32_shadow);
        p = page_list_prev(p, pin_list);
        ASSERT(p && p->u.sh.type == SH_type_l2_32_shadow);
    }
    ASSERT(!p || p->u.sh.head);
    return p;
}

#define foreach_pinned_shadow(dom, pos, tmp)                    \
    for ( pos = prev_pinned_shadow(NULL, (dom));                \
          pos ? (tmp = prev_pinned_shadow(pos, (dom)), 1) : 0;  \
          pos = tmp )

/*
 * Pin a shadow page: take an extra refcount, set the pin bit,
 * and put the shadow at the head of the list of pinned shadows.
 * Returns false for failure, true for success.
 */
static inline bool sh_pin(struct domain *d, mfn_t smfn)
{
    struct page_info *sp[4];
    struct page_list_head *pin_list;
    unsigned int i, pages;
    bool already_pinned;

    ASSERT(mfn_valid(smfn));
    sp[0] = mfn_to_page(smfn);
    pages = shadow_size(sp[0]->u.sh.type);
    already_pinned = sp[0]->u.sh.pinned;
    ASSERT(sh_type_is_pinnable(d, sp[0]->u.sh.type));
    ASSERT(sp[0]->u.sh.head);

    pin_list = &d->arch.paging.shadow.pinned_shadows;
    if ( already_pinned && sp[0] == page_list_first(pin_list) )
        return true;

    /* Treat the up-to-four pages of the shadow as a unit in the list ops */
    for ( i = 1; i < pages; i++ )
    {
        sp[i] = page_list_next(sp[i - 1], pin_list);
        ASSERT(sp[i]->u.sh.type == sp[0]->u.sh.type);
        ASSERT(!sp[i]->u.sh.head);
    }

    if ( already_pinned )
    {
        /* Take it out of the pinned-list so it can go at the front */
        for ( i = 0; i < pages; i++ )
            page_list_del(sp[i], pin_list);
    }
    else
    {
        /* Not pinned: pin it! */
        if ( !sh_get_ref(d, smfn, 0) )
            return false;
        sp[0]->u.sh.pinned = 1;
    }

    /* Put it at the head of the list of pinned shadows */
    for ( i = pages; i > 0; i-- )
        page_list_add(sp[i - 1], pin_list);

    return true;
}

/* Unpin a shadow page: unset the pin bit, take the shadow off the list
 * of pinned shadows, and release the extra ref. */
static inline void sh_unpin(struct domain *d, mfn_t smfn)
{
    struct page_list_head tmp_list, *pin_list;
    struct page_info *sp, *next;
    unsigned int i, head_type, sz;

    ASSERT(mfn_valid(smfn));
    sp = mfn_to_page(smfn);
    head_type = sp->u.sh.type;
    ASSERT(sh_type_is_pinnable(d, sp->u.sh.type));
    ASSERT(sp->u.sh.head);

    if ( !sp->u.sh.pinned )
        return;
    sp->u.sh.pinned = 0;

    sz = shadow_size(head_type);

    /*
     * Cut the sub-list out of the list of pinned shadows, stitching
     * multi-page shadows back into a list fragment of their own.
     */
    pin_list = &d->arch.paging.shadow.pinned_shadows;
    INIT_PAGE_LIST_HEAD(&tmp_list);
    for ( i = 0; i < sz; i++ )
    {
        ASSERT(sp->u.sh.type == head_type);
        ASSERT(!i || !sp->u.sh.head);
        next = page_list_next(sp, pin_list);
        page_list_del(sp, pin_list);
        if ( sz > 1 )
            page_list_add_tail(sp, &tmp_list);
        else if ( head_type == SH_type_l3_64_shadow )
            sp->up = 0;
        sp = next;
    }

    if ( sz > 1 )
        sh_terminate_list(&tmp_list);

    sh_put_ref(d, smfn, 0);
}


/**************************************************************************/
/* Hash table mapping from guest pagetables to shadows
 *
 * Normal case: maps the mfn of a guest page to the mfn of its shadow page.
 * FL1's:       see multi.c.
 */

static inline mfn_t
get_shadow_status(struct domain *d, mfn_t gmfn, u32 shadow_type)
/* Look for shadows in the hash table */
{
    mfn_t smfn = shadow_hash_lookup(d, mfn_x(gmfn), shadow_type);

    ASSERT(mfn_eq(smfn, INVALID_MFN) || mfn_to_page(smfn)->u.sh.head);
    perfc_incr(shadow_get_shadow_status);

    return smfn;
}

static inline void
set_shadow_status(struct domain *d, mfn_t gmfn, u32 shadow_type, mfn_t smfn)
/* Put a shadow into the hash table */
{
    SHADOW_PRINTK("d%d gmfn=%lx, type=%08x, smfn=%lx\n",
                  d->domain_id, mfn_x(gmfn), shadow_type, mfn_x(smfn));

    ASSERT(mfn_to_page(smfn)->u.sh.head);

    /* 32-bit PV guests don't own their l4 pages so can't get_page them */
    if ( (shadow_type != SH_type_l4_64_shadow || !is_pv_32bit_domain(d)) &&
         !get_page(mfn_to_page(gmfn), d) )
    {
        printk(XENLOG_G_ERR "%pd: cannot get page for MFN %" PRI_mfn "\n",
               d, mfn_x(gmfn));
        domain_crash(d);
        return;
    }

    shadow_hash_insert(d, mfn_x(gmfn), shadow_type, smfn);
}

static inline void
delete_shadow_status(struct domain *d, mfn_t gmfn, u32 shadow_type, mfn_t smfn)
/* Remove a shadow from the hash table */
{
    SHADOW_PRINTK("d%d gmfn=%"PRI_mfn", type=%08x, smfn=%"PRI_mfn"\n",
                  d->domain_id, mfn_x(gmfn), shadow_type, mfn_x(smfn));
    ASSERT(mfn_to_page(smfn)->u.sh.head);
    if ( shadow_hash_delete(d, mfn_x(gmfn), shadow_type, smfn) &&
         /* 32-bit PV guests don't own their l4 pages; see set_shadow_status */
         (shadow_type != SH_type_l4_64_shadow || !is_pv_32bit_domain(d)) )
        put_page(mfn_to_page(gmfn));
}


/**************************************************************************/
/* PTE-write emulation. */

struct sh_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;

    /* Cache of up to 31 bytes of instruction. */
    uint8_t insn_buf[31];
    uint8_t insn_buf_bytes;
    unsigned long insn_buf_eip;

    unsigned int pte_size;

    /* Cache of segment registers already gathered for this emulation. */
    unsigned int valid_seg_regs;
    struct segment_register seg_reg[6];

    /* MFNs being written to in write/cmpxchg callbacks */
    mfn_t mfn[2];

#if (SHADOW_OPTIMIZATIONS & SHOPT_SKIP_VERIFY)
    /* Special case for avoiding having to verify writes: remember
     * whether the old value had its low bit (_PAGE_PRESENT) clear. */
    bool low_bit_was_clear;
#endif
};

const struct x86_emulate_ops *shadow_init_emulation(
    struct sh_emulate_ctxt *sh_ctxt, struct cpu_user_regs *regs,
    unsigned int pte_size);
void shadow_continue_emulation(
    struct sh_emulate_ctxt *sh_ctxt, struct cpu_user_regs *regs);

/* Stop counting towards early unshadows, as we've seen a real page fault */
static inline void sh_reset_early_unshadow(struct vcpu *v)
{
#if SHADOW_OPTIMIZATIONS & SHOPT_EARLY_UNSHADOW
    v->arch.paging.shadow.last_emulated_mfn_for_unshadow = mfn_x(INVALID_MFN);
#endif
}

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
/**************************************************************************/
/* Virtual TLB entries
 *
 * We keep a cache of virtual-to-physical translations that we have seen
 * since the last TLB flush.  This is safe to use for frame translations,
 * but callers need to re-check the actual guest tables if the lookup fails.
 *
 * Lookups and updates are protected by a per-vTLB (and hence per-vcpu)
 * lock.  This lock is held *only* while reading or writing the table,
 * so it is safe to take in any non-interrupt context.  Most lookups
 * happen with v==current, so we expect contention to be low.
 */

#define VTLB_ENTRIES 13

struct shadow_vtlb {
    unsigned long page_number;      /* Guest virtual address >> PAGE_SHIFT  */
    unsigned long frame_number;     /* Guest physical address >> PAGE_SHIFT */
    uint32_t pfec;     /* PF error code of the lookup that filled this
                        * entry.  A pfec of zero means the slot is empty
                        * (since that would require us to re-try anyway) */
};

/* Call whenever the guest flushes hit actual TLB */
static inline void vtlb_flush(struct vcpu *v)
{
    spin_lock(&v->arch.paging.vtlb_lock);
    memset(v->arch.paging.vtlb, 0, VTLB_ENTRIES * sizeof (struct shadow_vtlb));
    spin_unlock(&v->arch.paging.vtlb_lock);
}

static inline int vtlb_hash(unsigned long page_number)
{
    return page_number % VTLB_ENTRIES;
}

/* Put a translation into the vTLB, potentially clobbering an old one */
static inline void vtlb_insert(struct vcpu *v, unsigned long page,
                               unsigned long frame, uint32_t pfec)
{
    struct shadow_vtlb entry =
        { .page_number = page, .frame_number = frame, .pfec = pfec };
    spin_lock(&v->arch.paging.vtlb_lock);
    v->arch.paging.vtlb[vtlb_hash(page)] = entry;
    spin_unlock(&v->arch.paging.vtlb_lock);
}

/* Look a translation up in the vTLB.  Returns INVALID_GFN if not found. */
static inline unsigned long vtlb_lookup(struct vcpu *v,
                                        unsigned long va, uint32_t pfec)
{
    unsigned long page_number = va >> PAGE_SHIFT;
    unsigned long frame_number = gfn_x(INVALID_GFN);
    int i = vtlb_hash(page_number);

    spin_lock(&v->arch.paging.vtlb_lock);
    if ( v->arch.paging.vtlb[i].pfec != 0
         && v->arch.paging.vtlb[i].page_number == page_number
         /* Any successful walk that had at least these pfec bits is OK */
         && (v->arch.paging.vtlb[i].pfec & pfec) == pfec )
    {
        frame_number = v->arch.paging.vtlb[i].frame_number;
    }
    spin_unlock(&v->arch.paging.vtlb_lock);
    return frame_number;
}
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

static inline int sh_check_page_has_no_refs(struct page_info *page)
{
    unsigned long count = read_atomic(&page->count_info);
    return ( (count & PGC_count_mask) ==
             ((count & PGC_allocated) ? 1 : 0) );
}

/* Flush the TLB of the selected vCPUs. */
bool cf_check shadow_flush_tlb(const unsigned long *vcpu_bitmap);

#endif /* _XEN_SHADOW_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
