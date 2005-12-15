/******************************************************************************
 * include/asm-x86/shadow.h
 * 
 * Copyright (c) 2005 Michael A Fetterman
 * Based on an earlier implementation by Ian Pratt et al
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

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/processor.h>
#include <asm/vmx.h>
#include <public/dom0_ops.h>
#include <asm/shadow_public.h>
#include <asm/page-guest32.h>
#include <asm/shadow_ops.h>

/* Shadow PT operation mode : shadow-mode variable in arch_domain. */

#define SHM_enable    (1<<0) /* we're in one of the shadow modes */
#define SHM_refcounts (1<<1) /* refcounts based on shadow tables instead of
                                guest tables */
#define SHM_write_all (1<<2) /* allow write access to all guest pt pages,
                                regardless of pte write permissions */
#define SHM_log_dirty (1<<3) /* enable log dirty mode */
#define SHM_translate (1<<4) /* Xen does p2m translation, not guest */
#define SHM_external  (1<<5) /* Xen does not steal address space from the
                                domain for its own booking; requires VT or
                                similar mechanisms */
#define SHM_wr_pt_pte (1<<6) /* guest allowed to set PAGE_RW bit in PTEs which
                                point to page table pages. */

#define shadow_mode_enabled(_d)   ((_d)->arch.shadow_mode)
#define shadow_mode_refcounts(_d) ((_d)->arch.shadow_mode & SHM_refcounts)
#define shadow_mode_write_l1(_d)  (VM_ASSIST(_d, VMASST_TYPE_writable_pagetables))
#define shadow_mode_write_all(_d) ((_d)->arch.shadow_mode & SHM_write_all)
#define shadow_mode_log_dirty(_d) ((_d)->arch.shadow_mode & SHM_log_dirty)
#define shadow_mode_translate(_d) ((_d)->arch.shadow_mode & SHM_translate)
#define shadow_mode_external(_d)  ((_d)->arch.shadow_mode & SHM_external)
#define shadow_mode_wr_pt_pte(_d) ((_d)->arch.shadow_mode & SHM_wr_pt_pte)

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define __shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START + \
     (SH_LINEAR_PT_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))
#define shadow_linear_l2_table(_v) ((_v)->arch.shadow_vtable)

// easy access to the hl2 table (for translated but not external modes only)
#define __linear_hl2_table ((l1_pgentry_t *)(LINEAR_PT_VIRT_START + \
     (PERDOMAIN_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))

/*
 * For now we use the per-domain BIGLOCK rather than a shadow-specific lock.
 * We usually have the BIGLOCK already acquired anyway, so this is unlikely
 * to cause much unnecessary extra serialisation. Also it's a recursive
 * lock, and there are some code paths containing nested shadow_lock().
 * The #if0'ed code below is therefore broken until such nesting is removed.
 */
#if 0
#define shadow_lock_init(_d)                    \
    spin_lock_init(&(_d)->arch.shadow_lock)
#define shadow_lock_is_acquired(_d)             \
    spin_is_locked(&(_d)->arch.shadow_lock)
#define shadow_lock(_d)                         \
do {                                            \
    ASSERT(!shadow_lock_is_acquired(_d));       \
    spin_lock(&(_d)->arch.shadow_lock);         \
} while (0)
#define shadow_unlock(_d)                       \
do {                                            \
    ASSERT(!shadow_lock_is_acquired(_d));       \
    spin_unlock(&(_d)->arch.shadow_lock);       \
} while (0)
#else
#define shadow_lock_init(_d)                    \
    ((_d)->arch.shadow_nest = 0)
#define shadow_lock_is_acquired(_d)             \
    (spin_is_locked(&(_d)->big_lock) && ((_d)->arch.shadow_nest != 0))
#define shadow_lock(_d)                         \
do {                                            \
    LOCK_BIGLOCK(_d);                           \
    (_d)->arch.shadow_nest++;                   \
} while (0)
#define shadow_unlock(_d)                       \
do {                                            \
    ASSERT(shadow_lock_is_acquired(_d));        \
    (_d)->arch.shadow_nest--;                   \
    UNLOCK_BIGLOCK(_d);                         \
} while (0)
#endif

#define SHADOW_ENCODE_MIN_MAX(_min, _max) ((((GUEST_L1_PAGETABLE_ENTRIES - 1) - (_max)) << 16) | (_min))
#define SHADOW_MIN(_encoded) ((_encoded) & ((1u<<16) - 1))
#define SHADOW_MAX(_encoded) ((GUEST_L1_PAGETABLE_ENTRIES - 1) - ((_encoded) >> 16))

extern void shadow_mode_init(void);
extern int shadow_mode_control(struct domain *p, dom0_shadow_control_t *sc);
extern int shadow_fault(unsigned long va, struct cpu_user_regs *regs);
extern int shadow_mode_enable(struct domain *p, unsigned int mode);
extern void shadow_invlpg(struct vcpu *, unsigned long);
extern struct out_of_sync_entry *shadow_mark_mfn_out_of_sync(
    struct vcpu *v, unsigned long gpfn, unsigned long mfn);
extern void free_monitor_pagetable(struct vcpu *v);
extern void __shadow_sync_all(struct domain *d);
extern int __shadow_out_of_sync(struct vcpu *v, unsigned long va);
extern int set_p2m_entry(
    struct domain *d, unsigned long pfn, unsigned long mfn,
    struct domain_mmap_cache *l2cache,
    struct domain_mmap_cache *l1cache);
extern void remove_shadow(struct domain *d, unsigned long gpfn, u32 stype);

extern void shadow_l1_normal_pt_update(struct domain *d,
                                       physaddr_t pa, l1_pgentry_t l1e,
                                       struct domain_mmap_cache *cache);
extern void shadow_l2_normal_pt_update(struct domain *d,
                                       physaddr_t pa, l2_pgentry_t l2e,
                                       struct domain_mmap_cache *cache);
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/page-guest32.h>
/*
 * va_mask cannot be used because it's used by the shadow hash.
 * Use the score area for for now.
 */
#define is_xen_l2_slot(t,s)                                                    \
    ( ((((t) & PGT_score_mask) >> PGT_score_shift) == 3) &&                    \
      ((s) >= (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES - 1))) )

extern unsigned long gva_to_gpa(unsigned long gva);
extern void shadow_l3_normal_pt_update(struct domain *d,
                                       physaddr_t pa, l3_pgentry_t l3e,
                                       struct domain_mmap_cache *cache);
#endif
#if CONFIG_PAGING_LEVELS >= 4
extern void shadow_l4_normal_pt_update(struct domain *d,
                                       physaddr_t pa, l4_pgentry_t l4e,
                                       struct domain_mmap_cache *cache);
#endif
extern int shadow_do_update_va_mapping(unsigned long va,
                                       l1_pgentry_t val,
                                       struct vcpu *v);


static inline unsigned long __shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype);

#if CONFIG_PAGING_LEVELS <= 2
static inline void update_hl2e(struct vcpu *v, unsigned long va);
#endif

extern void vmx_shadow_clear_state(struct domain *);

static inline int page_is_page_table(struct pfn_info *page)
{
    struct domain *owner = page_get_owner(page);
    u32 type_info;

    if ( owner && shadow_mode_refcounts(owner) )
        return page->count_info & PGC_page_table;

    type_info = page->u.inuse.type_info & PGT_type_mask;
    return type_info && (type_info <= PGT_l4_page_table);
}

static inline int mfn_is_page_table(unsigned long mfn)
{
    if ( !pfn_valid(mfn) )
        return 0;

    return page_is_page_table(pfn_to_page(mfn));
}

static inline int page_out_of_sync(struct pfn_info *page)
{
    return page->count_info & PGC_out_of_sync;
}

static inline int mfn_out_of_sync(unsigned long mfn)
{
    if ( !pfn_valid(mfn) )
        return 0;

    return page_out_of_sync(pfn_to_page(mfn));
}


/************************************************************************/

static void inline
__shadow_sync_mfn(struct domain *d, unsigned long mfn)
{
    if ( d->arch.out_of_sync )
    {
        // XXX - could be smarter
        //
        __shadow_sync_all(d);
    }
}

static void inline
__shadow_sync_va(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;

    if ( d->arch.out_of_sync && __shadow_out_of_sync(v, va) )
    {
        perfc_incrc(shadow_sync_va);

        // XXX - could be smarter
        //
        __shadow_sync_all(v->domain);
    }
#if CONFIG_PAGING_LEVELS <= 2
    // Also make sure the HL2 is up-to-date for this address.
    //
    if ( unlikely(shadow_mode_translate(v->domain)) )
        update_hl2e(v, va);
#endif
}

static void inline
shadow_sync_all(struct domain *d)
{
    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_lock(d);

        if ( d->arch.out_of_sync )
            __shadow_sync_all(d);

        ASSERT(d->arch.out_of_sync == NULL);

        shadow_unlock(d);
    }
}

// SMP BUG: This routine can't ever be used properly in an SMP context.
//          It should be something like get_shadow_and_sync_va().
//          This probably shouldn't exist.
//
static void inline
shadow_sync_va(struct vcpu *v, unsigned long gva)
{
    struct domain *d = v->domain;
    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_lock(d);
        __shadow_sync_va(v, gva);
        shadow_unlock(d);
    }
}

extern void __shadow_mode_disable(struct domain *d);
static inline void shadow_mode_disable(struct domain *d)
{
    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_lock(d);
        __shadow_mode_disable(d);
        shadow_unlock(d);
    }
}

/************************************************************************/

#define __mfn_to_gpfn(_d, mfn)                         \
    ( (shadow_mode_translate(_d))                      \
      ? get_pfn_from_mfn(mfn)                          \
      : (mfn) )

#define __gpfn_to_mfn(_d, gpfn)                        \
    ({                                                 \
        unlikely(shadow_mode_translate(_d))            \
        ? (likely(current->domain == (_d))             \
           ? get_mfn_from_pfn(gpfn)                    \
           : get_mfn_from_pfn_foreign(_d, gpfn))       \
        : (gpfn);                                      \
    })

extern unsigned long get_mfn_from_pfn_foreign(
    struct domain *d, unsigned long gpfn);

/************************************************************************/

struct shadow_status {
    struct shadow_status *next;   /* Pull-to-front list per hash bucket. */
    unsigned long gpfn_and_flags; /* Guest pfn plus flags. */
    unsigned long smfn;           /* Shadow mfn.           */
};

#define shadow_ht_extra_size 128
#define shadow_ht_buckets    256

struct out_of_sync_entry {
    struct out_of_sync_entry *next;
    struct vcpu   *v;
    unsigned long gpfn;    /* why is this here? */
    unsigned long gmfn;
    unsigned long snapshot_mfn;
    physaddr_t writable_pl1e; /* NB: this is a machine address */
    unsigned long va;
};

#define out_of_sync_extra_size 127

#define SHADOW_SNAPSHOT_ELSEWHERE (-1L)

/************************************************************************/
#define SHADOW_DEBUG 0
#define SHADOW_VERBOSE_DEBUG 0
#define SHADOW_VVERBOSE_DEBUG 0
#define SHADOW_VVVERBOSE_DEBUG 0
#define SHADOW_HASH_DEBUG 0
#define FULLSHADOW_DEBUG 0

#if SHADOW_DEBUG
extern int shadow_status_noswap;
#define SHADOW_REFLECTS_SNAPSHOT _PAGE_AVAIL0
#endif

#if SHADOW_VERBOSE_DEBUG
#define SH_LOG(_f, _a...)                                               \
    printk("DOM%uP%u: SH_LOG(%d): " _f "\n",                            \
       current->domain->domain_id , current->processor, __LINE__ , ## _a )
#define SH_VLOG(_f, _a...)                                              \
    printk("DOM%uP%u: SH_VLOG(%d): " _f "\n",                           \
           current->domain->domain_id, current->processor, __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) ((void)0)
#define SH_VLOG(_f, _a...) ((void)0)
#endif

#if SHADOW_VVERBOSE_DEBUG
#define SH_VVLOG(_f, _a...)                                             \
    printk("DOM%uP%u: SH_VVLOG(%d): " _f "\n",                          \
           current->domain->domain_id, current->processor, __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...) ((void)0)
#endif

#if SHADOW_VVVERBOSE_DEBUG
#define SH_VVVLOG(_f, _a...)                                            \
    printk("DOM%uP%u: SH_VVVLOG(%d): " _f "\n",                         \
           current->domain->domain_id, current->processor, __LINE__ , ## _a )
#else
#define SH_VVVLOG(_f, _a...) ((void)0)
#endif

#if FULLSHADOW_DEBUG
#define FSH_LOG(_f, _a...)                                              \
    printk("DOM%uP%u: FSH_LOG(%d): " _f "\n",                           \
           current->domain->domain_id, current->processor, __LINE__ , ## _a )
#else
#define FSH_LOG(_f, _a...) ((void)0)
#endif


/************************************************************************/

static inline int
shadow_get_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    l1_pgentry_t nl1e;
    int res;
    unsigned long mfn;
    struct domain *owner;

    ASSERT(l1e_get_flags(l1e) & _PAGE_PRESENT);

    if ( !shadow_mode_refcounts(d) )
        return 1;

    nl1e = l1e;
    l1e_remove_flags(nl1e, _PAGE_GLOBAL);

    if ( unlikely(l1e_get_flags(nl1e) & L1_DISALLOW_MASK) )
        return 0;

    res = get_page_from_l1e(nl1e, d);

    if ( unlikely(!res) && IS_PRIV(d) && !shadow_mode_translate(d) &&
         !(l1e_get_flags(nl1e) & L1_DISALLOW_MASK) &&
         (mfn = l1e_get_pfn(nl1e)) &&
         pfn_valid(mfn) &&
         (owner = page_get_owner(pfn_to_page(mfn))) &&
         (d != owner) )
    {
        res = get_page_from_l1e(nl1e, owner);
        printk("tried to map mfn %lx from domain %d into shadow page tables "
               "of domain %d; %s\n",
               mfn, owner->domain_id, d->domain_id,
               res ? "success" : "failed");
    }

    if ( unlikely(!res) )
    {
        perfc_incrc(shadow_get_page_fail);
        FSH_LOG("%s failed to get ref l1e=%" PRIpte "\n",
                __func__, l1e_get_intpte(l1e));
    }

    return res;
}

static inline void
shadow_put_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    if ( !shadow_mode_refcounts(d) )
        return;

    put_page_from_l1e(l1e, d);
}

static inline void
shadow_put_page_type(struct domain *d, struct pfn_info *page)
{
    if ( !shadow_mode_refcounts(d) )
        return;

    put_page_type(page);
}

static inline int shadow_get_page(struct domain *d,
                                  struct pfn_info *page,
                                  struct domain *owner)
{
    if ( !shadow_mode_refcounts(d) )
        return 1;
    return get_page(page, owner);
}

static inline void shadow_put_page(struct domain *d,
                                   struct pfn_info *page)
{
    if ( !shadow_mode_refcounts(d) )
        return;
    put_page(page);
}

/************************************************************************/

static inline void __mark_dirty(struct domain *d, unsigned long mfn)
{
    unsigned long pfn;

    ASSERT(shadow_lock_is_acquired(d));

    if ( likely(!shadow_mode_log_dirty(d)) || !VALID_MFN(mfn) )
        return;

    ASSERT(d->arch.shadow_dirty_bitmap != NULL);

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_pfn_from_mfn(mfn);

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(IS_INVALID_M2P_ENTRY(pfn)) )
        return;

    /* N.B. Can use non-atomic TAS because protected by shadow_lock. */
    if ( likely(pfn < d->arch.shadow_dirty_bitmap_size) &&
         !__test_and_set_bit(pfn, d->arch.shadow_dirty_bitmap) )
    {
        d->arch.shadow_dirty_count++;
    }
#ifndef NDEBUG
    else if ( mfn < max_page )
    {
        SH_VLOG("mark_dirty OOR! mfn=%x pfn=%lx max=%x (dom %p)",
               mfn, pfn, d->arch.shadow_dirty_bitmap_size, d);
        SH_VLOG("dom=%p caf=%08x taf=%" PRtype_info, 
               page_get_owner(&frame_table[mfn]),
               frame_table[mfn].count_info, 
               frame_table[mfn].u.inuse.type_info );
    }
#endif
}


static inline void mark_dirty(struct domain *d, unsigned int mfn)
{
    if ( unlikely(shadow_mode_log_dirty(d)) )
    {
        shadow_lock(d);
        __mark_dirty(d, mfn);
        shadow_unlock(d);
    }
}


/************************************************************************/
#if CONFIG_PAGING_LEVELS <= 2
static inline void
__shadow_get_l2e(
    struct vcpu *v, unsigned long va, l2_pgentry_t *psl2e)
{
    ASSERT(shadow_mode_enabled(v->domain));

    *psl2e = v->arch.shadow_vtable[l2_table_offset(va)];
}

static inline void
__shadow_set_l2e(
    struct vcpu *v, unsigned long va, l2_pgentry_t value)
{
    ASSERT(shadow_mode_enabled(v->domain));

    v->arch.shadow_vtable[l2_table_offset(va)] = value;
}

static inline void
__guest_get_l2e(
    struct vcpu *v, unsigned long va, l2_pgentry_t *pl2e)
{
    *pl2e = v->arch.guest_vtable[l2_table_offset(va)];
}

static inline void
__guest_set_l2e(
    struct vcpu *v, unsigned long va, l2_pgentry_t value)
{
    struct domain *d = v->domain;

    v->arch.guest_vtable[l2_table_offset(va)] = value;

    if ( unlikely(shadow_mode_translate(d)) )
        update_hl2e(v, va);

    __mark_dirty(d, pagetable_get_pfn(v->arch.guest_table));
}

static inline void
update_hl2e(struct vcpu *v, unsigned long va)
{
    int index = l2_table_offset(va);
    unsigned long mfn;
    l2_pgentry_t gl2e = v->arch.guest_vtable[index];
    l1_pgentry_t old_hl2e, new_hl2e;
    int need_flush = 0;

    ASSERT(shadow_mode_translate(v->domain));

    old_hl2e = v->arch.hl2_vtable[index];

    if ( (l2e_get_flags(gl2e) & _PAGE_PRESENT) &&
         VALID_MFN(mfn = get_mfn_from_pfn(l2e_get_pfn(gl2e))) )
        new_hl2e = l1e_from_pfn(mfn, __PAGE_HYPERVISOR);
    else
        new_hl2e = l1e_empty();

    // only do the ref counting if something has changed.
    //
    if ( (l1e_has_changed(old_hl2e, new_hl2e, PAGE_FLAG_MASK)) )
    {
        if ( (l1e_get_flags(new_hl2e) & _PAGE_PRESENT) &&
             !shadow_get_page(v->domain, pfn_to_page(l1e_get_pfn(new_hl2e)),
                              v->domain) )
            new_hl2e = l1e_empty();
        if ( l1e_get_flags(old_hl2e) & _PAGE_PRESENT )
        {
            shadow_put_page(v->domain, pfn_to_page(l1e_get_pfn(old_hl2e)));
            need_flush = 1;
        }

        v->arch.hl2_vtable[l2_table_offset(va)] = new_hl2e;

        if ( need_flush )
        {
            perfc_incrc(update_hl2e_invlpg);
            flush_tlb_one_mask(v->domain->cpumask,
                               &linear_pg_table[l1_linear_offset(va)]);
        }
    }
}

static inline void shadow_drop_references(
    struct domain *d, struct pfn_info *page)
{
    if ( likely(!shadow_mode_refcounts(d)) ||
         ((page->u.inuse.type_info & PGT_count_mask) == 0) )
        return;

    /* XXX This needs more thought... */
    printk("%s: needing to call shadow_remove_all_access for mfn=%lx\n",
           __func__, page_to_pfn(page));
    printk("Before: mfn=%lx c=%08x t=%" PRtype_info "\n", page_to_pfn(page),
           page->count_info, page->u.inuse.type_info);

    shadow_lock(d);
    shadow_remove_all_access(d, page_to_pfn(page));
    shadow_unlock(d);

    printk("After:  mfn=%lx c=%08x t=%" PRtype_info "\n", page_to_pfn(page),
           page->count_info, page->u.inuse.type_info);
}

/* XXX Needs more thought. Neither pretty nor fast: a place holder. */
static inline void shadow_sync_and_drop_references(
    struct domain *d, struct pfn_info *page)
{
    if ( likely(!shadow_mode_refcounts(d)) )
        return;

    shadow_lock(d);

    if ( page_out_of_sync(page) )
        __shadow_sync_mfn(d, page_to_pfn(page));

    shadow_remove_all_access(d, page_to_pfn(page));

    shadow_unlock(d);
}
#endif

/************************************************************************/

/*
 * Add another shadow reference to smfn.
 */
static inline int
get_shadow_ref(unsigned long smfn)
{
    u32 x, nx;

    ASSERT(pfn_valid(smfn));

    x = frame_table[smfn].count_info;
    nx = x + 1;

    if ( unlikely(nx == 0) )
    {
        printk("get_shadow_ref overflow, gmfn=%" PRtype_info  " smfn=%lx\n",
               frame_table[smfn].u.inuse.type_info & PGT_mfn_mask,
               smfn);
        BUG();
    }
    
    // Guarded by the shadow lock...
    //
    frame_table[smfn].count_info = nx;

    return 1;
}

extern void free_shadow_page(unsigned long smfn);

/*
 * Drop a shadow reference to smfn.
 */
static inline void
put_shadow_ref(unsigned long smfn)
{
    u32 x, nx;

    ASSERT(pfn_valid(smfn));

    x = frame_table[smfn].count_info;
    nx = x - 1;

    if ( unlikely(x == 0) )
    {
        printk("put_shadow_ref underflow, smfn=%lx oc=%08x t=%" 
               PRtype_info "\n",
               smfn,
               frame_table[smfn].count_info,
               frame_table[smfn].u.inuse.type_info);
        BUG();
    }

    // Guarded by the shadow lock...
    //
    frame_table[smfn].count_info = nx;

    if ( unlikely(nx == 0) )
    {
        free_shadow_page(smfn);
    }
}

static inline void
shadow_pin(unsigned long smfn)
{
    ASSERT( !(frame_table[smfn].u.inuse.type_info & PGT_pinned) );

    frame_table[smfn].u.inuse.type_info |= PGT_pinned;
    if ( unlikely(!get_shadow_ref(smfn)) )
        BUG();
}

static inline void
shadow_unpin(unsigned long smfn)
{
    ASSERT( (frame_table[smfn].u.inuse.type_info & PGT_pinned) );

    frame_table[smfn].u.inuse.type_info &= ~PGT_pinned;
    put_shadow_ref(smfn);
}

/*
 * SMP issue. The following code assumes the shadow lock is held. Re-visit
 * when working on finer-gained locks for shadow.
 */
static inline void set_guest_back_ptr(
    struct domain *d, l1_pgentry_t spte, unsigned long smfn, unsigned int index)
{
    if ( shadow_mode_external(d) ) {
        unsigned long gmfn;

        ASSERT(shadow_lock_is_acquired(d));
        gmfn = l1e_get_pfn(spte);
        frame_table[gmfn].tlbflush_timestamp = smfn;
        frame_table[gmfn].u.inuse.type_info &= ~PGT_va_mask;
        frame_table[gmfn].u.inuse.type_info |= (unsigned long) index << PGT_va_shift;
    }
}

/************************************************************************/
#if CONFIG_PAGING_LEVELS <= 2
extern void shadow_mark_va_out_of_sync(
    struct vcpu *v, unsigned long gpfn, unsigned long mfn,
    unsigned long va);

static inline int l1pte_write_fault(
    struct vcpu *v, l1_pgentry_t *gpte_p, l1_pgentry_t *spte_p,
    unsigned long va)
{
    struct domain *d = v->domain;
    l1_pgentry_t gpte = *gpte_p;
    l1_pgentry_t spte;
    unsigned long gpfn = l1e_get_pfn(gpte);
    unsigned long gmfn = __gpfn_to_mfn(d, gpfn);

    //printk("l1pte_write_fault gmfn=%lx\n", gmfn);

    if ( unlikely(!VALID_MFN(gmfn)) )
    {
        SH_VLOG("l1pte_write_fault: invalid gpfn=%lx", gpfn);
        *spte_p = l1e_empty();
        return 0;
    }

    ASSERT(l1e_get_flags(gpte) & _PAGE_RW);
    l1e_add_flags(gpte, _PAGE_DIRTY | _PAGE_ACCESSED);
    spte = l1e_from_pfn(gmfn, l1e_get_flags(gpte) & ~_PAGE_GLOBAL);

    SH_VVLOG("l1pte_write_fault: updating spte=0x%" PRIpte " gpte=0x%" PRIpte,
             l1e_get_intpte(spte), l1e_get_intpte(gpte));

    __mark_dirty(d, gmfn);

    if ( mfn_is_page_table(gmfn) )
        shadow_mark_va_out_of_sync(v, gpfn, gmfn, va);

    *gpte_p = gpte;
    *spte_p = spte;

    return 1;
}

static inline int l1pte_read_fault(
    struct domain *d, l1_pgentry_t *gpte_p, l1_pgentry_t *spte_p)
{ 
    l1_pgentry_t gpte = *gpte_p;
    l1_pgentry_t spte = *spte_p;
    unsigned long pfn = l1e_get_pfn(gpte);
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

    if ( unlikely(!VALID_MFN(mfn)) )
    {
        SH_VLOG("l1pte_read_fault: invalid gpfn=%lx", pfn);
        *spte_p = l1e_empty();
        return 0;
    }

    l1e_add_flags(gpte, _PAGE_ACCESSED);
    spte = l1e_from_pfn(mfn, l1e_get_flags(gpte) & ~_PAGE_GLOBAL);

    if ( shadow_mode_log_dirty(d) || !(l1e_get_flags(gpte) & _PAGE_DIRTY) ||
         mfn_is_page_table(mfn) )
    {
        l1e_remove_flags(spte, _PAGE_RW);
    }

    SH_VVLOG("l1pte_read_fault: updating spte=0x%" PRIpte " gpte=0x%" PRIpte,
             l1e_get_intpte(spte), l1e_get_intpte(gpte));
    *gpte_p = gpte;
    *spte_p = spte;

    return 1;
}
#endif

static inline void l1pte_propagate_from_guest(
    struct domain *d, guest_l1_pgentry_t gpte, l1_pgentry_t *spte_p)
{ 
    unsigned long mfn;
    l1_pgentry_t spte;

    spte = l1e_empty();

    if ( ((guest_l1e_get_flags(gpte) & (_PAGE_PRESENT|_PAGE_ACCESSED) ) ==
          (_PAGE_PRESENT|_PAGE_ACCESSED)) &&
         VALID_MFN(mfn = __gpfn_to_mfn(d, l1e_get_pfn(gpte))) )
    {
        spte = l1e_from_pfn(
            mfn, guest_l1e_get_flags(gpte) & ~(_PAGE_GLOBAL | _PAGE_AVAIL));

        if ( shadow_mode_log_dirty(d) ||
             !(guest_l1e_get_flags(gpte) & _PAGE_DIRTY) ||
             mfn_is_page_table(mfn) )
        {
            l1e_remove_flags(spte, _PAGE_RW);
        }
    }

    if ( l1e_get_intpte(spte) || l1e_get_intpte(gpte) )
        SH_VVVLOG("%s: gpte=%" PRIpte ", new spte=%" PRIpte,
                  __func__, l1e_get_intpte(gpte), l1e_get_intpte(spte));

    *spte_p = spte;
}

static inline void hl2e_propagate_from_guest(
    struct domain *d, l2_pgentry_t gpde, l1_pgentry_t *hl2e_p)
{
    unsigned long pfn = l2e_get_pfn(gpde);
    unsigned long mfn;
    l1_pgentry_t hl2e;
    
    hl2e = l1e_empty();

    if ( l2e_get_flags(gpde) & _PAGE_PRESENT )
    {
        mfn = __gpfn_to_mfn(d, pfn);
        if ( VALID_MFN(mfn) && (mfn < max_page) )
            hl2e = l1e_from_pfn(mfn, __PAGE_HYPERVISOR);
    }

    if ( l1e_get_intpte(hl2e) || l2e_get_intpte(gpde) )
        SH_VVLOG("%s: gpde=%" PRIpte " hl2e=%" PRIpte, __func__,
                 l2e_get_intpte(gpde), l1e_get_intpte(hl2e));

    *hl2e_p = hl2e;
}

static inline void l2pde_general(
    struct domain *d,
    guest_l2_pgentry_t *gpde_p,
    l2_pgentry_t *spde_p,
    unsigned long sl1mfn)
{
    guest_l2_pgentry_t gpde = *gpde_p;
    l2_pgentry_t spde;

    spde = l2e_empty();
    if ( (guest_l2e_get_flags(gpde) & _PAGE_PRESENT) && (sl1mfn != 0) )
    {
        spde = l2e_from_pfn(
            sl1mfn,
            (guest_l2e_get_flags(gpde) | _PAGE_RW | _PAGE_ACCESSED) & ~_PAGE_AVAIL);

        /* N.B. PDEs do not have a dirty bit. */
        guest_l2e_add_flags(gpde, _PAGE_ACCESSED);

        *gpde_p = gpde;
    } 

    if ( l2e_get_intpte(spde) || l2e_get_intpte(gpde) )
        SH_VVLOG("%s: gpde=%" PRIpte ", new spde=%" PRIpte, __func__,
                 l2e_get_intpte(gpde), l2e_get_intpte(spde));

    *spde_p = spde;
}

static inline void l2pde_propagate_from_guest(
    struct domain *d, guest_l2_pgentry_t *gpde_p, l2_pgentry_t *spde_p)
{
    guest_l2_pgentry_t gpde = *gpde_p;
    unsigned long sl1mfn = 0;

    if ( guest_l2e_get_flags(gpde) & _PAGE_PRESENT )
        sl1mfn =  __shadow_status(d, l2e_get_pfn(gpde), PGT_l1_shadow);
    l2pde_general(d, gpde_p, spde_p, sl1mfn);
}
    
/************************************************************************/

// returns true if a tlb flush is needed
//
static int inline
validate_pte_change(
    struct domain *d,
    guest_l1_pgentry_t new_pte,
    l1_pgentry_t *shadow_pte_p)
{
    l1_pgentry_t old_spte, new_spte;
    int need_flush = 0;

    perfc_incrc(validate_pte_calls);

    l1pte_propagate_from_guest(d, new_pte, &new_spte);

    if ( shadow_mode_refcounts(d) )
    {
        old_spte = *shadow_pte_p;

        if ( l1e_get_intpte(old_spte) == l1e_get_intpte(new_spte) )
        {
            // No accounting required...
            //
            perfc_incrc(validate_pte_changes1);
        }
        else if ( l1e_get_intpte(old_spte) == (l1e_get_intpte(new_spte)|_PAGE_RW) )
        {
            // Fast path for PTEs that have merely been write-protected
            // (e.g., during a Unix fork()). A strict reduction in privilege.
            //
            perfc_incrc(validate_pte_changes2);
            if ( likely(l1e_get_flags(new_spte) & _PAGE_PRESENT) )
                shadow_put_page_type(d, &frame_table[l1e_get_pfn(new_spte)]);
        }
        else if ( ((l1e_get_flags(old_spte) | l1e_get_flags(new_spte)) &
                   _PAGE_PRESENT ) &&
                  l1e_has_changed(old_spte, new_spte, _PAGE_RW | _PAGE_PRESENT) )
        {
            // only do the ref counting if something important changed.
            //
            perfc_incrc(validate_pte_changes3);

            if ( l1e_get_flags(old_spte) & _PAGE_PRESENT )
            {
                shadow_put_page_from_l1e(old_spte, d);
                need_flush = 1;
            }
            if ( (l1e_get_flags(new_spte) & _PAGE_PRESENT) &&
                 !shadow_get_page_from_l1e(new_spte, d) ) {
                new_spte = l1e_empty();
                need_flush = -1; /* need to unshadow the page */
            }
        }
        else
        {
            perfc_incrc(validate_pte_changes4);
        }
    }

    *shadow_pte_p = new_spte;

    return need_flush;
}

// returns true if a tlb flush is needed
//
static int inline
validate_hl2e_change(
    struct domain *d,
    l2_pgentry_t new_gpde,
    l1_pgentry_t *shadow_hl2e_p)
{
    l1_pgentry_t old_hl2e, new_hl2e;
    int need_flush = 0;

    perfc_incrc(validate_hl2e_calls);

    old_hl2e = *shadow_hl2e_p;
    hl2e_propagate_from_guest(d, new_gpde, &new_hl2e);

    // Only do the ref counting if something important changed.
    //
    if ( ((l1e_get_flags(old_hl2e) | l1e_get_flags(new_hl2e)) & _PAGE_PRESENT) &&
         l1e_has_changed(old_hl2e, new_hl2e, _PAGE_PRESENT) )
    {
        perfc_incrc(validate_hl2e_changes);

        if ( (l1e_get_flags(new_hl2e) & _PAGE_PRESENT) &&
             !get_page(pfn_to_page(l1e_get_pfn(new_hl2e)), d) )
            new_hl2e = l1e_empty();
        if ( l1e_get_flags(old_hl2e) & _PAGE_PRESENT )
        {
            put_page(pfn_to_page(l1e_get_pfn(old_hl2e)));
            need_flush = 1;
        }
    }

    *shadow_hl2e_p = new_hl2e;

    return need_flush;
}

// returns true if a tlb flush is needed
//
static int inline
validate_pde_change(
    struct domain *d,
    guest_l2_pgentry_t new_gpde,
    l2_pgentry_t *shadow_pde_p)
{
    l2_pgentry_t old_spde, new_spde;
    int need_flush = 0;

    perfc_incrc(validate_pde_calls);

    old_spde = *shadow_pde_p;
    l2pde_propagate_from_guest(d, &new_gpde, &new_spde);

    // Only do the ref counting if something important changed.
    //
    if ( ((l2e_get_intpte(old_spde) | l2e_get_intpte(new_spde)) & _PAGE_PRESENT) &&
         l2e_has_changed(old_spde, new_spde, _PAGE_PRESENT) )
    {
        perfc_incrc(validate_pde_changes);

        if ( (l2e_get_flags(new_spde) & _PAGE_PRESENT) &&
             !get_shadow_ref(l2e_get_pfn(new_spde)) )
            BUG();
        if ( l2e_get_flags(old_spde) & _PAGE_PRESENT )
        {
            put_shadow_ref(l2e_get_pfn(old_spde));
            need_flush = 1;
        }
    }

    *shadow_pde_p = new_spde;

    return need_flush;
}

/*********************************************************************/

#if SHADOW_HASH_DEBUG

static void shadow_audit(struct domain *d, int print)
{
    int live = 0, free = 0, j = 0, abs;
    struct shadow_status *a;

    for ( j = 0; j < shadow_ht_buckets; j++ )
    {
        a = &d->arch.shadow_ht[j];        
        if ( a->gpfn_and_flags )
        {
            live++;
            ASSERT(a->smfn);
        }
        else
            ASSERT(!a->next);

        a = a->next;
        while ( a && (live < 9999) )
        { 
            live++; 
            if ( (a->gpfn_and_flags == 0) || (a->smfn == 0) )
            {
                printk("XXX live=%d gpfn+flags=%lx sp=%lx next=%p\n",
                       live, a->gpfn_and_flags, a->smfn, a->next);
                BUG();
            }
            ASSERT(a->smfn);
            a = a->next; 
        }
        ASSERT(live < 9999);
    }

    for ( a = d->arch.shadow_ht_free; a != NULL; a = a->next )
        free++; 

    if ( print )
        printk("Xlive=%d free=%d\n", live, free);

    // BUG: this only works if there's only a single domain which is
    //      using shadow tables.
    //
    abs = (
        perfc_value(shadow_l1_pages) +
        perfc_value(shadow_l2_pages) +
        perfc_value(hl2_table_pages) +
        perfc_value(snapshot_pages) +
        perfc_value(writable_pte_predictions)
        ) - live;
#ifdef PERF_COUNTERS
    if ( (abs < -1) || (abs > 1) )
    {
        printk("live=%d free=%d l1=%d l2=%d hl2=%d snapshot=%d writable_ptes=%d\n",
               live, free,
               perfc_value(shadow_l1_pages),
               perfc_value(shadow_l2_pages),
               perfc_value(hl2_table_pages),
               perfc_value(snapshot_pages),
               perfc_value(writable_pte_predictions));
        BUG();
    }
#endif

    // XXX ought to add some code to audit the out-of-sync entries, too.
    //
}
#else
#define shadow_audit(p, print) ((void)0)
#endif


static inline struct shadow_status *hash_bucket(
    struct domain *d, unsigned int gpfn)
{
    return &d->arch.shadow_ht[gpfn % shadow_ht_buckets];
}


/*
 * N.B. This takes a guest pfn (i.e. a pfn in the guest's namespace,
 *      which, depending on full shadow mode, may or may not equal
 *      its mfn).
 *      It returns the shadow's mfn, or zero if it doesn't exist.
 */

static inline unsigned long ___shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype)
{
    struct shadow_status *p, *x, *head;
    unsigned long key = gpfn | stype;

    perfc_incrc(shadow_status_calls);

    x = head = hash_bucket(d, gpfn);
    p = NULL;

    //SH_VVLOG("lookup gpfn=%08x type=%08x bucket=%p", gpfn, stype, x);
    shadow_audit(d, 0);

    do
    {
        ASSERT(x->gpfn_and_flags || ((x == head) && (x->next == NULL)));

        if ( x->gpfn_and_flags == key )
        {
#if SHADOW_DEBUG
            if ( unlikely(shadow_status_noswap) )
                return x->smfn;
#endif
            /* Pull-to-front if 'x' isn't already the head item. */
            if ( unlikely(x != head) )
            {
                /* Delete 'x' from list and reinsert immediately after head. */
                p->next = x->next;
                x->next = head->next;
                head->next = x;

                /* Swap 'x' contents with head contents. */
                SWAP(head->gpfn_and_flags, x->gpfn_and_flags);
                SWAP(head->smfn, x->smfn);
            }
            else
            {
                perfc_incrc(shadow_status_hit_head);
            }

            //SH_VVLOG("lookup gpfn=%p => status=%p", key, head->smfn);
            return head->smfn;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    //SH_VVLOG("lookup gpfn=%p => status=0", key);
    perfc_incrc(shadow_status_miss);
    return 0;
}

static inline unsigned long __shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype)
{
    unsigned long gmfn = ((current->domain == d)
                          ? __gpfn_to_mfn(d, gpfn)
                          : INVALID_MFN);

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(gpfn == (gpfn & PGT_mfn_mask));
    ASSERT(stype && !(stype & ~PGT_type_mask));

    if ( VALID_MFN(gmfn) && (gmfn < max_page) &&
         (stype != PGT_writable_pred) &&
         ((stype == PGT_snapshot)
          ? !mfn_out_of_sync(gmfn)
          : !mfn_is_page_table(gmfn)) )
    {
        perfc_incrc(shadow_status_shortcut);
#ifndef NDEBUG
        if ( ___shadow_status(d, gpfn, stype) != 0 )
        {
            printk("d->id=%d gpfn=%lx gmfn=%lx stype=%lx c=%x t=%" PRtype_info " "
                   "mfn_out_of_sync(gmfn)=%d mfn_is_page_table(gmfn)=%d\n",
                   d->domain_id, gpfn, gmfn, stype,
                   frame_table[gmfn].count_info,
                   frame_table[gmfn].u.inuse.type_info,
                   mfn_out_of_sync(gmfn), mfn_is_page_table(gmfn));
            BUG();
        }

        // Undo the affects of the above call to ___shadow_status()'s perf
        // counters, since that call is really just part of an assertion.
        //
        perfc_decrc(shadow_status_calls);
        perfc_decrc(shadow_status_miss);
#endif
        return 0;
    }

    return ___shadow_status(d, gpfn, stype);
}

/*
 * Not clear if pull-to-front is worth while for this or not,
 * as it generally needs to scan the entire bucket anyway.
 * Much simpler without.
 *
 * Either returns PGT_none, or PGT_l{1,2,3,4}_page_table.
 */
static inline u32
shadow_max_pgtable_type(struct domain *d, unsigned long gpfn,
                        unsigned long *smfn)
{
    struct shadow_status *x;
    u32 pttype = PGT_none, type;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(gpfn == (gpfn & PGT_mfn_mask));

    perfc_incrc(shadow_max_type);

    x = hash_bucket(d, gpfn);

    while ( x && x->gpfn_and_flags )
    {
        if ( (x->gpfn_and_flags & PGT_mfn_mask) == gpfn )
        {
            type = x->gpfn_and_flags & PGT_type_mask;

            switch ( type )
            {
            case PGT_hl2_shadow:
                // Treat an HL2 as if it's an L1
                //
                type = PGT_l1_shadow;
                break;
            case PGT_snapshot:
            case PGT_writable_pred:
                // Ignore snapshots -- they don't in and of themselves constitute
                // treating a page as a page table
                //
                goto next;
            case PGT_base_page_table:
                // Early exit if we found the max possible value
                //
                return type;
            default:
                break;
            }

            if ( type > pttype )
            {
                pttype = type;
                if ( smfn )
                    *smfn = x->smfn;
            }
        }
    next:
        x = x->next;
    }

    return pttype;
}

static inline void delete_shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long gmfn, unsigned int stype)
{
    struct shadow_status *p, *x, *n, *head;
    unsigned long key = gpfn | stype;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(!(gpfn & ~PGT_mfn_mask));
    ASSERT(stype && !(stype & ~PGT_type_mask));

    head = hash_bucket(d, gpfn);

    SH_VLOG("delete gpfn=%lx t=%08x bucket=%p", gpfn, stype, head);
    shadow_audit(d, 0);

    /* Match on head item? */
    if ( head->gpfn_and_flags == key )
    {
        if ( (n = head->next) != NULL )
        {
            /* Overwrite head with contents of following node. */
            head->gpfn_and_flags = n->gpfn_and_flags;
            head->smfn           = n->smfn;

            /* Delete following node. */
            head->next           = n->next;

            /* Add deleted node to the free list. */
            n->gpfn_and_flags = 0;
            n->smfn           = 0;
            n->next           = d->arch.shadow_ht_free;
            d->arch.shadow_ht_free = n;
        }
        else
        {
            /* This bucket is now empty. Initialise the head node. */
            head->gpfn_and_flags = 0;
            head->smfn           = 0;
        }

        goto found;
    }

    p = head;
    x = head->next;

    do
    {
        if ( x->gpfn_and_flags == key )
        {
            /* Delete matching node. */
            p->next = x->next;

            /* Add deleted node to the free list. */
            x->gpfn_and_flags = 0;
            x->smfn           = 0;
            x->next           = d->arch.shadow_ht_free;
            d->arch.shadow_ht_free = x;

            goto found;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    /* If we got here, it wasn't in the list! */
    BUG();

 found:
    // release ref to page
    if ( stype != PGT_writable_pred )
        put_page(pfn_to_page(gmfn));

    shadow_audit(d, 0);
}

static inline void set_shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long gmfn,
    unsigned long smfn, unsigned long stype)
{
    struct shadow_status *x, *head, *extra;
    int i;
    unsigned long key = gpfn | stype;

    SH_VVLOG("set gpfn=%lx gmfn=%lx smfn=%lx t=%lx", gpfn, gmfn, smfn, stype);

    ASSERT(shadow_lock_is_acquired(d));

    ASSERT(shadow_mode_translate(d) || gpfn);
    ASSERT(!(gpfn & ~PGT_mfn_mask));

    // XXX - need to be more graceful.
    ASSERT(VALID_MFN(gmfn));

    ASSERT(stype && !(stype & ~PGT_type_mask));

    x = head = hash_bucket(d, gpfn);

    SH_VLOG("set gpfn=%lx smfn=%lx t=%lx bucket=%p(%p)",
             gpfn, smfn, stype, x, x->next);
    shadow_audit(d, 0);

    // grab a reference to the guest page to represent the entry in the shadow
    // hash table
    //
    // XXX - Should PGT_writable_pred grab a page ref?
    //     - Who/how are these hash table entry refs flushed if/when a page
    //       is given away by the domain?
    //
    if ( stype != PGT_writable_pred )
        get_page(pfn_to_page(gmfn), d);

    /*
     * STEP 1. If page is already in the table, update it in place.
     */
    do
    {
        if ( unlikely(x->gpfn_and_flags == key) )
        {
            if ( stype != PGT_writable_pred )
                BUG(); // we should never replace entries into the hash table
            x->smfn = smfn;
            if ( stype != PGT_writable_pred )
                put_page(pfn_to_page(gmfn)); // already had a ref...
            goto done;
        }

        x = x->next;
    }
    while ( x != NULL );

    /*
     * STEP 2. The page must be inserted into the table.
     */

    /* If the bucket is empty then insert the new page as the head item. */
    if ( head->gpfn_and_flags == 0 )
    {
        head->gpfn_and_flags = key;
        head->smfn           = smfn;
        ASSERT(head->next == NULL);
        goto done;
    }

    /* We need to allocate a new node. Ensure the quicklist is non-empty. */
    if ( unlikely(d->arch.shadow_ht_free == NULL) )
    {
        SH_VLOG("Allocate more shadow hashtable blocks.");

        extra = xmalloc_bytes(
            sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* XXX Should be more graceful here. */
        if ( extra == NULL )
            BUG();

        memset(extra, 0, sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* Record the allocation block so it can be correctly freed later. */
        d->arch.shadow_extras_count++;
        *((struct shadow_status **)&extra[shadow_ht_extra_size]) = 
            d->arch.shadow_ht_extras;
        d->arch.shadow_ht_extras = &extra[0];

        /* Thread a free chain through the newly-allocated nodes. */
        for ( i = 0; i < (shadow_ht_extra_size - 1); i++ )
            extra[i].next = &extra[i+1];
        extra[i].next = NULL;

        /* Add the new nodes to the free list. */
        d->arch.shadow_ht_free = &extra[0];
    }

    /* Allocate a new node from the quicklist. */
    x                      = d->arch.shadow_ht_free;
    d->arch.shadow_ht_free = x->next;

    /* Initialise the new node and insert directly after the head item. */
    x->gpfn_and_flags = key;
    x->smfn           = smfn;
    x->next           = head->next;
    head->next        = x;

 done:
    shadow_audit(d, 0);

    if ( stype <= PGT_l4_shadow )
    {
        // add to front of list of pages to check when removing write
        // permissions for a page...
        //
    }
}

/************************************************************************/

void static inline
shadow_update_min_max(unsigned long smfn, int index)
{
    struct pfn_info *sl1page = pfn_to_page(smfn);
    u32 min_max = sl1page->tlbflush_timestamp;
    int min = SHADOW_MIN(min_max);
    int max = SHADOW_MAX(min_max);
    int update = 0;

    if ( index < min )
    {
        min = index;
        update = 1;
    }
    if ( index > max )
    {
        max = index;
        update = 1;
    }
    if ( update )
        sl1page->tlbflush_timestamp = SHADOW_ENCODE_MIN_MAX(min, max);
}

#if CONFIG_PAGING_LEVELS <= 2
extern void shadow_map_l1_into_current_l2(unsigned long va);

void static inline
shadow_set_l1e(unsigned long va, l1_pgentry_t new_spte, int create_l1_shadow)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    l2_pgentry_t sl2e = {0};

    __shadow_get_l2e(v, va, &sl2e);
    if ( !(l2e_get_flags(sl2e) & _PAGE_PRESENT) )
    {
        /*
         * Either the L1 is not shadowed, or the shadow isn't linked into
         * the current shadow L2.
         */
        if ( create_l1_shadow )
        {
            perfc_incrc(shadow_set_l1e_force_map);
            shadow_map_l1_into_current_l2(va);
        }
        else /* check to see if it exists; if so, link it in */
        {
            l2_pgentry_t gpde = linear_l2_table(v)[l2_table_offset(va)];
            unsigned long gl1pfn = l2e_get_pfn(gpde);
            unsigned long sl1mfn = __shadow_status(d, gl1pfn, PGT_l1_shadow);

            ASSERT( l2e_get_flags(gpde) & _PAGE_PRESENT );

            if ( sl1mfn )
            {
                perfc_incrc(shadow_set_l1e_unlinked);
                if ( !get_shadow_ref(sl1mfn) )
                    BUG();
                l2pde_general(d, &gpde, &sl2e, sl1mfn);
                __guest_set_l2e(v, va, gpde);
                __shadow_set_l2e(v, va, sl2e);
            }
            else
            {
                // no shadow exists, so there's nothing to do.
                perfc_incrc(shadow_set_l1e_fail);
                return;
            }
        }
    }

    __shadow_get_l2e(v, va, &sl2e);

    if ( shadow_mode_refcounts(d) )
    {
        l1_pgentry_t old_spte = shadow_linear_pg_table[l1_linear_offset(va)];

        // only do the ref counting if something important changed.
        //
        if ( l1e_has_changed(old_spte, new_spte, _PAGE_RW | _PAGE_PRESENT) )
        {
            if ( (l1e_get_flags(new_spte) & _PAGE_PRESENT) &&
                 !shadow_get_page_from_l1e(new_spte, d) )
                new_spte = l1e_empty();
            if ( l1e_get_flags(old_spte) & _PAGE_PRESENT )
                shadow_put_page_from_l1e(old_spte, d);
        }

    }

    set_guest_back_ptr(d, new_spte, l2e_get_pfn(sl2e), l1_table_offset(va));
    shadow_linear_pg_table[l1_linear_offset(va)] = new_spte;
    shadow_update_min_max(l2e_get_pfn(sl2e), l1_table_offset(va));
}
#endif
/************************************************************************/

static inline int
shadow_mode_page_writable(unsigned long va, struct cpu_user_regs *regs, unsigned long gpfn)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long mfn = __gpfn_to_mfn(d, gpfn);
    u32 type = frame_table[mfn].u.inuse.type_info & PGT_type_mask;

    if ( shadow_mode_refcounts(d) &&
         (type == PGT_writable_page) )
        type = shadow_max_pgtable_type(d, gpfn, NULL);

    // Strange but true: writable page tables allow kernel-mode access
    // to L1 page table pages via write-protected PTEs...  Similarly, write 
    // access to all page table pages is granted for shadow_mode_write_all
    // clients.
    //
    if ( ((shadow_mode_write_l1(d) && (type == PGT_l1_page_table)) ||
          (shadow_mode_write_all(d) && type && (type <= PGT_l4_page_table))) &&
         ((va < HYPERVISOR_VIRT_START)
#if defined(__x86_64__)
          || (va >= HYPERVISOR_VIRT_END)
#endif
             ) &&
         KERNEL_MODE(v, regs) )
        return 1;

    return 0;
}

#if CONFIG_PAGING_LEVELS <= 2
static inline l1_pgentry_t gva_to_gpte(unsigned long gva)
{
    l2_pgentry_t gpde;
    l1_pgentry_t gpte;
    struct vcpu *v = current;

    ASSERT( shadow_mode_translate(current->domain) );

    __guest_get_l2e(v, gva, &gpde);
    if ( unlikely(!(l2e_get_flags(gpde) & _PAGE_PRESENT)) )
        return l1e_empty();;

    // This is actually overkill - we only need to make sure the hl2
    // is in-sync.
    //
    shadow_sync_va(v, gva);

    if ( unlikely(__copy_from_user(&gpte,
                                   &linear_pg_table[gva >> PAGE_SHIFT],
                                   sizeof(gpte))) )
    {
        FSH_LOG("gva_to_gpte got a fault on gva=%lx", gva);
        return l1e_empty();
    }

    return gpte;
}

static inline unsigned long gva_to_gpa(unsigned long gva)
{
    l1_pgentry_t gpte;

    gpte = gva_to_gpte(gva);
    if ( !(l1e_get_flags(gpte) & _PAGE_PRESENT) )
        return 0;

    return l1e_get_paddr(gpte) + (gva & ~PAGE_MASK); 
}
#endif
/************************************************************************/

extern void __update_pagetables(struct vcpu *v);
static inline void update_pagetables(struct vcpu *v)
{
    struct domain *d = v->domain;
    int paging_enabled;

#ifdef CONFIG_VMX
    if ( VMX_DOMAIN(v) )
        paging_enabled = vmx_paging_enabled(v);

    else
#endif
        // HACK ALERT: there's currently no easy way to figure out if a domU
        // has set its arch.guest_table to zero, vs not yet initialized it.
        //
        paging_enabled = !!pagetable_get_paddr(v->arch.guest_table);

    /*
     * We don't call __update_pagetables() when vmx guest paging is
     * disabled as we want the linear_pg_table to be inaccessible so that
     * we bail out early of shadow_fault() if the vmx guest tries illegal
     * accesses while it thinks paging is turned off.
     */
    if ( unlikely(shadow_mode_enabled(d)) && paging_enabled )
    {
        shadow_lock(d);
        __update_pagetables(v);
        shadow_unlock(d);
    }

    if ( likely(!shadow_mode_external(d)) )
    {
        if ( shadow_mode_enabled(d) )
            v->arch.monitor_table = v->arch.shadow_table;
        else
#if CONFIG_PAGING_LEVELS == 4
        if ( !(v->arch.flags & TF_kernel_mode) )
            v->arch.monitor_table = v->arch.guest_table_user;
        else
#endif
            v->arch.monitor_table = v->arch.guest_table;
    }
}

void clear_all_shadow_status(struct domain *d);

#if SHADOW_DEBUG
extern int _check_pagetable(struct vcpu *v, char *s);
extern int _check_all_pagetables(struct vcpu *v, char *s);

#define check_pagetable(_v, _s) _check_pagetable(_v, _s)
//#define check_pagetable(_v, _s) _check_all_pagetables(_v, _s)

#else
#define check_pagetable(_v, _s) ((void)0)
#endif

#endif /* XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
