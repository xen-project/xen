/******************************************************************************
 * include/asm-x86/shadow.h
 * 
 * Copyright (c) 2005 Michael A Fetterman
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
#include <asm/processor.h>
#include <asm/domain_page.h>

/* Shadow PT operation mode : shadow-mode variable in arch_domain. */

#define SHM_enable    (1<<0) /* we're in one of the shadow modes */
#define SHM_log_dirty (1<<1) /* enable log dirty mode */
#define SHM_translate (1<<2) /* do p2m tranaltion on guest tables */
#define SHM_external  (1<<3) /* external page table, not used by Xen */

#define shadow_mode_enabled(_d)   ((_d)->arch.shadow_mode)
#define shadow_mode_log_dirty(_d) ((_d)->arch.shadow_mode & SHM_log_dirty)
#define shadow_mode_translate(_d) ((_d)->arch.shadow_mode & SHM_translate)
#define shadow_mode_external(_d)  ((_d)->arch.shadow_mode & SHM_external)

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define __shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START + \
     (SH_LINEAR_PT_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))
#define shadow_linear_l2_table(_ed) ((_ed)->arch.shadow_vtable)

// easy access to the hl2 table (for translated but not external modes only)
#define __linear_hl2_table ((l1_pgentry_t *)(LINEAR_PT_VIRT_START + \
     (PERDOMAIN_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))

#define shadow_lock_init(_d) spin_lock_init(&(_d)->arch.shadow_lock)
#define shadow_lock(_d)      spin_lock(&(_d)->arch.shadow_lock)
#define shadow_unlock(_d)    spin_unlock(&(_d)->arch.shadow_lock)

extern void shadow_mode_init(void);
extern int shadow_mode_control(struct domain *p, dom0_shadow_control_t *sc);
extern int shadow_fault(unsigned long va, struct xen_regs *regs);
extern int shadow_mode_enable(struct domain *p, unsigned int mode);
extern void shadow_invlpg(struct exec_domain *, unsigned long);
extern struct out_of_sync_entry *shadow_mark_mfn_out_of_sync(
    struct exec_domain *ed, unsigned long gpfn, unsigned long mfn);
extern void free_monitor_pagetable(struct exec_domain *ed);
extern void __shadow_sync_all(struct domain *d);
extern int __shadow_out_of_sync(struct exec_domain *ed, unsigned long va);

static inline unsigned long __shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype);

extern void vmx_shadow_clear_state(struct domain *);

static inline int page_is_page_table(struct pfn_info *page)
{
    return page->count_info & PGC_page_table;
}

static inline int mfn_is_page_table(unsigned long mfn)
{
    if ( !pfn_is_ram(mfn) )
        return 0;

    return frame_table[mfn].count_info & PGC_page_table;
}

static inline int page_out_of_sync(struct pfn_info *page)
{
    return page->count_info & PGC_out_of_sync;
}

static inline int mfn_out_of_sync(unsigned long mfn)
{
    if ( !pfn_is_ram(mfn) )
        return 0;

    return frame_table[mfn].count_info & PGC_out_of_sync;
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
__shadow_sync_va(struct exec_domain *ed, unsigned long va)
{
    struct domain *d = ed->domain;

    if ( d->arch.out_of_sync && __shadow_out_of_sync(ed, va) )
    {
        // XXX - could be smarter
        //
        __shadow_sync_all(ed->domain);
    }
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
shadow_sync_va(struct exec_domain *ed, unsigned long gva)
{
    struct domain *d = ed->domain;
    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_lock(d);
        __shadow_sync_va(ed, gva);
        shadow_unlock(d);
    }
}

extern void __shadow_mode_disable(struct domain *d);
static inline void shadow_mode_disable(struct domain *d)
{
    if ( shadow_mode_enabled(d) )
        __shadow_mode_disable(d);
}

/************************************************************************/

#define __mfn_to_gpfn(_d, mfn)                         \
    ( (shadow_mode_translate(_d))                      \
      ? machine_to_phys_mapping[(mfn)]                 \
      : (mfn) )

#define __gpfn_to_mfn(_d, gpfn)                        \
    ( (shadow_mode_translate(_d))                      \
      ? phys_to_machine_mapping(gpfn)                  \
      : (gpfn) )

/************************************************************************/

struct shadow_status {
    unsigned long gpfn_and_flags; /* Guest pfn plus flags. */
    struct shadow_status *next;   /* Pull-to-front list.   */
    unsigned long smfn;           /* Shadow mfn.           */
};

#define shadow_ht_extra_size 128
#define shadow_ht_buckets    256

struct out_of_sync_entry {
    struct out_of_sync_entry *next;
    unsigned long gpfn;    /* why is this here? */
    unsigned long gmfn;
    unsigned long snapshot_mfn;
    unsigned long writable_pl1e; /* NB: this is a machine address */
};

#define out_of_sync_extra_size 127

#define SHADOW_SNAPSHOT_ELSEWHERE (-1L)

/************************************************************************/

#define SHADOW_DEBUG 0
#define SHADOW_VERBOSE_DEBUG 0
#define SHADOW_VVERBOSE_DEBUG 0
#define SHADOW_HASH_DEBUG 0
#define FULLSHADOW_DEBUG 0

#if SHADOW_DEBUG
extern int shadow_status_noswap;
#endif

#ifdef VERBOSE
#define SH_LOG(_f, _a...)                                               \
    printk("DOM%uP%u: SH_LOG(%d): " _f "\n",                            \
       current->domain->id , current->processor, __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) 
#endif

#if SHADOW_VERBOSE_DEBUG
#define SH_VLOG(_f, _a...)                                              \
    printk("DOM%uP%u: SH_VLOG(%d): " _f "\n",                           \
           current->domain->id, current->processor, __LINE__ , ## _a )
#else
#define SH_VLOG(_f, _a...) 
#endif

#if SHADOW_VVERBOSE_DEBUG
#define SH_VVLOG(_f, _a...)                                             \
    printk("DOM%uP%u: SH_VVLOG(%d): " _f "\n",                          \
           current->domain->id, current->processor, __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...)
#endif

#if FULLSHADOW_DEBUG
#define FSH_LOG(_f, _a...)                                              \
    printk("DOM%uP%u: FSH_LOG(%d): " _f "\n",                           \
           current->domain->id, current->processor, __LINE__ , ## _a )
#else
#define FSH_LOG(_f, _a...) 
#endif


/************************************************************************/

static inline int
shadow_get_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    int res = get_page_from_l1e(l1e, d);
    unsigned long mfn;
    struct domain *owner;

    ASSERT( l1_pgentry_val(l1e) & _PAGE_PRESENT );

    if ( unlikely(!res) && IS_PRIV(d) && !shadow_mode_translate(d) &&
         !(l1_pgentry_val(l1e) & L1_DISALLOW_MASK) &&
         (mfn = l1_pgentry_to_pfn(l1e)) &&
         pfn_is_ram(mfn) &&
         (owner = page_get_owner(pfn_to_page(l1_pgentry_to_pfn(l1e)))) &&
         (d != owner) )
    {
        res = get_page_from_l1e(l1e, owner);
        printk("tried to map mfn %p from domain %d into shadow page tables "
               "of domain %d; %s\n",
               mfn, owner->id, d->id, res ? "success" : "failed");
    }

    if ( unlikely(!res) )
    {
        perfc_incrc(shadow_get_page_fail);
        FSH_LOG("%s failed to get ref l1e=%p\n", l1_pgentry_val(l1e));
    }

    return res;
}

/************************************************************************/

static inline void
__shadow_get_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long *psl2e)
{
    ASSERT(shadow_mode_enabled(ed->domain));

    *psl2e = l2_pgentry_val( ed->arch.shadow_vtable[l2_table_offset(va)]);
}

static inline void
__shadow_set_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long value)
{
    ASSERT(shadow_mode_enabled(ed->domain));

    ed->arch.shadow_vtable[l2_table_offset(va)] = mk_l2_pgentry(value);
}

static inline void
__guest_get_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long *pl2e)
{
    *pl2e = l2_pgentry_val(ed->arch.guest_vtable[l2_table_offset(va)]);
}

static inline void
__guest_set_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long value)
{
    if ( unlikely(shadow_mode_translate(ed->domain)) )
    {
        unsigned long mfn = phys_to_machine_mapping(value >> PAGE_SHIFT);
        unsigned long old_hl2e =
            l1_pgentry_val(ed->arch.hl2_vtable[l2_table_offset(va)]);
        unsigned long new_hl2e =
            (mfn ? ((mfn << PAGE_SHIFT) | __PAGE_HYPERVISOR) : 0);

        // only do the ref counting if something important changed.
        //
        if ( (old_hl2e ^ new_hl2e) & (PAGE_MASK | _PAGE_PRESENT) )
        {
            if ( (new_hl2e & _PAGE_PRESENT) &&
                 !shadow_get_page_from_l1e(mk_l1_pgentry(new_hl2e), ed->domain) )
                new_hl2e = 0;
            if ( old_hl2e & _PAGE_PRESENT )
                put_page_from_l1e(mk_l1_pgentry(old_hl2e), ed->domain);
        }

        ed->arch.hl2_vtable[l2_table_offset(va)] = mk_l1_pgentry(new_hl2e);
    }

    ed->arch.guest_vtable[l2_table_offset(va)] = mk_l2_pgentry(value);
}

/************************************************************************/

/*
 * Add another shadow reference to smfn.
 */
static inline int
get_shadow_ref(unsigned long smfn)
{
    u32 x, nx;

    ASSERT(pfn_is_ram(smfn));

    x = frame_table[smfn].count_info;
    nx = x + 1;

    if ( unlikely(nx == 0) )
    {
        printk("get_shadow_ref overflow, gmfn=%p smfn=%p\n",
               frame_table[smfn].u.inuse.type_info & PGT_mfn_mask, smfn);
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

    ASSERT(pfn_is_ram(smfn));

    x = frame_table[smfn].count_info;
    nx = x - 1;

    if ( unlikely(x == 0) )
    {
        printk("put_shadow_ref underflow, gmfn=%p smfn=%p\n",
               frame_table[smfn].u.inuse.type_info & PGT_mfn_mask, smfn);
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
    get_shadow_ref(smfn);
}

static inline void
shadow_unpin(unsigned long smfn)
{
    frame_table[smfn].u.inuse.type_info &= ~PGT_pinned;
    put_shadow_ref(smfn);
}


/************************************************************************/

static inline int __mark_dirty(struct domain *d, unsigned int mfn)
{
    unsigned long pfn;
    int           rc = 0;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(d->arch.shadow_dirty_bitmap != NULL);

    pfn = __mfn_to_gpfn(d, mfn);

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(IS_INVALID_M2P_ENTRY(pfn)) )
        return rc;

    if ( likely(pfn < d->arch.shadow_dirty_bitmap_size) )
    {
        /* N.B. Can use non-atomic TAS because protected by shadow_lock. */
        if ( !__test_and_set_bit(pfn, d->arch.shadow_dirty_bitmap) )
        {
            d->arch.shadow_dirty_count++;
            rc = 1;
        }
    }
#ifndef NDEBUG
    else if ( mfn < max_page )
    {
        SH_LOG("mark_dirty OOR! mfn=%x pfn=%lx max=%x (dom %p)",
               mfn, pfn, d->arch.shadow_dirty_bitmap_size, d);
        SH_LOG("dom=%p caf=%08x taf=%08x\n", 
               page_get_owner(&frame_table[mfn]),
               frame_table[mfn].count_info, 
               frame_table[mfn].u.inuse.type_info );
    }
#endif

    return rc;
}


static inline int mark_dirty(struct domain *d, unsigned int mfn)
{
    int rc;
    shadow_lock(d);
    rc = __mark_dirty(d, mfn);
    shadow_unlock(d);
    return rc;
}


/************************************************************************/

extern void shadow_mark_out_of_sync(
    struct exec_domain *ed, unsigned long gpfn, unsigned long mfn,
    unsigned long va);

static inline void l1pte_write_fault(
    struct exec_domain *ed, unsigned long *gpte_p, unsigned long *spte_p,
    unsigned long va)
{
    struct domain *d = ed->domain;
    unsigned long gpte = *gpte_p;
    unsigned long spte;
    unsigned long gpfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, gpfn);

    //printk("l1pte_write_fault gmfn=%p\n", mfn);

    if ( unlikely(!mfn) )
    {
        SH_LOG("l1pte_write_fault: invalid gpfn=%p", gpfn);
        *spte_p = 0;
        return;
    }

    ASSERT(gpte & _PAGE_RW);
    gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;
    spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);

    SH_VVLOG("l1pte_write_fault: updating spte=0x%p gpte=0x%p", spte, gpte);

    if ( shadow_mode_log_dirty(d) )
        __mark_dirty(d, mfn);

    if ( mfn_is_page_table(mfn) )
        shadow_mark_out_of_sync(ed, gpfn, mfn, va);

    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_read_fault(
    struct domain *d, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;
    unsigned long pfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

    if ( unlikely(!mfn) )
    {
        SH_LOG("l1pte_read_fault: invalid gpfn=%p", pfn);
        *spte_p = 0;
        return;
    }

    gpte |= _PAGE_ACCESSED;
    spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);

    if ( shadow_mode_log_dirty(d) || !(gpte & _PAGE_DIRTY) ||
         mfn_is_page_table(mfn) )
    {
        spte &= ~_PAGE_RW;
    }

    SH_VVLOG("l1pte_read_fault: updating spte=0x%p gpte=0x%p", spte, gpte);
    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_propagate_from_guest(
    struct domain *d, unsigned long gpte, unsigned long *spte_p)
{ 
    unsigned long pfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, pfn);
    unsigned long spte;

#if SHADOW_VERBOSE_DEBUG
    unsigned long old_spte = *spte_p;
#endif

    spte = 0;

    if ( mfn &&
         ((gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) ==
          (_PAGE_PRESENT|_PAGE_ACCESSED)) ) {

        spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);
        
        if ( shadow_mode_log_dirty(d) ||
             !(gpte & _PAGE_DIRTY) ||
             mfn_is_page_table(mfn) )
        {
            spte &= ~_PAGE_RW;
        }
    }

#if SHADOW_VERBOSE_DEBUG
    if ( old_spte || spte || gpte )
        SH_VLOG("l1pte_propagate_from_guest: gpte=0x%p, old spte=0x%p, new spte=0x%p", gpte, old_spte, spte);
#endif

    *spte_p = spte;
}

static inline void l2pde_general(
    struct domain *d,
    unsigned long *gpde_p,
    unsigned long *spde_p,
    unsigned long sl1mfn)
{
    unsigned long gpde = *gpde_p;
    unsigned long spde;

    spde = 0;
    if ( (gpde & _PAGE_PRESENT) && (sl1mfn != 0) )
    {
        spde = (gpde & ~PAGE_MASK) | (sl1mfn << PAGE_SHIFT) | 
            _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY;
        gpde |= _PAGE_ACCESSED; /* N.B. PDEs do not have a dirty bit. */

        // XXX mafetter: Hmm...
        //     Shouldn't the dirty log be checked/updated here?
        //     Actually, it needs to be done in this function's callers.
        //
        *gpde_p = gpde;
    }

    *spde_p = spde;
}

static inline void l2pde_propagate_from_guest(
    struct domain *d, unsigned long *gpde_p, unsigned long *spde_p)
{
    unsigned long gpde = *gpde_p, sl1mfn = 0;

    if ( gpde & _PAGE_PRESENT )
        sl1mfn =  __shadow_status(d, gpde >> PAGE_SHIFT, PGT_l1_shadow);
    l2pde_general(d, gpde_p, spde_p, sl1mfn);
}
    
/************************************************************************/

// returns true if a tlb flush is needed
//
static int inline
validate_pte_change(
    struct domain *d,
    unsigned long new_pte,
    unsigned long *shadow_pte_p)
{
    unsigned long old_spte, new_spte;

    perfc_incrc(validate_pte_calls);

#if 0
    FSH_LOG("validate_pte(old=%p new=%p)\n", old_pte, new_pte);
#endif

    old_spte = *shadow_pte_p;
    l1pte_propagate_from_guest(d, new_pte, &new_spte);

    // only do the ref counting if something important changed.
    //
    if ( ((old_spte | new_spte) & _PAGE_PRESENT ) &&
         ((old_spte ^ new_spte) & (PAGE_MASK | _PAGE_RW | _PAGE_PRESENT)) )
    {
        perfc_incrc(validate_pte_changes);

        if ( (new_spte & _PAGE_PRESENT) &&
             !shadow_get_page_from_l1e(mk_l1_pgentry(new_spte), d) )
            new_spte = 0;
        if ( old_spte & _PAGE_PRESENT )
            put_page_from_l1e(mk_l1_pgentry(old_spte), d);
    }

    *shadow_pte_p = new_spte;

    // paranoia rules!
    return 1;
}

// returns true if a tlb flush is needed
//
static int inline
validate_pde_change(
    struct domain *d,
    unsigned long new_pde,
    unsigned long *shadow_pde_p)
{
    unsigned long old_spde, new_spde;

    perfc_incrc(validate_pde_calls);

    old_spde = *shadow_pde_p;
    l2pde_propagate_from_guest(d, &new_pde, &new_spde);

    // XXX Shouldn't we supposed to propagate the new_pde to the guest?

    // only do the ref counting if something important changed.
    //
    if ( ((old_spde | new_spde) & _PAGE_PRESENT) &&
         ((old_spde ^ new_spde) & (PAGE_MASK | _PAGE_PRESENT)) )
    {
        perfc_incrc(validate_pde_changes);

        if ( (new_spde & _PAGE_PRESENT) &&
             !get_shadow_ref(new_spde >> PAGE_SHIFT) )
            BUG();
        if ( old_spde & _PAGE_PRESENT )
            put_shadow_ref(old_spde >> PAGE_SHIFT);
    }

    *shadow_pde_p = new_spde;

    // paranoia rules!
    return 1;
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
                printk("XXX live=%d gpfn+flags=%p sp=%p next=%p\n",
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
        perfc_value(snapshot_pages)
        ) - live;
#ifdef PERF_COUNTERS
    if ( (abs < -1) || (abs > 1) )
    {
        printk("live=%d free=%d l1=%d l2=%d hl2=%d snapshot=%d\n",
               live, free,
               perfc_value(shadow_l1_pages),
               perfc_value(shadow_l2_pages),
               perfc_value(hl2_table_pages),
               perfc_value(snapshot_pages));
        BUG();
    }
#endif
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

            SH_VVLOG("lookup gpfn=%p => status=%p", key, head->smfn);
            return head->smfn;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    SH_VVLOG("lookup gpfn=%p => status=0", key);
    perfc_incrc(shadow_status_miss);
    return 0;
}

static inline unsigned long __shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype)
{
    unsigned long gmfn = __gpfn_to_mfn(d, gpfn);

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn == (gpfn & PGT_mfn_mask));
    ASSERT(stype && !(stype & ~PGT_type_mask));

    if ( gmfn && ((stype != PGT_snapshot)
                  ? !mfn_is_page_table(gmfn)
                  : !mfn_out_of_sync(gmfn)) )
    {
        perfc_incrc(shadow_status_shortcut);
        ASSERT(___shadow_status(d, gpfn, stype) == 0);
        return 0;
    }

    return ___shadow_status(d, gmfn, stype);
}

/*
 * Not clear if pull-to-front is worth while for this or not,
 * as it generally needs to scan the entire bucket anyway.
 * Much simpler without.
 *
 * Either returns PGT_none, or PGT_l{1,2,3,4}_page_table.
 */
static inline unsigned long
shadow_max_pgtable_type(struct domain *d, unsigned long gpfn)
{
    struct shadow_status *x;
    unsigned long pttype = PGT_none, type;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn == (gpfn & PGT_mfn_mask));

    x = hash_bucket(d, gpfn);

    while ( x && x->gpfn_and_flags )
    {
        if ( (x->gpfn_and_flags & PGT_mfn_mask) == gpfn )
        {
            type = x->gpfn_and_flags & PGT_type_mask;

            // Treat an HL2 as if it's an L1
            //
            if ( type == PGT_hl2_shadow )
                type = PGT_l1_shadow;

            // Ignore snapshots -- they don't in and of themselves constitute
            // treating a page as a page table
            //
            if ( type == PGT_snapshot )
                goto next;

            // Early exit if we found the max possible value
            //
            if ( type == PGT_base_page_table )
                return type;

            if ( type > pttype )
                pttype = type;
        }
    next:
        x = x->next;
    }

    return pttype;
}

/*
 * N.B. We can make this locking more fine grained (e.g., per shadow page) if
 * it ever becomes a problem, but since we need a spin lock on the hash table 
 * anyway it's probably not worth being too clever.
 */
static inline unsigned long get_shadow_status(
    struct domain *d, unsigned long gpfn, unsigned long stype)
{
    unsigned long res;

    ASSERT(shadow_mode_enabled(d));

    /*
     * If we get here we know that some sort of update has happened to the
     * underlying page table page: either a PTE has been updated, or the page
     * has changed type. If we're in log dirty mode, we should set the
     * appropriate bit in the dirty bitmap.
     * N.B. The VA update path doesn't use this and is handled independently. 
     *
     * XXX need to think this through for vmx guests, but probably OK
     */

    shadow_lock(d);

    if ( shadow_mode_log_dirty(d) )
        __mark_dirty(d, __gpfn_to_mfn(d, gpfn));

    if ( !(res = __shadow_status(d, gpfn, stype)) )
        shadow_unlock(d);

    return res;
}


static inline void put_shadow_status(struct domain *d)
{
    shadow_unlock(d);
}


static inline void delete_shadow_status( 
    struct domain *d, unsigned int gpfn, unsigned int stype)
{
    struct shadow_status *p, *x, *n, *head;
    unsigned long key = gpfn | stype;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn && !(gpfn & ~PGT_mfn_mask));
    ASSERT(stype && !(stype & ~PGT_type_mask));

    head = hash_bucket(d, gpfn);

    SH_VLOG("delete gpfn=%p t=%p bucket=%p", gpfn, stype, head);
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
    put_page(pfn_to_page(__gpfn_to_mfn(d, gpfn)));

    shadow_audit(d, 0);
}

static inline void set_shadow_status(
    struct domain *d, unsigned long gpfn,
    unsigned long smfn, unsigned long stype)
{
    struct shadow_status *x, *head, *extra;
    int i;
    unsigned long gmfn = __gpfn_to_mfn(d, gpfn);
    unsigned long key = gpfn | stype;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn && !(gpfn & ~PGT_mfn_mask));
    ASSERT(pfn_is_ram(gmfn)); // XXX need to be more graceful
    ASSERT(smfn && !(smfn & ~PGT_mfn_mask));
    ASSERT(stype && !(stype & ~PGT_type_mask));

    x = head = hash_bucket(d, gpfn);
   
    SH_VLOG("set gpfn=%p smfn=%p t=%p bucket=%p(%p)",
             gpfn, smfn, stype, x, x->next);
    shadow_audit(d, 0);

    // grab a reference to the guest page to represent the entry in the shadow
    // hash table
    //
    get_page(pfn_to_page(gmfn), d);

    /*
     * STEP 1. If page is already in the table, update it in place.
     */
    do
    {
        if ( x->gpfn_and_flags == key )
        {
            x->smfn = smfn;
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
        SH_LOG("Allocate more shadow hashtable blocks.");

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
}

/************************************************************************/

extern void shadow_map_l1_into_current_l2(unsigned long va);

void static inline
shadow_set_l1e(unsigned long va, unsigned long new_spte, int create_l1_shadow)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    unsigned long sl2e, old_spte;

#if 0
    printk("shadow_set_l1e(va=%p, new_spte=%p, create=%d)\n",
           va, new_spte, create_l1_shadow);
#endif

    __shadow_get_l2e(ed, va, &sl2e);
    if ( !(sl2e & _PAGE_PRESENT) )
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
            unsigned long gpde =
                l2_pgentry_val(linear_l2_table(ed)[l2_table_offset(va)]);
            unsigned long gl1pfn = gpde >> PAGE_SHIFT;
            unsigned long sl1mfn = __shadow_status(d, gl1pfn, PGT_l1_shadow);

            ASSERT( gpde & _PAGE_PRESENT );

            if ( sl1mfn )
            {
                perfc_incrc(shadow_set_l1e_unlinked);
                if (!get_shadow_ref(sl1mfn))
                    BUG();
                l2pde_general(d, &gpde, &sl2e, sl1mfn);
                __guest_set_l2e(ed, va, gpde);
                __shadow_set_l2e(ed, va, sl2e);
            }
            else
            {
                // no shadow exists, so there's nothing to do.
                perfc_incrc(shadow_set_l1e_fail);
                return;
            }
        }
    }

    old_spte = l1_pgentry_val(shadow_linear_pg_table[l1_linear_offset(va)]);

    // only do the ref counting if something important changed.
    //
    if ( (old_spte ^ new_spte) & (PAGE_MASK | _PAGE_RW | _PAGE_PRESENT) )
    {
        if ( (new_spte & _PAGE_PRESENT) &&
             !shadow_get_page_from_l1e(mk_l1_pgentry(new_spte), d) )
            new_spte = 0;
        if ( old_spte & _PAGE_PRESENT )
            put_page_from_l1e(mk_l1_pgentry(old_spte), d);
    }

    shadow_linear_pg_table[l1_linear_offset(va)] = mk_l1_pgentry(new_spte);
}

/************************************************************************/

static inline unsigned long gva_to_gpte(unsigned long gva)
{
    unsigned long gpde, gpte;
    struct exec_domain *ed = current;

    ASSERT( shadow_mode_translate(current->domain) );

    __guest_get_l2e(ed, gva, &gpde);
    if ( unlikely(!(gpde & _PAGE_PRESENT)) )
        return 0;

    // This is actually overkill - we only need to make sure the hl2
    // is in-sync.
    //
    shadow_sync_va(ed, gva);

    if ( unlikely(__get_user(gpte, (unsigned long *)
                             &linear_pg_table[gva >> PAGE_SHIFT])) )
    {
        FSH_LOG("gva_to_gpte got a fault on gva=%p\n", gva);
        return 0;
    }

    return gpte;
}

static inline unsigned long gva_to_gpa(unsigned long gva)
{
    unsigned long gpte;

    gpte = gva_to_gpte(gva);
    if ( !(gpte & _PAGE_PRESENT) )
        return 0;

    return (gpte & PAGE_MASK) + (gva & ~PAGE_MASK); 
}

/************************************************************************/

extern void __update_pagetables(struct exec_domain *ed);
static inline void update_pagetables(struct exec_domain *ed)
{
    struct domain *d = ed->domain;

#ifdef CONFIG_VMX
    int paging_enabled =
        !VMX_DOMAIN(ed) ||
        test_bit(VMX_CPU_STATE_PG_ENABLED, &ed->arch.arch_vmx.cpu_state);
#else
    const int paging_enabled = 1;
#endif

    /*
     * We don't call __update_pagetables() when vmx guest paging is
     * disabled as we want the linear_pg_table to be inaccessible so that
     * we bail out early of shadow_fault() if the vmx guest tries illegal
     * accesses while it thinks paging is turned off.
     */
    if ( unlikely(shadow_mode_enabled(d)) && paging_enabled )
    {
        shadow_lock(d);
        __update_pagetables(ed);
        shadow_unlock(d);
    }

    if ( likely(!shadow_mode_external(d)) )
    {
#ifdef __x86_64__
        if ( !(ed->arch.flags & TF_kernel_mode) )
            ed->arch.monitor_table = ed->arch.guest_table_user;
        else
#endif
        if ( shadow_mode_enabled(d) )
            ed->arch.monitor_table = ed->arch.shadow_table;
        else
            ed->arch.monitor_table = ed->arch.guest_table;
    }
}

#if SHADOW_DEBUG
extern int _check_pagetable(struct exec_domain *ed, char *s);
extern int _check_all_pagetables(struct exec_domain *ed, char *s);

#define check_pagetable(_ed, _s) _check_pagetable(_ed, _s)
//#define check_pagetable(_ed, _s) _check_all_pagetables(_ed, _s)

#else
#define check_pagetable(_ed, _s) ((void)0)
#endif

#endif /* XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 */
