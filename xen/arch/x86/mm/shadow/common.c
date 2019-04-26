/******************************************************************************
 * arch/x86/mm/shadow/common.c
 *
 * Shadow code that does not need to be multiply compiled.
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

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/event.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/shadow.h>
#include <asm/hvm/ioreq.h>
#include <xen/numa.h>
#include "private.h"

DEFINE_PER_CPU(uint32_t,trace_shadow_path_flags);

static int sh_enable_log_dirty(struct domain *, bool log_global);
static int sh_disable_log_dirty(struct domain *);
static void sh_clean_dirty_bitmap(struct domain *);

/* Set up the shadow-specific parts of a domain struct at start of day.
 * Called for every domain from arch_domain_create() */
int shadow_domain_init(struct domain *d)
{
    static const struct log_dirty_ops sh_ops = {
        .enable  = sh_enable_log_dirty,
        .disable = sh_disable_log_dirty,
        .clean   = sh_clean_dirty_bitmap,
    };

    INIT_PAGE_LIST_HEAD(&d->arch.paging.shadow.freelist);
    INIT_PAGE_LIST_HEAD(&d->arch.paging.shadow.pinned_shadows);

    /* Use shadow pagetables for log-dirty support */
    paging_log_dirty_init(d, &sh_ops);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    d->arch.paging.shadow.oos_active = 0;
#endif
    d->arch.paging.shadow.pagetable_dying_op = 0;

    return 0;
}

/* Setup the shadow-specfic parts of a vcpu struct. Note: The most important
 * job is to initialize the update_paging_modes() function pointer, which is
 * used to initialized the rest of resources. Therefore, it really does not
 * matter to have v->arch.paging.mode pointing to any mode, as long as it can
 * be compiled.
 */
void shadow_vcpu_init(struct vcpu *v)
{
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    int i, j;

    for ( i = 0; i < SHADOW_OOS_PAGES; i++ )
    {
        v->arch.paging.shadow.oos[i] = INVALID_MFN;
        v->arch.paging.shadow.oos_snapshot[i] = INVALID_MFN;
        for ( j = 0; j < SHADOW_OOS_FIXUPS; j++ )
            v->arch.paging.shadow.oos_fixup[i].smfn[j] = INVALID_MFN;
    }
#endif

    v->arch.paging.mode = is_pv_vcpu(v) ?
                          &SHADOW_INTERNAL_NAME(sh_paging_mode, 4) :
                          &SHADOW_INTERNAL_NAME(sh_paging_mode, 3);
}

#if SHADOW_AUDIT
int shadow_audit_enable = 0;

static void shadow_audit_key(unsigned char key)
{
    shadow_audit_enable = !shadow_audit_enable;
    printk("%s shadow_audit_enable=%d\n",
           __func__, shadow_audit_enable);
}

static int __init shadow_audit_key_init(void)
{
    register_keyhandler('O', shadow_audit_key, "toggle shadow audits", 0);
    return 0;
}
__initcall(shadow_audit_key_init);
#endif /* SHADOW_AUDIT */

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
/**************************************************************************/
/* Out-of-sync shadows. */

/* From time to time, we let a shadowed pagetable page go out of sync
 * with its shadow: the guest is allowed to write directly to the page,
 * and those writes are not synchronously reflected in the shadow.
 * This lets us avoid many emulations if the guest is writing a lot to a
 * pagetable, but it relaxes a pretty important invariant in the shadow
 * pagetable design.  Therefore, some rules:
 *
 * 1. Only L1 pagetables may go out of sync: any page that is shadowed
 *    at at higher level must be synchronously updated.  This makes
 *    using linear shadow pagetables much less dangerous.
 *    That means that: (a) unsyncing code needs to check for higher-level
 *    shadows, and (b) promotion code needs to resync.
 *
 * 2. All shadow operations on a guest page require the page to be brought
 *    back into sync before proceeding.  This must be done under the
 *    paging lock so that the page is guaranteed to remain synced until
 *    the operation completes.
 *
 *    Exceptions to this rule: the pagefault and invlpg handlers may
 *    update only one entry on an out-of-sync page without resyncing it.
 *
 * 3. Operations on shadows that do not start from a guest page need to
 *    be aware that they may be handling an out-of-sync shadow.
 *
 * 4. Operations that do not normally take the paging lock (fast-path
 *    #PF handler, INVLPG) must fall back to a locking, syncing version
 *    if they see an out-of-sync table.
 *
 * 5. Operations corresponding to guest TLB flushes (MOV CR3, INVLPG)
 *    must explicitly resync all relevant pages or update their
 *    shadows.
 *
 * Currently out-of-sync pages are listed in a simple open-addressed
 * hash table with a second chance (must resist temptation to radically
 * over-engineer hash tables...)  The virtual address of the access
 * which caused us to unsync the page is also kept in the hash table, as
 * a hint for finding the writable mappings later.
 *
 * We keep a hash per vcpu, because we want as much as possible to do
 * the re-sync on the save vcpu we did the unsync on, so the VA hint
 * will be valid.
 */

static void sh_oos_audit(struct domain *d)
{
    unsigned int idx, expected_idx, expected_idx_alt;
    struct page_info *pg;
    struct vcpu *v;

    for_each_vcpu(d, v)
    {
        for ( idx = 0; idx < SHADOW_OOS_PAGES; idx++ )
        {
            mfn_t *oos = v->arch.paging.shadow.oos;
            if ( !mfn_valid(oos[idx]) )
                continue;

            expected_idx = mfn_x(oos[idx]) % SHADOW_OOS_PAGES;
            expected_idx_alt = ((expected_idx + 1) % SHADOW_OOS_PAGES);
            if ( idx != expected_idx && idx != expected_idx_alt )
            {
                printk("%s: idx %x contains gmfn %lx, expected at %x or %x.\n",
                       __func__, idx, mfn_x(oos[idx]),
                       expected_idx, expected_idx_alt);
                BUG();
            }
            pg = mfn_to_page(oos[idx]);
            if ( !(pg->count_info & PGC_page_table) )
            {
                printk("%s: idx %x gmfn %lx not a pt (count %lx)\n",
                       __func__, idx, mfn_x(oos[idx]), pg->count_info);
                BUG();
            }
            if ( !(pg->shadow_flags & SHF_out_of_sync) )
            {
                printk("%s: idx %x gmfn %lx not marked oos (flags %x)\n",
                       __func__, idx, mfn_x(oos[idx]), pg->shadow_flags);
                BUG();
            }
            if ( (pg->shadow_flags & SHF_page_type_mask & ~SHF_L1_ANY) )
            {
                printk("%s: idx %x gmfn %lx shadowed as non-l1 (flags %x)\n",
                       __func__, idx, mfn_x(oos[idx]), pg->shadow_flags);
                BUG();
            }
        }
    }
}

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES
void oos_audit_hash_is_present(struct domain *d, mfn_t gmfn)
{
    int idx;
    struct vcpu *v;
    mfn_t *oos;

    ASSERT(mfn_is_out_of_sync(gmfn));

    for_each_vcpu(d, v)
    {
        oos = v->arch.paging.shadow.oos;
        idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
        if ( !mfn_eq(oos[idx], gmfn) )
            idx = (idx + 1) % SHADOW_OOS_PAGES;

        if ( mfn_eq(oos[idx], gmfn) )
            return;
    }

    printk(XENLOG_ERR "gmfn %"PRI_mfn" marked OOS but not in hash table\n",
           mfn_x(gmfn));
    BUG();
}
#endif

/* Update the shadow, but keep the page out of sync. */
static inline void _sh_resync_l1(struct vcpu *v, mfn_t gmfn, mfn_t snpmfn)
{
    struct page_info *pg = mfn_to_page(gmfn);

    ASSERT(mfn_valid(gmfn));
    ASSERT(page_is_out_of_sync(pg));

    /* Call out to the appropriate per-mode resyncing function */
    if ( pg->shadow_flags & SHF_L1_32 )
        SHADOW_INTERNAL_NAME(sh_resync_l1, 2)(v, gmfn, snpmfn);
    else if ( pg->shadow_flags & SHF_L1_PAE )
        SHADOW_INTERNAL_NAME(sh_resync_l1, 3)(v, gmfn, snpmfn);
    else if ( pg->shadow_flags & SHF_L1_64 )
        SHADOW_INTERNAL_NAME(sh_resync_l1, 4)(v, gmfn, snpmfn);
}


/*
 * Fixup arrays: We limit the maximum number of writable mappings to
 * SHADOW_OOS_FIXUPS and store enough information to remove them
 * quickly on resync.
 */

static inline int oos_fixup_flush_gmfn(struct vcpu *v, mfn_t gmfn,
                                       struct oos_fixup *fixup)
{
    struct domain *d = v->domain;
    int i;
    for ( i = 0; i < SHADOW_OOS_FIXUPS; i++ )
    {
        if ( !mfn_eq(fixup->smfn[i], INVALID_MFN) )
        {
            sh_remove_write_access_from_sl1p(d, gmfn,
                                             fixup->smfn[i],
                                             fixup->off[i]);
            fixup->smfn[i] = INVALID_MFN;
        }
    }

    /* Always flush the TLBs. See comment on oos_fixup_add(). */
    return 1;
}

void oos_fixup_add(struct domain *d, mfn_t gmfn,
                   mfn_t smfn,  unsigned long off)
{
    int idx, next;
    mfn_t *oos;
    struct oos_fixup *oos_fixup;
    struct vcpu *v;

    perfc_incr(shadow_oos_fixup_add);

    for_each_vcpu(d, v)
    {
        oos = v->arch.paging.shadow.oos;
        oos_fixup = v->arch.paging.shadow.oos_fixup;
        idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
        if ( !mfn_eq(oos[idx], gmfn) )
            idx = (idx + 1) % SHADOW_OOS_PAGES;
        if ( mfn_eq(oos[idx], gmfn) )
        {
            int i;
            for ( i = 0; i < SHADOW_OOS_FIXUPS; i++ )
            {
                if ( mfn_valid(oos_fixup[idx].smfn[i])
                     && mfn_eq(oos_fixup[idx].smfn[i], smfn)
                     && (oos_fixup[idx].off[i] == off) )
                    return;
            }

            next = oos_fixup[idx].next;

            if ( !mfn_eq(oos_fixup[idx].smfn[next], INVALID_MFN) )
            {
                TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_OOS_FIXUP_EVICT);

                /* Reuse this slot and remove current writable mapping. */
                sh_remove_write_access_from_sl1p(d, gmfn,
                                                 oos_fixup[idx].smfn[next],
                                                 oos_fixup[idx].off[next]);
                perfc_incr(shadow_oos_fixup_evict);
                /* We should flush the TLBs now, because we removed a
                   writable mapping, but since the shadow is already
                   OOS we have no problem if another vcpu write to
                   this page table. We just have to be very careful to
                   *always* flush the tlbs on resync. */
            }

            oos_fixup[idx].smfn[next] = smfn;
            oos_fixup[idx].off[next] = off;
            oos_fixup[idx].next = (next + 1) % SHADOW_OOS_FIXUPS;

            TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_OOS_FIXUP_ADD);
            return;
        }
    }

    printk(XENLOG_ERR "gmfn %"PRI_mfn" was OOS but not in hash table\n",
           mfn_x(gmfn));
    BUG();
}

static int oos_remove_write_access(struct vcpu *v, mfn_t gmfn,
                                   struct oos_fixup *fixup)
{
    struct domain *d = v->domain;
    int ftlb = 0;

    ftlb |= oos_fixup_flush_gmfn(v, gmfn, fixup);

    switch ( sh_remove_write_access(d, gmfn, 0, 0) )
    {
    default:
    case 0:
        break;

    case 1:
        ftlb |= 1;
        break;

    case -1:
        /* An unfindable writeable typecount has appeared, probably via a
         * grant table entry: can't shoot the mapping, so try to unshadow
         * the page.  If that doesn't work either, the guest is granting
         * his pagetables and must be killed after all.
         * This will flush the tlb, so we can return with no worries. */
        sh_remove_shadows(d, gmfn, 0 /* Be thorough */, 1 /* Must succeed */);
        return 1;
    }

    if ( ftlb )
        flush_tlb_mask(d->dirty_cpumask);

    return 0;
}


static inline void trace_resync(int event, mfn_t gmfn)
{
    if ( tb_init_done )
    {
        /* Convert gmfn to gfn */
        gfn_t gfn = mfn_to_gfn(current->domain, gmfn);

        __trace_var(event, 0/*!tsc*/, sizeof(gfn), &gfn);
    }
}

/* Pull all the entries on an out-of-sync page back into sync. */
static void _sh_resync(struct vcpu *v, mfn_t gmfn,
                       struct oos_fixup *fixup, mfn_t snp)
{
    struct page_info *pg = mfn_to_page(gmfn);

    ASSERT(paging_locked_by_me(v->domain));
    ASSERT(mfn_is_out_of_sync(gmfn));
    /* Guest page must be shadowed *only* as L1 when out of sync. */
    ASSERT(!(mfn_to_page(gmfn)->shadow_flags & SHF_page_type_mask
             & ~SHF_L1_ANY));
    ASSERT(!sh_page_has_multiple_shadows(mfn_to_page(gmfn)));

    SHADOW_PRINTK("%pv gmfn=%"PRI_mfn"\n", v, mfn_x(gmfn));

    /* Need to pull write access so the page *stays* in sync. */
    if ( oos_remove_write_access(v, gmfn, fixup) )
    {
        /* Page has been unshadowed. */
        return;
    }

    /* No more writable mappings of this page, please */
    pg->shadow_flags &= ~SHF_oos_may_write;

    /* Update the shadows with current guest entries. */
    _sh_resync_l1(v, gmfn, snp);

    /* Now we know all the entries are synced, and will stay that way */
    pg->shadow_flags &= ~SHF_out_of_sync;
    perfc_incr(shadow_resync);
    trace_resync(TRC_SHADOW_RESYNC_FULL, gmfn);
}


/* Add an MFN to the list of out-of-sync guest pagetables */
static void oos_hash_add(struct vcpu *v, mfn_t gmfn)
{
    int i, idx, oidx, swap = 0;
    void *gptr, *gsnpptr;
    mfn_t *oos = v->arch.paging.shadow.oos;
    mfn_t *oos_snapshot = v->arch.paging.shadow.oos_snapshot;
    struct oos_fixup *oos_fixup = v->arch.paging.shadow.oos_fixup;
    struct oos_fixup fixup = { .next = 0 };

    for (i = 0; i < SHADOW_OOS_FIXUPS; i++ )
        fixup.smfn[i] = INVALID_MFN;

    idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
    oidx = idx;

    if ( mfn_valid(oos[idx])
         && (mfn_x(oos[idx]) % SHADOW_OOS_PAGES) == idx )
    {
        /* Punt the current occupant into the next slot */
        SWAP(oos[idx], gmfn);
        SWAP(oos_fixup[idx], fixup);
        swap = 1;
        idx = (idx + 1) % SHADOW_OOS_PAGES;
    }
    if ( mfn_valid(oos[idx]) )
   {
        /* Crush the current occupant. */
        _sh_resync(v, oos[idx], &oos_fixup[idx], oos_snapshot[idx]);
        perfc_incr(shadow_unsync_evict);
    }
    oos[idx] = gmfn;
    oos_fixup[idx] = fixup;

    if ( swap )
        SWAP(oos_snapshot[idx], oos_snapshot[oidx]);

    gptr = map_domain_page(oos[oidx]);
    gsnpptr = map_domain_page(oos_snapshot[oidx]);
    memcpy(gsnpptr, gptr, PAGE_SIZE);
    unmap_domain_page(gptr);
    unmap_domain_page(gsnpptr);
}

/* Remove an MFN from the list of out-of-sync guest pagetables */
static void oos_hash_remove(struct domain *d, mfn_t gmfn)
{
    int idx;
    mfn_t *oos;
    struct vcpu *v;

    SHADOW_PRINTK("d%d gmfn %lx\n", d->domain_id, mfn_x(gmfn));

    for_each_vcpu(d, v)
    {
        oos = v->arch.paging.shadow.oos;
        idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
        if ( !mfn_eq(oos[idx], gmfn) )
            idx = (idx + 1) % SHADOW_OOS_PAGES;
        if ( mfn_eq(oos[idx], gmfn) )
        {
            oos[idx] = INVALID_MFN;
            return;
        }
    }

    printk(XENLOG_ERR "gmfn %"PRI_mfn" was OOS but not in hash table\n",
           mfn_x(gmfn));
    BUG();
}

mfn_t oos_snapshot_lookup(struct domain *d, mfn_t gmfn)
{
    int idx;
    mfn_t *oos;
    mfn_t *oos_snapshot;
    struct vcpu *v;

    for_each_vcpu(d, v)
    {
        oos = v->arch.paging.shadow.oos;
        oos_snapshot = v->arch.paging.shadow.oos_snapshot;
        idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
        if ( !mfn_eq(oos[idx], gmfn) )
            idx = (idx + 1) % SHADOW_OOS_PAGES;
        if ( mfn_eq(oos[idx], gmfn) )
        {
            return oos_snapshot[idx];
        }
    }

    printk(XENLOG_ERR "gmfn %"PRI_mfn" was OOS but not in hash table\n",
           mfn_x(gmfn));
    BUG();
}

/* Pull a single guest page back into sync */
void sh_resync(struct domain *d, mfn_t gmfn)
{
    int idx;
    mfn_t *oos;
    mfn_t *oos_snapshot;
    struct oos_fixup *oos_fixup;
    struct vcpu *v;

    for_each_vcpu(d, v)
    {
        oos = v->arch.paging.shadow.oos;
        oos_fixup = v->arch.paging.shadow.oos_fixup;
        oos_snapshot = v->arch.paging.shadow.oos_snapshot;
        idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
        if ( !mfn_eq(oos[idx], gmfn) )
            idx = (idx + 1) % SHADOW_OOS_PAGES;

        if ( mfn_eq(oos[idx], gmfn) )
        {
            _sh_resync(v, gmfn, &oos_fixup[idx], oos_snapshot[idx]);
            oos[idx] = INVALID_MFN;
            return;
        }
    }

    printk(XENLOG_ERR "gmfn %"PRI_mfn" was OOS but not in hash table\n",
           mfn_x(gmfn));
    BUG();
}

/* Figure out whether it's definitely safe not to sync this l1 table,
 * by making a call out to the mode in which that shadow was made. */
static int sh_skip_sync(struct vcpu *v, mfn_t gl1mfn)
{
    struct page_info *pg = mfn_to_page(gl1mfn);
    if ( pg->shadow_flags & SHF_L1_32 )
        return SHADOW_INTERNAL_NAME(sh_safe_not_to_sync, 2)(v, gl1mfn);
    else if ( pg->shadow_flags & SHF_L1_PAE )
        return SHADOW_INTERNAL_NAME(sh_safe_not_to_sync, 3)(v, gl1mfn);
    else if ( pg->shadow_flags & SHF_L1_64 )
        return SHADOW_INTERNAL_NAME(sh_safe_not_to_sync, 4)(v, gl1mfn);
    printk(XENLOG_ERR "gmfn %"PRI_mfn" was OOS but not shadowed as an l1\n",
           mfn_x(gl1mfn));
    BUG();
}


/* Pull all out-of-sync pages back into sync.  Pages brought out of sync
 * on other vcpus are allowed to remain out of sync, but their contents
 * will be made safe (TLB flush semantics); pages unsynced by this vcpu
 * are brought back into sync and write-protected.  If skip != 0, we try
 * to avoid resyncing at all if we think we can get away with it. */
void sh_resync_all(struct vcpu *v, int skip, int this, int others)
{
    int idx;
    struct vcpu *other;
    mfn_t *oos = v->arch.paging.shadow.oos;
    mfn_t *oos_snapshot = v->arch.paging.shadow.oos_snapshot;
    struct oos_fixup *oos_fixup = v->arch.paging.shadow.oos_fixup;

    SHADOW_PRINTK("%pv\n", v);

    ASSERT(paging_locked_by_me(v->domain));

    if ( !this )
        goto resync_others;

    /* First: resync all of this vcpu's oos pages */
    for ( idx = 0; idx < SHADOW_OOS_PAGES; idx++ )
        if ( mfn_valid(oos[idx]) )
        {
            /* Write-protect and sync contents */
            _sh_resync(v, oos[idx], &oos_fixup[idx], oos_snapshot[idx]);
            oos[idx] = INVALID_MFN;
        }

 resync_others:
    if ( !others )
        return;

    /* Second: make all *other* vcpus' oos pages safe. */
    for_each_vcpu(v->domain, other)
    {
        if ( v == other )
            continue;

        oos = other->arch.paging.shadow.oos;
        oos_fixup = other->arch.paging.shadow.oos_fixup;
        oos_snapshot = other->arch.paging.shadow.oos_snapshot;

        for ( idx = 0; idx < SHADOW_OOS_PAGES; idx++ )
        {
            if ( !mfn_valid(oos[idx]) )
                continue;

            if ( skip )
            {
                /* Update the shadows and leave the page OOS. */
                if ( sh_skip_sync(v, oos[idx]) )
                    continue;
                trace_resync(TRC_SHADOW_RESYNC_ONLY, oos[idx]);
                _sh_resync_l1(other, oos[idx], oos_snapshot[idx]);
            }
            else
            {
                /* Write-protect and sync contents */
                _sh_resync(other, oos[idx], &oos_fixup[idx], oos_snapshot[idx]);
                oos[idx] = INVALID_MFN;
            }
        }
    }
}

/* Allow a shadowed page to go out of sync. Unsyncs are traced in
 * multi.c:sh_page_fault() */
int sh_unsync(struct vcpu *v, mfn_t gmfn)
{
    struct page_info *pg;

    ASSERT(paging_locked_by_me(v->domain));

    SHADOW_PRINTK("%pv gmfn=%"PRI_mfn"\n", v, mfn_x(gmfn));

    pg = mfn_to_page(gmfn);

    /* Guest page must be shadowed *only* as L1 and *only* once when out
     * of sync.  Also, get out now if it's already out of sync.
     * Also, can't safely unsync if some vcpus have paging disabled.*/
    if ( pg->shadow_flags &
         ((SHF_page_type_mask & ~SHF_L1_ANY) | SHF_out_of_sync)
         || sh_page_has_multiple_shadows(pg)
         || is_pv_vcpu(v)
         || !v->domain->arch.paging.shadow.oos_active )
        return 0;

    BUILD_BUG_ON(!(typeof(pg->shadow_flags))SHF_out_of_sync);
    BUILD_BUG_ON(!(typeof(pg->shadow_flags))SHF_oos_may_write);

    pg->shadow_flags |= SHF_out_of_sync|SHF_oos_may_write;
    oos_hash_add(v, gmfn);
    perfc_incr(shadow_unsync);
    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_UNSYNC);
    return 1;
}

#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC) */


/**************************************************************************/
/* Code for "promoting" a guest page to the point where the shadow code is
 * willing to let it be treated as a guest page table.  This generally
 * involves making sure there are no writable mappings available to the guest
 * for this page.
 */
void shadow_promote(struct domain *d, mfn_t gmfn, unsigned int type)
{
    struct page_info *page = mfn_to_page(gmfn);

    ASSERT(mfn_valid(gmfn));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Is the page already shadowed and out of sync? */
    if ( page_is_out_of_sync(page) )
        sh_resync(d, gmfn);
#endif

    /* We should never try to promote a gmfn that has writeable mappings */
    ASSERT((page->u.inuse.type_info & PGT_type_mask) != PGT_writable_page
           || (page->u.inuse.type_info & PGT_count_mask) == 0
           || d->is_shutting_down);

    /* Is the page already shadowed? */
    if ( !test_and_set_bit(_PGC_page_table, &page->count_info) )
    {
        page->shadow_flags = 0;
        if ( is_hvm_domain(d) )
            page->pagetable_dying = false;
    }

    ASSERT(!(page->shadow_flags & (1u << type)));
    page->shadow_flags |= 1u << type;
    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_PROMOTE);
}

void shadow_demote(struct domain *d, mfn_t gmfn, u32 type)
{
    struct page_info *page = mfn_to_page(gmfn);

    ASSERT(test_bit(_PGC_page_table, &page->count_info));
    ASSERT(page->shadow_flags & (1u << type));

    page->shadow_flags &= ~(1u << type);

    if ( (page->shadow_flags & SHF_page_type_mask) == 0 )
    {
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        /* Was the page out of sync? */
        if ( page_is_out_of_sync(page) )
        {
            oos_hash_remove(d, gmfn);
        }
#endif
        clear_bit(_PGC_page_table, &page->count_info);
    }

    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_DEMOTE);
}

/**************************************************************************/
/* Validate a pagetable change from the guest and update the shadows.
 * Returns a bitmask of SHADOW_SET_* flags. */

int
sh_validate_guest_entry(struct vcpu *v, mfn_t gmfn, void *entry, u32 size)
{
    int result = 0;
    struct page_info *page = mfn_to_page(gmfn);

    paging_mark_dirty(v->domain, gmfn);

    // Determine which types of shadows are affected, and update each.
    //
    // Always validate L1s before L2s to prevent another cpu with a linear
    // mapping of this gmfn from seeing a walk that results from
    // using the new L2 value and the old L1 value.  (It is OK for such a
    // guest to see a walk that uses the old L2 value with the new L1 value,
    // as hardware could behave this way if one level of the pagewalk occurs
    // before the store, and the next level of the pagewalk occurs after the
    // store.
    //
    // Ditto for L2s before L3s, etc.
    //

    if ( !(page->count_info & PGC_page_table) )
        return 0;  /* Not shadowed at all */

    if ( page->shadow_flags & SHF_L1_32 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 2)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2_32 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 2)
            (v, gmfn, entry, size);

    if ( page->shadow_flags & SHF_L1_PAE )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 3)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2_PAE )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 3)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2H_PAE )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2he, 3)
            (v, gmfn, entry, size);

    if ( page->shadow_flags & SHF_L1_64 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2_64 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2H_64 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2he, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L3_64 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl3e, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L4_64 )
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl4e, 4)
            (v, gmfn, entry, size);

    this_cpu(trace_shadow_path_flags) |= (result<<(TRCE_SFLAG_SET_CHANGED));

    return result;
}


/**************************************************************************/
/* Memory management for shadow pages. */

/* Allocating shadow pages
 * -----------------------
 *
 * Most shadow pages are allocated singly, but there is one case where
 * we need to allocate multiple pages together: shadowing 32-bit guest
 * tables on PAE or 64-bit shadows.  A 32-bit guest l1 table covers 4MB
 * of virtual address space, and needs to be shadowed by two PAE/64-bit
 * l1 tables (covering 2MB of virtual address space each).  Similarly, a
 * 32-bit guest l2 table (4GB va) needs to be shadowed by four
 * PAE/64-bit l2 tables (1GB va each).  These multi-page shadows are
 * not contiguous in memory; functions for handling offsets into them are
 * defined in shadow/multi.c (shadow_l1_index() etc.)
 *
 * This table shows the allocation behaviour of the different modes:
 *
 * Xen paging      64b  64b  64b
 * Guest paging    32b  pae  64b
 * PV or HVM       HVM  HVM   *
 * Shadow paging   pae  pae  64b
 *
 * sl1 size         8k   4k   4k
 * sl2 size        16k   4k   4k
 * sl3 size         -    -    4k
 * sl4 size         -    -    4k
 *
 * In HVM guests, the p2m table is built out of shadow pages, and we provide
 * a function for the p2m management to steal pages, in max-order chunks, from
 * the free pool.
 */

const u8 sh_type_to_size[] = {
    1, /* SH_type_none           */
    2, /* SH_type_l1_32_shadow   */
    2, /* SH_type_fl1_32_shadow  */
    4, /* SH_type_l2_32_shadow   */
    1, /* SH_type_l1_pae_shadow  */
    1, /* SH_type_fl1_pae_shadow */
    1, /* SH_type_l2_pae_shadow  */
    1, /* SH_type_l2h_pae_shadow */
    1, /* SH_type_l1_64_shadow   */
    1, /* SH_type_fl1_64_shadow  */
    1, /* SH_type_l2_64_shadow   */
    1, /* SH_type_l2h_64_shadow  */
    1, /* SH_type_l3_64_shadow   */
    1, /* SH_type_l4_64_shadow   */
    1, /* SH_type_p2m_table      */
    1, /* SH_type_monitor_table  */
    1  /* SH_type_oos_snapshot   */
};

/*
 * Figure out the least acceptable quantity of shadow memory.
 * The minimum memory requirement for always being able to free up a
 * chunk of memory is very small -- only three max-order chunks per
 * vcpu to hold the top level shadows and pages with Xen mappings in them.
 *
 * But for a guest to be guaranteed to successfully execute a single
 * instruction, we must be able to map a large number (about thirty) VAs
 * at the same time, which means that to guarantee progress, we must
 * allow for more than ninety allocated pages per vcpu.  We round that
 * up to 128 pages, or half a megabyte per vcpu.
 */
static unsigned int shadow_min_acceptable_pages(const struct domain *d)
{
    return d->max_vcpus * 128;
}

/* Dispatcher function: call the per-mode function that will unhook the
 * non-Xen mappings in this top-level shadow mfn.  With user_only == 1,
 * unhooks only the user-mode mappings. */
void shadow_unhook_mappings(struct domain *d, mfn_t smfn, int user_only)
{
    struct page_info *sp = mfn_to_page(smfn);
    switch ( sp->u.sh.type )
    {
    case SH_type_l2_32_shadow:
        SHADOW_INTERNAL_NAME(sh_unhook_32b_mappings, 2)(d, smfn, user_only);
        break;
    case SH_type_l2_pae_shadow:
    case SH_type_l2h_pae_shadow:
        SHADOW_INTERNAL_NAME(sh_unhook_pae_mappings, 3)(d, smfn, user_only);
        break;
    case SH_type_l4_64_shadow:
        SHADOW_INTERNAL_NAME(sh_unhook_64b_mappings, 4)(d, smfn, user_only);
        break;
    default:
        printk(XENLOG_ERR "Bad top-level shadow type %08x\n", sp->u.sh.type);
        BUG();
    }
}

static inline void trace_shadow_prealloc_unpin(struct domain *d, mfn_t smfn)
{
    if ( tb_init_done )
    {
        /* Convert smfn to gfn */
        gfn_t gfn;

        ASSERT(mfn_valid(smfn));
        gfn = mfn_to_gfn(d, backpointer(mfn_to_page(smfn)));
        __trace_var(TRC_SHADOW_PREALLOC_UNPIN, 0/*!tsc*/, sizeof(gfn), &gfn);
    }
}

/* Make sure there are at least count order-sized pages
 * available in the shadow page pool. */
static void _shadow_prealloc(struct domain *d, unsigned int pages)
{
    struct vcpu *v;
    struct page_info *sp, *t;
    mfn_t smfn;
    int i;

    if ( d->arch.paging.shadow.free_pages >= pages ) return;

    /* Shouldn't have enabled shadows if we've no vcpus. */
    ASSERT(d->vcpu && d->vcpu[0]);

    /* Stage one: walk the list of pinned pages, unpinning them */
    perfc_incr(shadow_prealloc_1);
    foreach_pinned_shadow(d, sp, t)
    {
        smfn = page_to_mfn(sp);

        /* Unpin this top-level shadow */
        trace_shadow_prealloc_unpin(d, smfn);
        sh_unpin(d, smfn);

        /* See if that freed up enough space */
        if ( d->arch.paging.shadow.free_pages >= pages ) return;
    }

    /* Stage two: all shadow pages are in use in hierarchies that are
     * loaded in cr3 on some vcpu.  Walk them, unhooking the non-Xen
     * mappings. */
    perfc_incr(shadow_prealloc_2);

    for_each_vcpu(d, v)
        for ( i = 0 ; i < 4 ; i++ )
        {
            if ( !pagetable_is_null(v->arch.shadow_table[i]) )
            {
                TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_PREALLOC_UNHOOK);
                shadow_unhook_mappings(d,
                               pagetable_get_mfn(v->arch.shadow_table[i]), 0);

                /* See if that freed up enough space */
                if ( d->arch.paging.shadow.free_pages >= pages )
                {
                    flush_tlb_mask(d->dirty_cpumask);
                    return;
                }
            }
        }

    /* Nothing more we can do: all remaining shadows are of pages that
     * hold Xen mappings for some vcpu.  This can never happen. */
    printk(XENLOG_ERR "Can't pre-allocate %u shadow pages!\n"
           "  shadow pages total = %u, free = %u, p2m=%u\n",
           pages,
           d->arch.paging.shadow.total_pages,
           d->arch.paging.shadow.free_pages,
           d->arch.paging.shadow.p2m_pages);
    BUG();
}

/* Make sure there are at least count pages of the order according to
 * type available in the shadow page pool.
 * This must be called before any calls to shadow_alloc().  Since this
 * will free existing shadows to make room, it must be called early enough
 * to avoid freeing shadows that the caller is currently working on. */
void shadow_prealloc(struct domain *d, u32 type, unsigned int count)
{
    return _shadow_prealloc(d, shadow_size(type) * count);
}

/* Deliberately free all the memory we can: this will tear down all of
 * this domain's shadows */
static void shadow_blow_tables(struct domain *d)
{
    struct page_info *sp, *t;
    struct vcpu *v;
    mfn_t smfn;
    int i;

    /* Shouldn't have enabled shadows if we've no vcpus. */
    ASSERT(d->vcpu && d->vcpu[0]);

    /* Pass one: unpin all pinned pages */
    foreach_pinned_shadow(d, sp, t)
    {
        smfn = page_to_mfn(sp);
        sh_unpin(d, smfn);
    }

    /* Second pass: unhook entries of in-use shadows */
    for_each_vcpu(d, v)
        for ( i = 0 ; i < 4 ; i++ )
            if ( !pagetable_is_null(v->arch.shadow_table[i]) )
                shadow_unhook_mappings(d,
                               pagetable_get_mfn(v->arch.shadow_table[i]), 0);

    /* Make sure everyone sees the unshadowings */
    flush_tlb_mask(d->dirty_cpumask);
}

void shadow_blow_tables_per_domain(struct domain *d)
{
    if ( shadow_mode_enabled(d) && d->vcpu != NULL && d->vcpu[0] != NULL ) {
        paging_lock(d);
        shadow_blow_tables(d);
        paging_unlock(d);
    }
}

#ifndef NDEBUG
/* Blow all shadows of all shadowed domains: this can be used to cause the
 * guest's pagetables to be re-shadowed if we suspect that the shadows
 * have somehow got out of sync */
static void shadow_blow_all_tables(unsigned char c)
{
    struct domain *d;
    printk("'%c' pressed -> blowing all shadow tables\n", c);
    rcu_read_lock(&domlist_read_lock);
    for_each_domain(d)
    {
        if ( shadow_mode_enabled(d) && d->vcpu != NULL && d->vcpu[0] != NULL )
        {
            paging_lock(d);
            shadow_blow_tables(d);
            paging_unlock(d);
        }
    }
    rcu_read_unlock(&domlist_read_lock);
}

/* Register this function in the Xen console keypress table */
static __init int shadow_blow_tables_keyhandler_init(void)
{
    register_keyhandler('S', shadow_blow_all_tables, "reset shadow pagetables", 1);
    return 0;
}
__initcall(shadow_blow_tables_keyhandler_init);
#endif /* !NDEBUG */

/* Accessors for the singly-linked list that's used for hash chains */
static inline struct page_info *
next_shadow(const struct page_info *sp)
{
    return sp->next_shadow ? pdx_to_page(sp->next_shadow) : NULL;
}

static inline void
set_next_shadow(struct page_info *sp, struct page_info *next)
{
    sp->next_shadow = next ? page_to_pdx(next) : 0;
}

/* Allocate another shadow's worth of (contiguous, aligned) pages,
 * and fill in the type and backpointer fields of their page_infos.
 * Never fails to allocate. */
mfn_t shadow_alloc(struct domain *d,
                    u32 shadow_type,
                    unsigned long backpointer)
{
    struct page_info *sp = NULL;
    unsigned int pages = shadow_size(shadow_type);
    struct page_list_head tmp_list;
    cpumask_t mask;
    unsigned int i;

    ASSERT(paging_locked_by_me(d));
    ASSERT(shadow_type != SH_type_none);
    perfc_incr(shadow_alloc);

    if ( d->arch.paging.shadow.free_pages < pages )
    {
        /* If we get here, we failed to allocate. This should never
         * happen.  It means that we didn't call shadow_prealloc()
         * correctly before we allocated.  We can't recover by calling
         * prealloc here, because we might free up higher-level pages
         * that the caller is working on. */
        printk(XENLOG_ERR "Can't allocate %u shadow pages!\n", pages);
        BUG();
    }
    d->arch.paging.shadow.free_pages -= pages;

    /* Backpointers that are MFNs need to be packed into PDXs (PFNs don't) */
    switch (shadow_type)
    {
    case SH_type_fl1_32_shadow:
    case SH_type_fl1_pae_shadow:
    case SH_type_fl1_64_shadow:
        break;
    default:
        backpointer = pfn_to_pdx(backpointer);
        break;
    }

    INIT_PAGE_LIST_HEAD(&tmp_list);

    /* Init page info fields and clear the pages */
    for ( i = 0; i < pages ; i++ )
    {
        sp = page_list_remove_head(&d->arch.paging.shadow.freelist);
        /* Before we overwrite the old contents of this page,
         * we need to be sure that no TLB holds a pointer to it. */
        cpumask_copy(&mask, d->dirty_cpumask);
        tlbflush_filter(&mask, sp->tlbflush_timestamp);
        if ( unlikely(!cpumask_empty(&mask)) )
        {
            perfc_incr(shadow_alloc_tlbflush);
            flush_tlb_mask(&mask);
        }
        /* Now safe to clear the page for reuse */
        clear_domain_page(page_to_mfn(sp));
        INIT_PAGE_LIST_ENTRY(&sp->list);
        page_list_add(sp, &tmp_list);
        sp->u.sh.type = shadow_type;
        sp->u.sh.pinned = 0;
        sp->u.sh.count = 0;
        sp->u.sh.head = 0;
        sp->v.sh.back = backpointer;
        set_next_shadow(sp, NULL);
        perfc_incr(shadow_alloc_count);
    }
    if ( shadow_type >= SH_type_min_shadow
         && shadow_type <= SH_type_max_shadow )
        sp->u.sh.head = 1;

    sh_terminate_list(&tmp_list);

    return page_to_mfn(sp);
}


/* Return some shadow pages to the pool. */
void shadow_free(struct domain *d, mfn_t smfn)
{
    struct page_info *next = NULL, *sp = mfn_to_page(smfn);
    struct page_list_head *pin_list;
    unsigned int pages;
    u32 shadow_type;
    int i;

    ASSERT(paging_locked_by_me(d));
    perfc_incr(shadow_free);

    shadow_type = sp->u.sh.type;
    ASSERT(shadow_type != SH_type_none);
    ASSERT(sp->u.sh.head || (shadow_type > SH_type_max_shadow));
    pages = shadow_size(shadow_type);
    pin_list = &d->arch.paging.shadow.pinned_shadows;

    for ( i = 0; i < pages; i++ )
    {
#if SHADOW_OPTIMIZATIONS & (SHOPT_WRITABLE_HEURISTIC | SHOPT_FAST_EMULATION)
        struct vcpu *v;
        for_each_vcpu(d, v)
        {
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
            /* No longer safe to look for a writeable mapping in this shadow */
            if ( v->arch.paging.shadow.last_writeable_pte_smfn
                 == mfn_x(page_to_mfn(sp)) )
                v->arch.paging.shadow.last_writeable_pte_smfn = 0;
#endif
#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
            v->arch.paging.last_write_emul_ok = 0;
#endif
        }
#endif
        /* Get the next page before we overwrite the list header */
        if ( i < pages - 1 )
            next = page_list_next(sp, pin_list);
        /* Strip out the type: this is now a free shadow page */
        sp->u.sh.type = sp->u.sh.head = 0;
        /* Remember the TLB timestamp so we will know whether to flush
         * TLBs when we reuse the page.  Because the destructors leave the
         * contents of the pages in place, we can delay TLB flushes until
         * just before the allocator hands the page out again. */
        page_set_tlbflush_timestamp(sp);
        perfc_decr(shadow_alloc_count);
        page_list_add_tail(sp, &d->arch.paging.shadow.freelist);
        sp = next;
    }

    d->arch.paging.shadow.free_pages += pages;
}

/* Divert a page from the pool to be used by the p2m mapping.
 * This action is irreversible: the p2m mapping only ever grows.
 * That's OK because the p2m table only exists for translated domains,
 * and those domains can't ever turn off shadow mode. */
static struct page_info *
shadow_alloc_p2m_page(struct domain *d)
{
    struct page_info *pg;

    /* This is called both from the p2m code (which never holds the
     * paging lock) and the log-dirty code (which always does). */
    paging_lock_recursive(d);

    if ( d->arch.paging.shadow.total_pages
         < shadow_min_acceptable_pages(d) + 1 )
    {
        if ( !d->arch.paging.p2m_alloc_failed )
        {
            d->arch.paging.p2m_alloc_failed = 1;
            dprintk(XENLOG_ERR,
                    "d%d failed to allocate from shadow pool (tot=%u p2m=%u min=%u)\n",
                    d->domain_id, d->arch.paging.shadow.total_pages,
                    d->arch.paging.shadow.p2m_pages,
                    shadow_min_acceptable_pages(d));
        }
        paging_unlock(d);
        return NULL;
    }

    shadow_prealloc(d, SH_type_p2m_table, 1);
    pg = mfn_to_page(shadow_alloc(d, SH_type_p2m_table, 0));
    d->arch.paging.shadow.p2m_pages++;
    d->arch.paging.shadow.total_pages--;
    ASSERT(!page_get_owner(pg) && !(pg->count_info & PGC_count_mask));

    paging_unlock(d);

    return pg;
}

static void
shadow_free_p2m_page(struct domain *d, struct page_info *pg)
{
    struct domain *owner = page_get_owner(pg);

    /* Should still have no owner and count zero. */
    if ( owner || (pg->count_info & PGC_count_mask) )
    {
        printk(XENLOG_ERR
               "d%d: Odd p2m page %"PRI_mfn" d=%d c=%lx t=%"PRtype_info"\n",
               d->domain_id, mfn_x(page_to_mfn(pg)),
               owner ? owner->domain_id : DOMID_INVALID,
               pg->count_info, pg->u.inuse.type_info);
        pg->count_info &= ~PGC_count_mask;
        page_set_owner(pg, NULL);
    }
    pg->u.sh.type = SH_type_p2m_table; /* p2m code reuses type-info */

    /* This is called both from the p2m code (which never holds the
     * paging lock) and the log-dirty code (which always does). */
    paging_lock_recursive(d);

    shadow_free(d, page_to_mfn(pg));
    d->arch.paging.shadow.p2m_pages--;
    d->arch.paging.shadow.total_pages++;

    paging_unlock(d);
}

static unsigned int sh_min_allocation(const struct domain *d)
{
    /*
     * Don't allocate less than the minimum acceptable, plus one page per
     * megabyte of RAM (for the p2m table, minimally enough for HVM's setting
     * up of slot zero and an LAPIC page), plus one for HVM's 1-to-1 pagetable.
     */
    return shadow_min_acceptable_pages(d) +
           max(max(d->tot_pages / 256,
                   is_hvm_domain(d) ? CONFIG_PAGING_LEVELS + 2 : 0U) +
               is_hvm_domain(d),
               d->arch.paging.shadow.p2m_pages);
}

int shadow_set_allocation(struct domain *d, unsigned int pages, bool *preempted)
{
    struct page_info *sp;

    ASSERT(paging_locked_by_me(d));

    if ( pages > 0 )
    {
        /* Check for minimum value. */
        unsigned int lower_bound = sh_min_allocation(d);

        if ( pages < lower_bound )
            pages = lower_bound;
        pages -= d->arch.paging.shadow.p2m_pages;
    }

    SHADOW_PRINTK("current %i target %i\n",
                   d->arch.paging.shadow.total_pages, pages);

    for ( ; ; )
    {
        if ( d->arch.paging.shadow.total_pages < pages )
        {
            /* Need to allocate more memory from domheap */
            sp = (struct page_info *)
                alloc_domheap_page(d, MEMF_no_owner);
            if ( sp == NULL )
            {
                SHADOW_PRINTK("failed to allocate shadow pages.\n");
                return -ENOMEM;
            }
            d->arch.paging.shadow.free_pages++;
            d->arch.paging.shadow.total_pages++;
            sp->u.sh.type = 0;
            sp->u.sh.pinned = 0;
            sp->u.sh.count = 0;
            sp->tlbflush_timestamp = 0; /* Not in any TLB */
            page_list_add_tail(sp, &d->arch.paging.shadow.freelist);
        }
        else if ( d->arch.paging.shadow.total_pages > pages )
        {
            /* Need to return memory to domheap */
            _shadow_prealloc(d, 1);
            sp = page_list_remove_head(&d->arch.paging.shadow.freelist);
            ASSERT(sp);
            /*
             * The pages were allocated anonymously, but the owner field
             * gets overwritten normally, so need to clear it here.
             */
            page_set_owner(sp, NULL);
            d->arch.paging.shadow.free_pages--;
            d->arch.paging.shadow.total_pages--;
            free_domheap_page(sp);
        }
        else
            break;

        /* Check to see if we need to yield and try again */
        if ( preempted && general_preempt_check() )
        {
            *preempted = true;
            return 0;
        }
    }

    return 0;
}

/* Return the size of the shadow pool, rounded up to the nearest MB */
static unsigned int shadow_get_allocation(struct domain *d)
{
    unsigned int pg = d->arch.paging.shadow.total_pages
        + d->arch.paging.shadow.p2m_pages;
    return ((pg >> (20 - PAGE_SHIFT))
            + ((pg & ((1 << (20 - PAGE_SHIFT)) - 1)) ? 1 : 0));
}

/**************************************************************************/
/* Hash table for storing the guest->shadow mappings.
 * The table itself is an array of pointers to shadows; the shadows are then
 * threaded on a singly-linked list of shadows with the same hash value */

#define SHADOW_HASH_BUCKETS 251
/* Other possibly useful primes are 509, 1021, 2039, 4093, 8191, 16381 */

/* Hash function that takes a gfn or mfn, plus another byte of type info */
typedef u32 key_t;
static inline key_t sh_hash(unsigned long n, unsigned int t)
{
    unsigned char *p = (unsigned char *)&n;
    key_t k = t;
    int i;
    for ( i = 0; i < sizeof(n) ; i++ ) k = (u32)p[i] + (k<<6) + (k<<16) - k;
    return k % SHADOW_HASH_BUCKETS;
}

/* Before we get to the mechanism, define a pair of audit functions
 * that sanity-check the contents of the hash table. */
static void sh_hash_audit_bucket(struct domain *d, int bucket)
/* Audit one bucket of the hash table */
{
    struct page_info *sp, *x;

    if ( !(SHADOW_AUDIT & (SHADOW_AUDIT_HASH|SHADOW_AUDIT_HASH_FULL)) ||
         !SHADOW_AUDIT_ENABLE )
        return;

    sp = d->arch.paging.shadow.hash_table[bucket];
    while ( sp )
    {
        /* Not a shadow? */
        BUG_ON( (sp->count_info & PGC_count_mask )!= 0 ) ;
        /* Bogus type? */
        BUG_ON( sp->u.sh.type == 0 );
        BUG_ON( sp->u.sh.type > SH_type_max_shadow );
        /* Wrong page of a multi-page shadow? */
        BUG_ON( !sp->u.sh.head );
        /* Wrong bucket? */
        BUG_ON( sh_hash(__backpointer(sp), sp->u.sh.type) != bucket );
        /* Duplicate entry? */
        for ( x = next_shadow(sp); x; x = next_shadow(x) )
            BUG_ON( x->v.sh.back == sp->v.sh.back &&
                    x->u.sh.type == sp->u.sh.type );
        /* Follow the backpointer to the guest pagetable */
        if ( sp->u.sh.type != SH_type_fl1_32_shadow
             && sp->u.sh.type != SH_type_fl1_pae_shadow
             && sp->u.sh.type != SH_type_fl1_64_shadow )
        {
            struct page_info *gpg = mfn_to_page(backpointer(sp));
            /* Bad shadow flags on guest page? */
            BUG_ON( !(gpg->shadow_flags & (1<<sp->u.sh.type)) );
            /* Bad type count on guest page? */
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
            if ( sp->u.sh.type == SH_type_l1_32_shadow
                 || sp->u.sh.type == SH_type_l1_pae_shadow
                 || sp->u.sh.type == SH_type_l1_64_shadow )
            {
                if ( (gpg->u.inuse.type_info & PGT_type_mask) == PGT_writable_page
                     && (gpg->u.inuse.type_info & PGT_count_mask) != 0 )
                {
                    if ( !page_is_out_of_sync(gpg) )
                    {
                        printk(XENLOG_ERR
                               "MFN %"PRI_mfn" shadowed (by %"PRI_mfn")"
                               " and not OOS but has typecount %#lx\n",
                               __backpointer(sp), mfn_x(page_to_mfn(sp)),
                               gpg->u.inuse.type_info);
                        BUG();
                    }
                }
            }
            else /* Not an l1 */
#endif
            if ( (gpg->u.inuse.type_info & PGT_type_mask) == PGT_writable_page
                 && (gpg->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                printk(XENLOG_ERR "MFN %"PRI_mfn" shadowed (by %"PRI_mfn")"
                       " but has typecount %#lx\n",
                       __backpointer(sp), mfn_x(page_to_mfn(sp)),
                       gpg->u.inuse.type_info);
                BUG();
            }
        }
        /* That entry was OK; on we go */
        sp = next_shadow(sp);
    }
}

static void sh_hash_audit(struct domain *d)
/* Full audit: audit every bucket in the table */
{
    int i;

    if ( !(SHADOW_AUDIT & SHADOW_AUDIT_HASH_FULL) || !SHADOW_AUDIT_ENABLE )
        return;

    for ( i = 0; i < SHADOW_HASH_BUCKETS; i++ )
    {
        sh_hash_audit_bucket(d, i);
    }
}

/* Allocate and initialise the table itself.
 * Returns 0 for success, 1 for error. */
static int shadow_hash_alloc(struct domain *d)
{
    struct page_info **table;

    ASSERT(paging_locked_by_me(d));
    ASSERT(!d->arch.paging.shadow.hash_table);

    table = xzalloc_array(struct page_info *, SHADOW_HASH_BUCKETS);
    if ( !table ) return 1;
    d->arch.paging.shadow.hash_table = table;
    return 0;
}

/* Tear down the hash table and return all memory to Xen.
 * This function does not care whether the table is populated. */
static void shadow_hash_teardown(struct domain *d)
{
    ASSERT(paging_locked_by_me(d));
    ASSERT(d->arch.paging.shadow.hash_table);

    xfree(d->arch.paging.shadow.hash_table);
    d->arch.paging.shadow.hash_table = NULL;
}


mfn_t shadow_hash_lookup(struct domain *d, unsigned long n, unsigned int t)
/* Find an entry in the hash table.  Returns the MFN of the shadow,
 * or INVALID_MFN if it doesn't exist */
{
    struct page_info *sp, *prev;
    key_t key;

    ASSERT(paging_locked_by_me(d));
    ASSERT(d->arch.paging.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incr(shadow_hash_lookups);
    key = sh_hash(n, t);
    sh_hash_audit_bucket(d, key);

    sp = d->arch.paging.shadow.hash_table[key];
    prev = NULL;
    while(sp)
    {
        if ( __backpointer(sp) == n && sp->u.sh.type == t )
        {
            /* Pull-to-front if 'sp' isn't already the head item */
            if ( unlikely(sp != d->arch.paging.shadow.hash_table[key]) )
            {
                if ( unlikely(d->arch.paging.shadow.hash_walking != 0) )
                    /* Can't reorder: someone is walking the hash chains */
                    return page_to_mfn(sp);
                else
                {
                    ASSERT(prev);
                    /* Delete sp from the list */
                    prev->next_shadow = sp->next_shadow;
                    /* Re-insert it at the head of the list */
                    set_next_shadow(sp, d->arch.paging.shadow.hash_table[key]);
                    d->arch.paging.shadow.hash_table[key] = sp;
                }
            }
            else
            {
                perfc_incr(shadow_hash_lookup_head);
            }
            return page_to_mfn(sp);
        }
        prev = sp;
        sp = next_shadow(sp);
    }

    perfc_incr(shadow_hash_lookup_miss);
    return INVALID_MFN;
}

void shadow_hash_insert(struct domain *d, unsigned long n, unsigned int t,
                        mfn_t smfn)
/* Put a mapping (n,t)->smfn into the hash table */
{
    struct page_info *sp;
    key_t key;

    ASSERT(paging_locked_by_me(d));
    ASSERT(d->arch.paging.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incr(shadow_hash_inserts);
    key = sh_hash(n, t);
    sh_hash_audit_bucket(d, key);

    /* Insert this shadow at the top of the bucket */
    sp = mfn_to_page(smfn);
    set_next_shadow(sp, d->arch.paging.shadow.hash_table[key]);
    d->arch.paging.shadow.hash_table[key] = sp;

    sh_hash_audit_bucket(d, key);
}

void shadow_hash_delete(struct domain *d, unsigned long n, unsigned int t,
                        mfn_t smfn)
/* Excise the mapping (n,t)->smfn from the hash table */
{
    struct page_info *sp, *x;
    key_t key;

    ASSERT(paging_locked_by_me(d));
    ASSERT(d->arch.paging.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incr(shadow_hash_deletes);
    key = sh_hash(n, t);
    sh_hash_audit_bucket(d, key);

    sp = mfn_to_page(smfn);
    if ( d->arch.paging.shadow.hash_table[key] == sp )
        /* Easy case: we're deleting the head item. */
        d->arch.paging.shadow.hash_table[key] = next_shadow(sp);
    else
    {
        /* Need to search for the one we want */
        x = d->arch.paging.shadow.hash_table[key];
        while ( 1 )
        {
            ASSERT(x); /* We can't have hit the end, since our target is
                        * still in the chain somehwere... */
            if ( next_shadow(x) == sp )
            {
                x->next_shadow = sp->next_shadow;
                break;
            }
            x = next_shadow(x);
        }
    }
    set_next_shadow(sp, NULL);

    sh_hash_audit_bucket(d, key);
}

typedef int (*hash_vcpu_callback_t)(struct vcpu *v, mfn_t smfn, mfn_t other_mfn);
typedef int (*hash_domain_callback_t)(struct domain *d, mfn_t smfn, mfn_t other_mfn);

static void hash_vcpu_foreach(struct vcpu *v, unsigned int callback_mask,
                              const hash_vcpu_callback_t callbacks[],
                              mfn_t callback_mfn)
/* Walk the hash table looking at the types of the entries and
 * calling the appropriate callback function for each entry.
 * The mask determines which shadow types we call back for, and the array
 * of callbacks tells us which function to call.
 * Any callback may return non-zero to let us skip the rest of the scan.
 *
 * WARNING: Callbacks MUST NOT add or remove hash entries unless they
 * then return non-zero to terminate the scan. */
{
    int i, done = 0;
    struct domain *d = v->domain;
    struct page_info *x;

    ASSERT(paging_locked_by_me(d));

    /* Can be called via p2m code &c after shadow teardown. */
    if ( unlikely(!d->arch.paging.shadow.hash_table) )
        return;

    /* Say we're here, to stop hash-lookups reordering the chains */
    ASSERT(d->arch.paging.shadow.hash_walking == 0);
    d->arch.paging.shadow.hash_walking = 1;

    for ( i = 0; i < SHADOW_HASH_BUCKETS; i++ )
    {
        /* WARNING: This is not safe against changes to the hash table.
         * The callback *must* return non-zero if it has inserted or
         * deleted anything from the hash (lookups are OK, though). */
        for ( x = d->arch.paging.shadow.hash_table[i]; x; x = next_shadow(x) )
        {
            if ( callback_mask & (1 << x->u.sh.type) )
            {
                ASSERT(x->u.sh.type <= 15);
                ASSERT(callbacks[x->u.sh.type] != NULL);
                done = callbacks[x->u.sh.type](v, page_to_mfn(x),
                                               callback_mfn);
                if ( done ) break;
            }
        }
        if ( done ) break;
    }
    d->arch.paging.shadow.hash_walking = 0;
}

static void hash_domain_foreach(struct domain *d,
                                unsigned int callback_mask,
                                const hash_domain_callback_t callbacks[],
                                mfn_t callback_mfn)
/* Walk the hash table looking at the types of the entries and
 * calling the appropriate callback function for each entry.
 * The mask determines which shadow types we call back for, and the array
 * of callbacks tells us which function to call.
 * Any callback may return non-zero to let us skip the rest of the scan.
 *
 * WARNING: Callbacks MUST NOT add or remove hash entries unless they
 * then return non-zero to terminate the scan. */
{
    int i, done = 0;
    struct page_info *x;

    ASSERT(paging_locked_by_me(d));

    /* Can be called via p2m code &c after shadow teardown. */
    if ( unlikely(!d->arch.paging.shadow.hash_table) )
        return;

    /* Say we're here, to stop hash-lookups reordering the chains */
    ASSERT(d->arch.paging.shadow.hash_walking == 0);
    d->arch.paging.shadow.hash_walking = 1;

    for ( i = 0; i < SHADOW_HASH_BUCKETS; i++ )
    {
        /* WARNING: This is not safe against changes to the hash table.
         * The callback *must* return non-zero if it has inserted or
         * deleted anything from the hash (lookups are OK, though). */
        for ( x = d->arch.paging.shadow.hash_table[i]; x; x = next_shadow(x) )
        {
            if ( callback_mask & (1 << x->u.sh.type) )
            {
                ASSERT(x->u.sh.type <= 15);
                ASSERT(callbacks[x->u.sh.type] != NULL);
                done = callbacks[x->u.sh.type](d, page_to_mfn(x),
                                               callback_mfn);
                if ( done ) break;
            }
        }
        if ( done ) break;
    }
    d->arch.paging.shadow.hash_walking = 0;
}


/**************************************************************************/
/* Destroy a shadow page: simple dispatcher to call the per-type destructor
 * which will decrement refcounts appropriately and return memory to the
 * free pool. */

void sh_destroy_shadow(struct domain *d, mfn_t smfn)
{
    struct page_info *sp = mfn_to_page(smfn);
    unsigned int t = sp->u.sh.type;


    SHADOW_PRINTK("smfn=%#lx\n", mfn_x(smfn));

    /* Double-check, if we can, that the shadowed page belongs to this
     * domain, (by following the back-pointer). */
    ASSERT(t == SH_type_fl1_32_shadow  ||
           t == SH_type_fl1_pae_shadow ||
           t == SH_type_fl1_64_shadow  ||
           t == SH_type_monitor_table  ||
           (is_pv_32bit_domain(d) && t == SH_type_l4_64_shadow) ||
           (page_get_owner(mfn_to_page(backpointer(sp))) == d));

    /* The down-shifts here are so that the switch statement is on nice
     * small numbers that the compiler will enjoy */
    switch ( t )
    {
    case SH_type_l1_32_shadow:
    case SH_type_fl1_32_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 2)(d, smfn);
        break;
    case SH_type_l2_32_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 2)(d, smfn);
        break;

    case SH_type_l1_pae_shadow:
    case SH_type_fl1_pae_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 3)(d, smfn);
        break;
    case SH_type_l2_pae_shadow:
    case SH_type_l2h_pae_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 3)(d, smfn);
        break;

    case SH_type_l1_64_shadow:
    case SH_type_fl1_64_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 4)(d, smfn);
        break;
    case SH_type_l2h_64_shadow:
        ASSERT(is_pv_32bit_domain(d));
        /* Fall through... */
    case SH_type_l2_64_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 4)(d, smfn);
        break;
    case SH_type_l3_64_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l3_shadow, 4)(d, smfn);
        break;
    case SH_type_l4_64_shadow:
        SHADOW_INTERNAL_NAME(sh_destroy_l4_shadow, 4)(d, smfn);
        break;

    default:
        printk(XENLOG_ERR "tried to destroy shadow of bad type %08x\n", t);
        BUG();
    }
}

static inline void trace_shadow_wrmap_bf(mfn_t gmfn)
{
    if ( tb_init_done )
    {
        /* Convert gmfn to gfn */
        gfn_t gfn = mfn_to_gfn(current->domain, gmfn);

        __trace_var(TRC_SHADOW_WRMAP_BF, 0/*!tsc*/, sizeof(gfn), &gfn);
    }
}

/**************************************************************************/
/* Remove all writeable mappings of a guest frame from the shadow tables
 * Returns non-zero if we need to flush TLBs.
 * level and fault_addr desribe how we found this to be a pagetable;
 * level==0 means we have some other reason for revoking write access.
 * If level==0 we are allowed to fail, returning -1. */

int sh_remove_write_access(struct domain *d, mfn_t gmfn,
                           unsigned int level,
                           unsigned long fault_addr)
{
    /* Dispatch table for getting per-type functions */
    static const hash_domain_callback_t callbacks[SH_type_unused] = {
        NULL, /* none    */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 2), /* fl1_32  */
        NULL, /* l2_32   */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 3), /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 3), /* fl1_pae */
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 4), /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, 4), /* fl1_64  */
        NULL, /* l2_64   */
        NULL, /* l2h_64  */
        NULL, /* l3_64   */
        NULL, /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    static const unsigned int callback_mask =
          SHF_L1_32
        | SHF_FL1_32
        | SHF_L1_PAE
        | SHF_FL1_PAE
        | SHF_L1_64
        | SHF_FL1_64
        ;
    struct page_info *pg = mfn_to_page(gmfn);
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    struct vcpu *curr = current;
#endif

    ASSERT(paging_locked_by_me(d));

    /* Only remove writable mappings if we are doing shadow refcounts.
     * In guest refcounting, we trust Xen to already be restricting
     * all the writes to the guest page tables, so we do not need to
     * do more. */
    if ( !shadow_mode_refcounts(d) )
        return 0;

    /* Early exit if it's already a pagetable, or otherwise not writeable */
    if ( (sh_mfn_is_a_page_table(gmfn)
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
         /* Unless they've been allowed to go out of sync with their shadows */
           && !mfn_oos_may_write(gmfn)
#endif
         )
         || (pg->u.inuse.type_info & PGT_count_mask) == 0 )
        return 0;

    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_WRMAP);

    perfc_incr(shadow_writeable);

    /* If this isn't a "normal" writeable page, the domain is trying to
     * put pagetables in special memory of some kind.  We can't allow that. */
    if ( (pg->u.inuse.type_info & PGT_type_mask) != PGT_writable_page )
    {
        printk(XENLOG_G_ERR "can't remove write access to mfn %"PRI_mfn
               ", type_info is %"PRtype_info "\n",
               mfn_x(gmfn), mfn_to_page(gmfn)->u.inuse.type_info);
        domain_crash(d);
    }

#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    if ( curr->domain == d )
    {
        gfn_t gfn;
        /* Heuristic: there is likely to be only one writeable mapping,
         * and that mapping is likely to be in the current pagetable,
         * in the guest's linear map (on non-HIGHPTE linux and windows)*/

#define GUESS(_a, _h) do {                                              \
            if ( curr->arch.paging.mode->shadow.guess_wrmap(            \
                     curr, (_a), gmfn) )                                \
                perfc_incr(shadow_writeable_h_ ## _h);                  \
            if ( (pg->u.inuse.type_info & PGT_count_mask) == 0 )        \
            {                                                           \
                TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_WRMAP_GUESS_FOUND);   \
                return 1;                                               \
            }                                                           \
        } while (0)

        if ( curr->arch.paging.mode->guest_levels == 2 )
        {
            if ( level == 1 )
                /* 32bit non-PAE w2k3: linear map at 0xC0000000 */
                GUESS(0xC0000000UL + (fault_addr >> 10), 1);

            /* Linux lowmem: first 896MB is mapped 1-to-1 above 0xC0000000 */
            gfn = mfn_to_gfn(d, gmfn);
            if ( gfn_x(gfn) < 0x38000 )
                GUESS(0xC0000000UL + gfn_to_gaddr(gfn), 4);

            /* FreeBSD: Linear map at 0xBFC00000 */
            if ( level == 1 )
                GUESS(0xBFC00000UL
                      + ((fault_addr & VADDR_MASK) >> 10), 6);
        }
        else if ( curr->arch.paging.mode->guest_levels == 3 )
        {
            /* 32bit PAE w2k3: linear map at 0xC0000000 */
            switch ( level )
            {
            case 1: GUESS(0xC0000000UL + (fault_addr >> 9), 2); break;
            case 2: GUESS(0xC0600000UL + (fault_addr >> 18), 2); break;
            }

            /* Linux lowmem: first 896MB is mapped 1-to-1 above 0xC0000000 */
            gfn = mfn_to_gfn(d, gmfn);
            if ( gfn_x(gfn) < 0x38000 )
                GUESS(0xC0000000UL + gfn_to_gaddr(gfn), 4);

            /* FreeBSD PAE: Linear map at 0xBF800000 */
            switch ( level )
            {
            case 1: GUESS(0xBF800000UL
                          + ((fault_addr & VADDR_MASK) >> 9), 6); break;
            case 2: GUESS(0xBFDFC000UL
                          + ((fault_addr & VADDR_MASK) >> 18), 6); break;
            }
        }
        else if ( curr->arch.paging.mode->guest_levels == 4 )
        {
            /* 64bit w2k3: linear map at 0xfffff68000000000 */
            switch ( level )
            {
            case 1: GUESS(0xfffff68000000000UL
                          + ((fault_addr & VADDR_MASK) >> 9), 3); break;
            case 2: GUESS(0xfffff6fb40000000UL
                          + ((fault_addr & VADDR_MASK) >> 18), 3); break;
            case 3: GUESS(0xfffff6fb7da00000UL
                          + ((fault_addr & VADDR_MASK) >> 27), 3); break;
            }

            /* 64bit Linux direct map at 0xffff880000000000; older kernels
             * had it at 0xffff810000000000, and older kernels yet had it
             * at 0x0000010000000000UL */
            gfn = mfn_to_gfn(d, gmfn);
            GUESS(0xffff880000000000UL + gfn_to_gaddr(gfn), 4);
            GUESS(0xffff810000000000UL + gfn_to_gaddr(gfn), 4);
            GUESS(0x0000010000000000UL + gfn_to_gaddr(gfn), 4);

            /*
             * 64bit Solaris kernel page map at
             * kpm_vbase; 0xfffffe0000000000UL
             */
            GUESS(0xfffffe0000000000UL + gfn_to_gaddr(gfn), 4);

             /* FreeBSD 64bit: linear map 0xffff800000000000 */
             switch ( level )
             {
             case 1: GUESS(0xffff800000000000
                           + ((fault_addr & VADDR_MASK) >> 9), 6); break;
             case 2: GUESS(0xffff804000000000UL
                           + ((fault_addr & VADDR_MASK) >> 18), 6); break;
             case 3: GUESS(0xffff804020000000UL
                           + ((fault_addr & VADDR_MASK) >> 27), 6); break;
             }
             /* FreeBSD 64bit: direct map at 0xffffff0000000000 */
             GUESS(0xffffff0000000000 + gfn_to_gaddr(gfn), 6);
        }

#undef GUESS
    }

    if ( (pg->u.inuse.type_info & PGT_count_mask) == 0 )
        return 1;

    /* Second heuristic: on HIGHPTE linux, there are two particular PTEs
     * (entries in the fixmap) where linux maps its pagetables.  Since
     * we expect to hit them most of the time, we start the search for
     * the writeable mapping by looking at the same MFN where the last
     * brute-force search succeeded. */

    if ( (curr->domain == d) &&
         (curr->arch.paging.shadow.last_writeable_pte_smfn != 0) )
    {
        unsigned long old_count = (pg->u.inuse.type_info & PGT_count_mask);
        mfn_t last_smfn = _mfn(curr->arch.paging.shadow.last_writeable_pte_smfn);
        int shtype = mfn_to_page(last_smfn)->u.sh.type;

        if ( callbacks[shtype] )
            callbacks[shtype](d, last_smfn, gmfn);

        if ( (pg->u.inuse.type_info & PGT_count_mask) != old_count )
            perfc_incr(shadow_writeable_h_5);
    }

    if ( (pg->u.inuse.type_info & PGT_count_mask) == 0 )
        return 1;

#endif /* SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC */

    /* Brute-force search of all the shadows, by walking the hash */
    trace_shadow_wrmap_bf(gmfn);
    if ( level == 0 )
        perfc_incr(shadow_writeable_bf_1);
    else
        perfc_incr(shadow_writeable_bf);
    hash_domain_foreach(d, callback_mask, callbacks, gmfn);

    /* If that didn't catch the mapping, then there's some non-pagetable
     * mapping -- ioreq page, grant mapping, &c. */
    if ( (mfn_to_page(gmfn)->u.inuse.type_info & PGT_count_mask) != 0 )
    {
        if ( level == 0 )
            return -1;

        printk(XENLOG_G_ERR "can't remove write access to mfn %"PRI_mfn
               ": guest has %lu special-use mappings\n", mfn_x(gmfn),
               mfn_to_page(gmfn)->u.inuse.type_info & PGT_count_mask);
        domain_crash(d);
    }

    /* We killed at least one writeable mapping, so must flush TLBs. */
    return 1;
}

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
int sh_remove_write_access_from_sl1p(struct domain *d, mfn_t gmfn,
                                     mfn_t smfn, unsigned long off)
{
    struct page_info *sp = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(mfn_valid(gmfn));

    if ( sp->u.sh.type == SH_type_l1_32_shadow
         || sp->u.sh.type == SH_type_fl1_32_shadow )
    {
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p,2)
            (d, gmfn, smfn, off);
    }
    else if ( sp->u.sh.type == SH_type_l1_pae_shadow
              || sp->u.sh.type == SH_type_fl1_pae_shadow )
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p,3)
            (d, gmfn, smfn, off);
    else if ( sp->u.sh.type == SH_type_l1_64_shadow
              || sp->u.sh.type == SH_type_fl1_64_shadow )
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p,4)
            (d, gmfn, smfn, off);

    return 0;
}
#endif

/**************************************************************************/
/* Remove all mappings of a guest frame from the shadow tables.
 * Returns non-zero if we need to flush TLBs. */

static int sh_remove_all_mappings(struct domain *d, mfn_t gmfn, gfn_t gfn)
{
    struct page_info *page = mfn_to_page(gmfn);

    /* Dispatch table for getting per-type functions */
    static const hash_domain_callback_t callbacks[SH_type_unused] = {
        NULL, /* none    */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 2), /* fl1_32  */
        NULL, /* l2_32   */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 3), /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 3), /* fl1_pae */
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 4), /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, 4), /* fl1_64  */
        NULL, /* l2_64   */
        NULL, /* l2h_64  */
        NULL, /* l3_64   */
        NULL, /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    static const unsigned int callback_mask =
          SHF_L1_32
        | SHF_FL1_32
        | SHF_L1_PAE
        | SHF_FL1_PAE
        | SHF_L1_64
        | SHF_FL1_64
        ;

    perfc_incr(shadow_mappings);
    if ( sh_check_page_has_no_refs(page) )
        return 0;

    /* Although this is an externally visible function, we do not know
     * whether the paging lock will be held when it is called (since it
     * can be called via put_page_type when we clear a shadow l1e).*/
    paging_lock_recursive(d);

    /* XXX TODO:
     * Heuristics for finding the (probably) single mapping of this gmfn */

    /* Brute-force search of all the shadows, by walking the hash */
    perfc_incr(shadow_mappings_bf);
    hash_domain_foreach(d, callback_mask, callbacks, gmfn);

    /* If that didn't catch the mapping, something is very wrong */
    if ( !sh_check_page_has_no_refs(page) )
    {
        /*
         * Don't complain if we're in HVM and there are some extra mappings:
         * The qemu helper process has an untyped mapping of this dom's RAM
         * and the HVM restore program takes another.
         * Also allow one typed refcount for
         * - Xen heap pages, to match share_xen_page_with_guest(),
         * - ioreq server pages, to match prepare_ring_for_helper().
         */
        if ( !(shadow_mode_external(d)
               && (page->count_info & PGC_count_mask) <= 3
               && ((page->u.inuse.type_info & PGT_count_mask)
                   == (is_xen_heap_page(page) ||
                       (is_hvm_domain(d) && is_ioreq_server_page(d, page))))) )
            printk(XENLOG_G_ERR "can't find all mappings of mfn %"PRI_mfn
                   " (gfn %"PRI_gfn"): c=%lx t=%lx x=%d i=%d\n",
                   mfn_x(gmfn), gfn_x(gfn),
                   page->count_info, page->u.inuse.type_info,
                   !!is_xen_heap_page(page),
                   (is_hvm_domain(d) && is_ioreq_server_page(d, page)));
    }

    paging_unlock(d);

    /* We killed at least one mapping, so must flush TLBs. */
    return 1;
}


/**************************************************************************/
/* Remove all shadows of a guest frame from the shadow tables */

static int sh_remove_shadow_via_pointer(struct domain *d, mfn_t smfn)
/* Follow this shadow's up-pointer, if it has one, and remove the reference
 * found there.  Returns 1 if that was the only reference to this shadow */
{
    struct page_info *sp = mfn_to_page(smfn);
    mfn_t pmfn;
    l1_pgentry_t *vaddr;
    int rc;

    ASSERT(sp->u.sh.type > 0);
    ASSERT(sp->u.sh.type < SH_type_max_shadow);
    ASSERT(sh_type_has_up_pointer(d, sp->u.sh.type));

    if (sp->up == 0) return 0;
    pmfn = maddr_to_mfn(sp->up);
    ASSERT(mfn_valid(pmfn));
    vaddr = map_domain_page(pmfn) + (sp->up & (PAGE_SIZE - 1));
    ASSERT(mfn_eq(l1e_get_mfn(*vaddr), smfn));

    /* Is this the only reference to this shadow? */
    rc = (sp->u.sh.count == 1) ? 1 : 0;

    /* Blank the offending entry */
    switch (sp->u.sh.type)
    {
    case SH_type_l1_32_shadow:
    case SH_type_l2_32_shadow:
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry, 2)(d, vaddr, pmfn);
        break;
    case SH_type_l1_pae_shadow:
    case SH_type_l2_pae_shadow:
    case SH_type_l2h_pae_shadow:
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry, 3)(d, vaddr, pmfn);
        break;
    case SH_type_l1_64_shadow:
    case SH_type_l2_64_shadow:
    case SH_type_l2h_64_shadow:
    case SH_type_l3_64_shadow:
    case SH_type_l4_64_shadow:
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry, 4)(d, vaddr, pmfn);
        break;
    default: BUG(); /* Some wierd unknown shadow type */
    }

    unmap_domain_page(vaddr);
    if ( rc )
        perfc_incr(shadow_up_pointer);
    else
        perfc_incr(shadow_unshadow_bf);

    return rc;
}

void sh_remove_shadows(struct domain *d, mfn_t gmfn, int fast, int all)
/* Remove the shadows of this guest page.
 * If fast != 0, just try the quick heuristic, which will remove
 * at most one reference to each shadow of the page.  Otherwise, walk
 * all the shadow tables looking for refs to shadows of this gmfn.
 * If all != 0, kill the domain if we can't find all the shadows.
 * (all != 0 implies fast == 0)
 */
{
    struct page_info *pg = mfn_to_page(gmfn);
    mfn_t smfn;
    unsigned char t;

    /* Dispatch table for getting per-type functions: each level must
     * be called with the function to remove a lower-level shadow. */
    static const hash_domain_callback_t callbacks[SH_type_unused] = {
        NULL, /* none    */
        NULL, /* l1_32   */
        NULL, /* fl1_32  */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, 2), /* l2_32   */
        NULL, /* l1_pae  */
        NULL, /* fl1_pae */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, 3), /* l2_pae  */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, 3), /* l2h_pae */
        NULL, /* l1_64   */
        NULL, /* fl1_64  */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, 4), /* l2_64   */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, 4), /* l2h_64  */
        SHADOW_INTERNAL_NAME(sh_remove_l2_shadow, 4), /* l3_64   */
        SHADOW_INTERNAL_NAME(sh_remove_l3_shadow, 4), /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    /* Another lookup table, for choosing which mask to use */
    static const unsigned int masks[SH_type_unused] = {
        0, /* none    */
        SHF_L2_32, /* l1_32   */
        0, /* fl1_32  */
        0, /* l2_32   */
        SHF_L2H_PAE | SHF_L2_PAE, /* l1_pae  */
        0, /* fl1_pae */
        0, /* l2_pae  */
        0, /* l2h_pae  */
        SHF_L2H_64 | SHF_L2_64, /* l1_64   */
        0, /* fl1_64  */
        SHF_L3_64, /* l2_64   */
        SHF_L3_64, /* l2h_64  */
        SHF_L4_64, /* l3_64   */
        0, /* l4_64   */
        0, /* p2m     */
        0  /* unused  */
    };

    ASSERT(!(all && fast));
    ASSERT(mfn_valid(gmfn));

    /* Although this is an externally visible function, we do not know
     * whether the paging lock will be held when it is called (since it
     * can be called via put_page_type when we clear a shadow l1e).*/
    paging_lock_recursive(d);

    SHADOW_PRINTK("d%d gmfn=%"PRI_mfn"\n", d->domain_id, mfn_x(gmfn));

    /* Bail out now if the page is not shadowed */
    if ( (pg->count_info & PGC_page_table) == 0 )
    {
        paging_unlock(d);
        return;
    }

    /* Search for this shadow in all appropriate shadows */
    perfc_incr(shadow_unshadow);

    /* Lower-level shadows need to be excised from upper-level shadows.
     * This call to hash_vcpu_foreach() looks dangerous but is in fact OK: each
     * call will remove at most one shadow, and terminate immediately when
     * it does remove it, so we never walk the hash after doing a deletion.  */
#define DO_UNSHADOW(_type) do {                                         \
    t = (_type);                                                        \
    if( !(pg->count_info & PGC_page_table)                              \
        || !(pg->shadow_flags & (1 << t)) )                             \
        break;                                                          \
    smfn = shadow_hash_lookup(d, mfn_x(gmfn), t);                       \
    if ( unlikely(!mfn_valid(smfn)) )                                   \
    {                                                                   \
        printk(XENLOG_G_ERR "gmfn %"PRI_mfn" has flags %#x"             \
               " but no type-%#x shadow\n",                             \
               mfn_x(gmfn), pg->shadow_flags, t);                       \
        break;                                                          \
    }                                                                   \
    if ( sh_type_is_pinnable(d, t) )                                    \
        sh_unpin(d, smfn);                                              \
    else if ( sh_type_has_up_pointer(d, t) )                            \
        sh_remove_shadow_via_pointer(d, smfn);                          \
    if( !fast                                                           \
        && (pg->count_info & PGC_page_table)                            \
        && (pg->shadow_flags & (1 << t)) )                              \
        hash_domain_foreach(d, masks[t], callbacks, smfn);              \
} while (0)

    DO_UNSHADOW(SH_type_l2_32_shadow);
    DO_UNSHADOW(SH_type_l1_32_shadow);
    DO_UNSHADOW(SH_type_l2h_pae_shadow);
    DO_UNSHADOW(SH_type_l2_pae_shadow);
    DO_UNSHADOW(SH_type_l1_pae_shadow);
    DO_UNSHADOW(SH_type_l4_64_shadow);
    DO_UNSHADOW(SH_type_l3_64_shadow);
    DO_UNSHADOW(SH_type_l2h_64_shadow);
    DO_UNSHADOW(SH_type_l2_64_shadow);
    DO_UNSHADOW(SH_type_l1_64_shadow);

#undef DO_UNSHADOW

    /* If that didn't catch the shadows, something is wrong */
    if ( !fast && all && (pg->count_info & PGC_page_table) )
    {
        printk(XENLOG_G_ERR "can't find all shadows of mfn %"PRI_mfn
               " (shadow_flags=%04x)\n", mfn_x(gmfn), pg->shadow_flags);
        domain_crash(d);
    }

    /* Need to flush TLBs now, so that linear maps are safe next time we
     * take a fault. */
    flush_tlb_mask(d->dirty_cpumask);

    paging_unlock(d);
}

void shadow_prepare_page_type_change(struct domain *d, struct page_info *page,
                                     unsigned long new_type)
{
    if ( !(page->count_info & PGC_page_table) )
        return;

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /*
     * Normally we should never let a page go from type count 0 to type
     * count 1 when it is shadowed. One exception: out-of-sync shadowed
     * pages are allowed to become writeable.
     */
    if ( (page->shadow_flags & SHF_oos_may_write) &&
         new_type == PGT_writable_page )
        return;
#endif

    shadow_remove_all_shadows(d, page_to_mfn(page));
}

static void
sh_remove_all_shadows_and_parents(struct domain *d, mfn_t gmfn)
/* Even harsher: this is a HVM page that we thing is no longer a pagetable.
 * Unshadow it, and recursively unshadow pages that reference it. */
{
    sh_remove_shadows(d, gmfn, 0, 1);
    /* XXX TODO:
     * Rework this hashtable walker to return a linked-list of all
     * the shadows it modified, then do breadth-first recursion
     * to find the way up to higher-level tables and unshadow them too.
     *
     * The current code (just tearing down each page's shadows as we
     * detect that it is not a pagetable) is correct, but very slow.
     * It means extra emulated writes and slows down removal of mappings. */
}

/**************************************************************************/

/* Reset the up-pointers of every L3 shadow to 0.
 * This is called when l3 shadows stop being pinnable, to clear out all
 * the list-head bits so the up-pointer field is properly inititalised. */
static int sh_clear_up_pointer(struct vcpu *v, mfn_t smfn, mfn_t unused)
{
    mfn_to_page(smfn)->up = 0;
    return 0;
}

void sh_reset_l3_up_pointers(struct vcpu *v)
{
    static const hash_vcpu_callback_t callbacks[SH_type_unused] = {
        NULL, /* none    */
        NULL, /* l1_32   */
        NULL, /* fl1_32  */
        NULL, /* l2_32   */
        NULL, /* l1_pae  */
        NULL, /* fl1_pae */
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        NULL, /* l1_64   */
        NULL, /* fl1_64  */
        NULL, /* l2_64   */
        NULL, /* l2h_64  */
        sh_clear_up_pointer, /* l3_64   */
        NULL, /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };
    static const unsigned int callback_mask = SHF_L3_64;

    hash_vcpu_foreach(v, callback_mask, callbacks, INVALID_MFN);
}


/**************************************************************************/

static void sh_update_paging_modes(struct vcpu *v)
{
    struct domain *d = v->domain;
    const struct paging_mode *old_mode = v->arch.paging.mode;

    ASSERT(paging_locked_by_me(d));

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* Make sure this vcpu has a virtual TLB array allocated */
    if ( unlikely(!v->arch.paging.vtlb) )
    {
        v->arch.paging.vtlb = xzalloc_array(struct shadow_vtlb, VTLB_ENTRIES);
        if ( unlikely(!v->arch.paging.vtlb) )
        {
            printk(XENLOG_G_ERR "Could not allocate vTLB space for %pv\n", v);
            domain_crash(v->domain);
            return;
        }
        spin_lock_init(&v->arch.paging.vtlb_lock);
    }
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    if ( mfn_eq(v->arch.paging.shadow.oos_snapshot[0], INVALID_MFN) )
    {
        int i;
        for(i = 0; i < SHADOW_OOS_PAGES; i++)
        {
            shadow_prealloc(d, SH_type_oos_snapshot, 1);
            v->arch.paging.shadow.oos_snapshot[i] =
                shadow_alloc(d, SH_type_oos_snapshot, 0);
        }
    }
#endif /* OOS */

    // Valid transitions handled by this function:
    // - For PV guests:
    //     - after a shadow mode has been changed
    // - For HVM guests:
    //     - after a shadow mode has been changed
    //     - changes in CR0.PG, CR4.PAE, CR4.PSE, or CR4.PGE
    //

    // First, tear down any old shadow tables held by this vcpu.
    //
    if ( v->arch.paging.mode )
        v->arch.paging.mode->shadow.detach_old_tables(v);

    if ( !is_pv_domain(d) )
    {
        ///
        /// HVM guest
        ///
        ASSERT(shadow_mode_translate(d));
        ASSERT(shadow_mode_external(d));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        /* Need to resync all our pages now, because if a page goes out
         * of sync with paging enabled and is resynced with paging
         * disabled, the resync will go wrong. */
        shadow_resync_all(v);
#endif /* OOS */

        if ( !hvm_paging_enabled(v) )
        {
            /* When the guest has CR0.PG clear, we provide a 32-bit, non-PAE
             * pagetable for it, mapping 4 GB one-to-one using a single l2
             * page of 1024 superpage mappings */
            v->arch.guest_table = d->arch.paging.shadow.unpaged_pagetable;
            v->arch.paging.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode, 2);
        }
        else if ( hvm_long_mode_active(v) )
        {
            // long mode guest...
            v->arch.paging.mode =
                &SHADOW_INTERNAL_NAME(sh_paging_mode, 4);
        }
        else if ( hvm_pae_enabled(v) )
        {
            // 32-bit PAE mode guest...
            v->arch.paging.mode =
                &SHADOW_INTERNAL_NAME(sh_paging_mode, 3);
        }
        else
        {
            // 32-bit 2 level guest...
            v->arch.paging.mode =
                &SHADOW_INTERNAL_NAME(sh_paging_mode, 2);
        }

        if ( pagetable_is_null(v->arch.monitor_table) )
        {
            mfn_t mmfn = v->arch.paging.mode->shadow.make_monitor_table(v);
            v->arch.monitor_table = pagetable_from_mfn(mmfn);
            make_cr3(v, mmfn);
            hvm_update_host_cr3(v);
        }

        if ( v->arch.paging.mode != old_mode )
        {
            SHADOW_PRINTK("new paging mode: %pv pe=%d gl=%u "
                          "sl=%u (was g=%u s=%u)\n",
                          v,
                          is_hvm_domain(d) ? hvm_paging_enabled(v) : 1,
                          v->arch.paging.mode->guest_levels,
                          v->arch.paging.mode->shadow.shadow_levels,
                          old_mode ? old_mode->guest_levels : 0,
                          old_mode ? old_mode->shadow.shadow_levels : 0);
            if ( old_mode &&
                 (v->arch.paging.mode->shadow.shadow_levels !=
                  old_mode->shadow.shadow_levels) )
            {
                /* Need to make a new monitor table for the new mode */
                mfn_t new_mfn, old_mfn;

                if ( v != current && vcpu_runnable(v) )
                {
                    printk(XENLOG_G_ERR
                           "Some third party (%pv) is changing this HVM vcpu's"
                           " (%pv) paging mode while it is running\n",
                           current, v);
                    /* It's not safe to do that because we can't change
                     * the host CR3 for a running domain */
                    domain_crash(v->domain);
                    return;
                }

                old_mfn = pagetable_get_mfn(v->arch.monitor_table);
                v->arch.monitor_table = pagetable_null();
                new_mfn = v->arch.paging.mode->shadow.make_monitor_table(v);
                v->arch.monitor_table = pagetable_from_mfn(new_mfn);
                SHADOW_PRINTK("new monitor table %"PRI_mfn "\n",
                               mfn_x(new_mfn));

                /* Don't be running on the old monitor table when we
                 * pull it down!  Switch CR3, and warn the HVM code that
                 * its host cr3 has changed. */
                make_cr3(v, new_mfn);
                if ( v == current )
                    write_ptbase(v);
                hvm_update_host_cr3(v);
                old_mode->shadow.destroy_monitor_table(v, old_mfn);
            }
        }

        // XXX -- Need to deal with changes in CR4.PSE and CR4.PGE.
        //        These are HARD: think about the case where two CPU's have
        //        different values for CR4.PSE and CR4.PGE at the same time.
        //        This *does* happen, at least for CR4.PGE...
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* We need to check that all the vcpus have paging enabled to
     * unsync PTs. */
    if ( !(d->options & XEN_DOMCTL_CDF_oos_off) )
    {
        int pe = 1;
        struct vcpu *vptr;

        ASSERT(is_hvm_domain(d));

        for_each_vcpu(d, vptr)
        {
            if ( !hvm_paging_enabled(vptr) )
            {
                pe = 0;
                break;
            }
        }

        d->arch.paging.shadow.oos_active = pe;
    }
#endif /* OOS */

    v->arch.paging.mode->update_cr3(v, 0, false);
}

void shadow_update_paging_modes(struct vcpu *v)
{
    paging_lock(v->domain);
    sh_update_paging_modes(v);
    paging_unlock(v->domain);
}

/**************************************************************************/
/* Turning on and off shadow features */

static void sh_new_mode(struct domain *d, u32 new_mode)
/* Inform all the vcpus that the shadow mode has been changed */
{
    struct vcpu *v;

    ASSERT(paging_locked_by_me(d));
    ASSERT(d != current->domain);

    /*
     * If PG_SH_forced has previously been activated because of writing an
     * L1TF-vulnerable PTE, it must remain active for the remaining lifetime
     * of the domain, even if the logdirty mode needs to be controlled for
     * migration purposes.
     */
    if ( paging_mode_sh_forced(d) )
        new_mode |= PG_SH_forced | PG_SH_enable;

    d->arch.paging.mode = new_mode;
    for_each_vcpu(d, v)
        sh_update_paging_modes(v);
}

int shadow_enable(struct domain *d, u32 mode)
/* Turn on "permanent" shadow features: external, translate, refcount.
 * Can only be called once on a domain, and these features cannot be
 * disabled.
 * Returns 0 for success, -errno for failure. */
{
    unsigned int old_pages;
    struct page_info *pg = NULL;
    uint32_t *e;
    int rv = 0;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    mode |= PG_SH_enable;

    domain_pause(d);

    /* Sanity check the arguments */
    if ( shadow_mode_enabled(d) )
    {
        rv = -EINVAL;
        goto out_unlocked;
    }

    /* Init the shadow memory allocation if the user hasn't done so */
    old_pages = d->arch.paging.shadow.total_pages;
    if ( old_pages < sh_min_allocation(d) )
    {
        paging_lock(d);
        rv = shadow_set_allocation(d, 1024, NULL); /* Use at least 4MB */
        if ( rv != 0 )
        {
            shadow_set_allocation(d, 0, NULL);
            goto out_locked;
        }
        paging_unlock(d);
    }

    /* Allow p2m and log-dirty code to borrow shadow memory */
    d->arch.paging.alloc_page = shadow_alloc_p2m_page;
    d->arch.paging.free_page = shadow_free_p2m_page;

    /* Init the P2M table.  Must be done before we take the paging lock
     * to avoid possible deadlock. */
    if ( mode & PG_translate )
    {
        rv = p2m_alloc_table(p2m);
        if (rv != 0)
            goto out_unlocked;
    }

    /* HVM domains need an extra pagetable for vcpus that think they
     * have paging disabled */
    if ( is_hvm_domain(d) )
    {
        /* Get a single page from the shadow pool.  Take it via the
         * P2M interface to make freeing it simpler afterwards. */
        pg = shadow_alloc_p2m_page(d);
        if ( pg == NULL )
        {
            rv = -ENOMEM;
            goto out_unlocked;
        }
        /* Fill it with 32-bit, non-PAE superpage entries, each mapping 4MB
         * of virtual address space onto the same physical address range */
        e = __map_domain_page(pg);
        write_32bit_pse_identmap(e);
        unmap_domain_page(e);
        pg->count_info = 1;
        pg->u.inuse.type_info = PGT_l2_page_table | 1 | PGT_validated;
        page_set_owner(pg, d);
    }

    paging_lock(d);

    /* Sanity check again with the lock held */
    if ( shadow_mode_enabled(d) )
    {
        rv = -EINVAL;
        goto out_locked;
    }

    /* Init the hash table */
    if ( shadow_hash_alloc(d) != 0 )
    {
        rv = -ENOMEM;
        goto out_locked;
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL)
    /* We assume we're dealing with an older 64bit linux guest until we
     * see the guest use more than one l4 per vcpu. */
    d->arch.paging.shadow.opt_flags = SHOPT_LINUX_L3_TOPLEVEL;
#endif

    /* Record the 1-to-1 pagetable we just made */
    if ( is_hvm_domain(d) )
        d->arch.paging.shadow.unpaged_pagetable = pagetable_from_page(pg);

    /* Update the bits */
    sh_new_mode(d, mode);

 out_locked:
    paging_unlock(d);
 out_unlocked:
    if ( rv != 0 && !pagetable_is_null(p2m_get_pagetable(p2m)) )
        p2m_teardown(p2m);
    if ( rv != 0 && pg != NULL )
    {
        pg->count_info &= ~PGC_count_mask;
        page_set_owner(pg, NULL);
        shadow_free_p2m_page(d, pg);
    }
    domain_unpause(d);
    return rv;
}

void shadow_teardown(struct domain *d, bool *preempted)
/* Destroy the shadow pagetables of this domain and free its shadow memory.
 * Should only be called for dying domains. */
{
    struct vcpu *v;
    mfn_t mfn;
    struct page_info *unpaged_pagetable = NULL;

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    paging_lock(d);

    if ( shadow_mode_enabled(d) )
    {
        /* Release the shadow and monitor tables held by each vcpu */
        for_each_vcpu(d, v)
        {
            if ( v->arch.paging.mode )
            {
                v->arch.paging.mode->shadow.detach_old_tables(v);
                if ( shadow_mode_external(d) )
                {
                    mfn = pagetable_get_mfn(v->arch.monitor_table);
                    if ( mfn_valid(mfn) && (mfn_x(mfn) != 0) )
                        v->arch.paging.mode->shadow.destroy_monitor_table(v, mfn);
                    v->arch.monitor_table = pagetable_null();
                }
            }
        }
    }

#if (SHADOW_OPTIMIZATIONS & (SHOPT_VIRTUAL_TLB|SHOPT_OUT_OF_SYNC))
    /* Free the virtual-TLB array attached to each vcpu */
    for_each_vcpu(d, v)
    {
#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
        if ( v->arch.paging.vtlb )
        {
            xfree(v->arch.paging.vtlb);
            v->arch.paging.vtlb = NULL;
        }
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        {
            int i;
            mfn_t *oos_snapshot = v->arch.paging.shadow.oos_snapshot;
            for ( i = 0; i < SHADOW_OOS_PAGES; i++ )
                if ( mfn_valid(oos_snapshot[i]) )
                {
                    shadow_free(d, oos_snapshot[i]);
                    oos_snapshot[i] = INVALID_MFN;
                }
        }
#endif /* OOS */
    }
#endif /* (SHADOW_OPTIMIZATIONS & (SHOPT_VIRTUAL_TLB|SHOPT_OUT_OF_SYNC)) */

    if ( d->arch.paging.shadow.total_pages != 0 )
    {
        /* Destroy all the shadows and release memory to domheap */
        shadow_set_allocation(d, 0, preempted);

        if ( preempted && *preempted )
            goto out;

        /* Release the hash table back to xenheap */
        if (d->arch.paging.shadow.hash_table)
            shadow_hash_teardown(d);

        ASSERT(d->arch.paging.shadow.total_pages == 0);
    }

    /* Free the non-paged-vcpus pagetable; must happen after we've
     * destroyed any shadows of it or sh_destroy_shadow will get confused. */
    if ( !pagetable_is_null(d->arch.paging.shadow.unpaged_pagetable) )
    {
        ASSERT(is_hvm_domain(d));
        for_each_vcpu(d, v)
            if ( !hvm_paging_enabled(v) )
                v->arch.guest_table = pagetable_null();
        unpaged_pagetable =
            pagetable_get_page(d->arch.paging.shadow.unpaged_pagetable);
        d->arch.paging.shadow.unpaged_pagetable = pagetable_null();
    }

    /* We leave the "permanent" shadow modes enabled, but clear the
     * log-dirty mode bit.  We don't want any more mark_dirty()
     * calls now that we've torn down the bitmap */
    d->arch.paging.mode &= ~PG_log_dirty;

    if ( d->arch.hvm.dirty_vram )
    {
        xfree(d->arch.hvm.dirty_vram->sl1ma);
        xfree(d->arch.hvm.dirty_vram->dirty_bitmap);
        XFREE(d->arch.hvm.dirty_vram);
    }

out:
    paging_unlock(d);

    /* Must be called outside the lock */
    if ( unpaged_pagetable )
    {
        if ( page_get_owner(unpaged_pagetable) == d &&
             (unpaged_pagetable->count_info & PGC_count_mask) == 1 )
        {
            unpaged_pagetable->count_info &= ~PGC_count_mask;
            page_set_owner(unpaged_pagetable, NULL);
        }
        /* Complain here in cases where shadow_free_p2m_page() won't. */
        else if ( !page_get_owner(unpaged_pagetable) &&
                  !(unpaged_pagetable->count_info & PGC_count_mask) )
            printk(XENLOG_ERR
                   "d%d: Odd unpaged pt %"PRI_mfn" c=%lx t=%"PRtype_info"\n",
                   d->domain_id, mfn_x(page_to_mfn(unpaged_pagetable)),
                   unpaged_pagetable->count_info,
                   unpaged_pagetable->u.inuse.type_info);
        shadow_free_p2m_page(d, unpaged_pagetable);
    }
}

void shadow_final_teardown(struct domain *d)
/* Called by arch_domain_destroy(), when it's safe to pull down the p2m map. */
{
    SHADOW_PRINTK("dom %u final teardown starts."
                   "  Shadow pages total = %u, free = %u, p2m=%u\n",
                   d->domain_id,
                   d->arch.paging.shadow.total_pages,
                   d->arch.paging.shadow.free_pages,
                   d->arch.paging.shadow.p2m_pages);

    /* Double-check that the domain didn't have any shadow memory.
     * It is possible for a domain that never got domain_kill()ed
     * to get here with its shadow allocation intact. */
    if ( d->arch.paging.shadow.total_pages != 0 )
        shadow_teardown(d, NULL);

    /* It is now safe to pull down the p2m map. */
    p2m_teardown(p2m_get_hostp2m(d));
    /* Free any shadow memory that the p2m teardown released */
    paging_lock(d);
    shadow_set_allocation(d, 0, NULL);
    SHADOW_PRINTK("dom %u final teardown done."
                   "  Shadow pages total = %u, free = %u, p2m=%u\n",
                   d->domain_id,
                   d->arch.paging.shadow.total_pages,
                   d->arch.paging.shadow.free_pages,
                   d->arch.paging.shadow.p2m_pages);
    paging_unlock(d);
}

static int shadow_one_bit_enable(struct domain *d, u32 mode)
/* Turn on a single shadow mode feature */
{
    ASSERT(paging_locked_by_me(d));

    /* Sanity check the call */
    if ( d == current->domain || (d->arch.paging.mode & mode) == mode )
    {
        return -EINVAL;
    }

    mode |= PG_SH_enable;

    if ( d->arch.paging.shadow.total_pages < sh_min_allocation(d) )
    {
        /* Init the shadow memory allocation if the user hasn't done so */
        if ( shadow_set_allocation(d, 1, NULL) != 0 )
        {
            shadow_set_allocation(d, 0, NULL);
            return -ENOMEM;
        }
    }

    /* Allow p2m and log-dirty code to borrow shadow memory */
    d->arch.paging.alloc_page = shadow_alloc_p2m_page;
    d->arch.paging.free_page = shadow_free_p2m_page;

    if ( d->arch.paging.mode == 0 )
    {
        /* Init the shadow hash table */
        if ( shadow_hash_alloc(d) != 0 )
            return -ENOMEM;
    }

    /* Update the bits */
    sh_new_mode(d, d->arch.paging.mode | mode);

    return 0;
}

static int shadow_one_bit_disable(struct domain *d, u32 mode)
/* Turn off a single shadow mode feature */
{
    struct vcpu *v;
    ASSERT(paging_locked_by_me(d));

    /* Sanity check the call */
    if ( d == current->domain || !((d->arch.paging.mode & mode) == mode) )
    {
        return -EINVAL;
    }

    /* Update the bits */
    mode = d->arch.paging.mode & ~mode;
    if ( mode == PG_SH_enable )
        mode = 0;
    sh_new_mode(d, mode);
    if ( d->arch.paging.mode == 0 )
    {
        /* Get this domain off shadows */
        SHADOW_PRINTK("un-shadowing of domain %u starts."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->domain_id,
                       d->arch.paging.shadow.total_pages,
                       d->arch.paging.shadow.free_pages,
                       d->arch.paging.shadow.p2m_pages);
        for_each_vcpu(d, v)
        {
            if ( v->arch.paging.mode )
                v->arch.paging.mode->shadow.detach_old_tables(v);
            if ( !(v->arch.flags & TF_kernel_mode) )
                make_cr3(v, pagetable_get_mfn(v->arch.guest_table_user));
            else
                make_cr3(v, pagetable_get_mfn(v->arch.guest_table));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
            {
                int i;
                mfn_t *oos_snapshot = v->arch.paging.shadow.oos_snapshot;
                for ( i = 0; i < SHADOW_OOS_PAGES; i++ )
                    if ( mfn_valid(oos_snapshot[i]) )
                    {
                        shadow_free(d, oos_snapshot[i]);
                        oos_snapshot[i] = INVALID_MFN;
                    }
            }
#endif /* OOS */
        }

        /* Pull down the memory allocation */
        if ( shadow_set_allocation(d, 0, NULL) != 0 )
            BUG(); /* In fact, we will have BUG()ed already */
        shadow_hash_teardown(d);
        SHADOW_PRINTK("un-shadowing of domain %u done."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->domain_id,
                       d->arch.paging.shadow.total_pages,
                       d->arch.paging.shadow.free_pages,
                       d->arch.paging.shadow.p2m_pages);
    }

    return 0;
}

/* Enable/disable ops for the "test" and "log-dirty" modes */
static int shadow_test_enable(struct domain *d)
{
    int ret;

    domain_pause(d);
    paging_lock(d);
    ret = shadow_one_bit_enable(d, PG_SH_enable);
    paging_unlock(d);
    domain_unpause(d);

    return ret;
}

static int shadow_test_disable(struct domain *d)
{
    int ret;

    domain_pause(d);
    paging_lock(d);
    ret = shadow_one_bit_disable(d, PG_SH_enable);
    paging_unlock(d);
    domain_unpause(d);

    return ret;
}

/**************************************************************************/
/* P2M map manipulations */

/* shadow specific code which should be called when P2M table entry is updated
 * with new content. It is responsible for update the entry, as well as other
 * shadow processing jobs.
 */

static void sh_unshadow_for_p2m_change(struct domain *d, unsigned long gfn,
                                       l1_pgentry_t *p, l1_pgentry_t new,
                                       unsigned int level)
{
    /* The following assertion is to make sure we don't step on 1GB host
     * page support of HVM guest. */
    ASSERT(!(level > 2 && (l1e_get_flags(*p) & _PAGE_PRESENT) &&
             (l1e_get_flags(*p) & _PAGE_PSE)));

    /* If we're removing an MFN from the p2m, remove it from the shadows too */
    if ( level == 1 )
    {
        mfn_t mfn = l1e_get_mfn(*p);
        p2m_type_t p2mt = p2m_flags_to_type(l1e_get_flags(*p));
        if ( (p2m_is_valid(p2mt) || p2m_is_grant(p2mt)) && mfn_valid(mfn) )
        {
            sh_remove_all_shadows_and_parents(d, mfn);
            if ( sh_remove_all_mappings(d, mfn, _gfn(gfn)) )
                flush_tlb_mask(d->dirty_cpumask);
        }
    }

    /* If we're removing a superpage mapping from the p2m, we need to check
     * all the pages covered by it.  If they're still there in the new
     * scheme, that's OK, but otherwise they must be unshadowed. */
    if ( level == 2 && (l1e_get_flags(*p) & _PAGE_PRESENT) &&
         (l1e_get_flags(*p) & _PAGE_PSE) )
    {
        unsigned int i;
        cpumask_t flushmask;
        mfn_t omfn = l1e_get_mfn(*p);
        mfn_t nmfn = l1e_get_mfn(new);
        l1_pgentry_t *npte = NULL;
        p2m_type_t p2mt = p2m_flags_to_type(l1e_get_flags(*p));
        if ( p2m_is_valid(p2mt) && mfn_valid(omfn) )
        {
            cpumask_clear(&flushmask);

            /* If we're replacing a superpage with a normal L1 page, map it */
            if ( (l1e_get_flags(new) & _PAGE_PRESENT)
                 && !(l1e_get_flags(new) & _PAGE_PSE)
                 && mfn_valid(nmfn) )
                npte = map_domain_page(nmfn);

            for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
            {
                if ( !npte
                     || !p2m_is_ram(p2m_flags_to_type(l1e_get_flags(npte[i])))
                     || !mfn_eq(l1e_get_mfn(npte[i]), omfn) )
                {
                    /* This GFN->MFN mapping has gone away */
                    sh_remove_all_shadows_and_parents(d, omfn);
                    if ( sh_remove_all_mappings(d, omfn,
                                                _gfn(gfn + (i << PAGE_SHIFT))) )
                        cpumask_or(&flushmask, &flushmask, d->dirty_cpumask);
                }
                omfn = mfn_add(omfn, 1);
            }
            flush_tlb_mask(&flushmask);

            if ( npte )
                unmap_domain_page(npte);
        }
    }
}

int
shadow_write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
                       l1_pgentry_t *p, l1_pgentry_t new,
                       unsigned int level)
{
    struct domain *d = p2m->domain;
    int rc;

    paging_lock(d);

    /* If there are any shadows, update them.  But if shadow_teardown()
     * has already been called then it's not safe to try. */
    if ( likely(d->arch.paging.shadow.total_pages != 0) )
         sh_unshadow_for_p2m_change(d, gfn, p, new, level);

    rc = p2m_entry_modify(p2m, p2m_flags_to_type(l1e_get_flags(new)),
                          p2m_flags_to_type(l1e_get_flags(*p)),
                          l1e_get_mfn(new), l1e_get_mfn(*p), level);
    if ( rc )
    {
        paging_unlock(d);
        return rc;
    }

    /* Update the entry with new content */
    safe_write_pte(p, new);

#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH)
    /* If we're doing FAST_FAULT_PATH, then shadow mode may have
       cached the fact that this is an mmio region in the shadow
       page tables.  Blow the tables away to remove the cache.
       This is pretty heavy handed, but this is a rare operation
       (it might happen a dozen times during boot and then never
       again), so it doesn't matter too much. */
    if ( d->arch.paging.shadow.has_fast_mmio_entries )
    {
        shadow_blow_tables(d);
        d->arch.paging.shadow.has_fast_mmio_entries = false;
    }
#endif

    paging_unlock(d);

    return 0;
}

/**************************************************************************/
/* Log-dirty mode support */

/* Shadow specific code which is called in paging_log_dirty_enable().
 * Return 0 if no problem found.
 */
static int sh_enable_log_dirty(struct domain *d, bool log_global)
{
    int ret;

    paging_lock(d);
    if ( shadow_mode_enabled(d) )
    {
        /* This domain already has some shadows: need to clear them out
         * of the way to make sure that all references to guest memory are
         * properly write-protected */
        shadow_blow_tables(d);
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL)
    /* 32bit PV guests on 64bit xen behave like older 64bit linux: they
     * change an l4e instead of cr3 to switch tables.  Give them the
     * same optimization */
    if ( is_pv_32bit_domain(d) )
        d->arch.paging.shadow.opt_flags = SHOPT_LINUX_L3_TOPLEVEL;
#endif

    ret = shadow_one_bit_enable(d, PG_log_dirty);
    paging_unlock(d);

    return ret;
}

/* shadow specfic code which is called in paging_log_dirty_disable() */
static int sh_disable_log_dirty(struct domain *d)
{
    int ret;

    paging_lock(d);
    ret = shadow_one_bit_disable(d, PG_log_dirty);
    paging_unlock(d);

    return ret;
}

/* This function is called when we CLEAN log dirty bitmap. See
 * paging_log_dirty_op() for details.
 */
static void sh_clean_dirty_bitmap(struct domain *d)
{
    paging_lock(d);
    /* Need to revoke write access to the domain's pages again.
     * In future, we'll have a less heavy-handed approach to this,
     * but for now, we just unshadow everything except Xen. */
    shadow_blow_tables(d);
    paging_unlock(d);
}


/**************************************************************************/
/* VRAM dirty tracking support */
int shadow_track_dirty_vram(struct domain *d,
                            unsigned long begin_pfn,
                            unsigned long nr,
                            XEN_GUEST_HANDLE_PARAM(void) guest_dirty_bitmap)
{
    int rc = 0;
    unsigned long end_pfn = begin_pfn + nr;
    unsigned long dirty_size = (nr + 7) / 8;
    int flush_tlb = 0;
    unsigned long i;
    p2m_type_t t;
    struct sh_dirty_vram *dirty_vram;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    uint8_t *dirty_bitmap = NULL;

    if ( end_pfn < begin_pfn || end_pfn > p2m->max_mapped_pfn + 1 )
        return -EINVAL;

    /* We perform p2m lookups, so lock the p2m upfront to avoid deadlock */
    p2m_lock(p2m_get_hostp2m(d));
    paging_lock(d);

    dirty_vram = d->arch.hvm.dirty_vram;

    if ( dirty_vram && (!nr ||
             ( begin_pfn != dirty_vram->begin_pfn
            || end_pfn   != dirty_vram->end_pfn )) )
    {
        /* Different tracking, tear the previous down. */
        gdprintk(XENLOG_INFO, "stopping tracking VRAM %lx - %lx\n", dirty_vram->begin_pfn, dirty_vram->end_pfn);
        xfree(dirty_vram->sl1ma);
        xfree(dirty_vram->dirty_bitmap);
        xfree(dirty_vram);
        dirty_vram = d->arch.hvm.dirty_vram = NULL;
    }

    if ( !nr )
        goto out;

    dirty_bitmap = vzalloc(dirty_size);
    if ( dirty_bitmap == NULL )
    {
        rc = -ENOMEM;
        goto out;
    }
    /* This should happen seldomly (Video mode change),
     * no need to be careful. */
    if ( !dirty_vram )
    {
        /* Throw away all the shadows rather than walking through them
         * up to nr times getting rid of mappings of each pfn */
        shadow_blow_tables(d);

        gdprintk(XENLOG_INFO, "tracking VRAM %lx - %lx\n", begin_pfn, end_pfn);

        rc = -ENOMEM;
        if ( (dirty_vram = xmalloc(struct sh_dirty_vram)) == NULL )
            goto out;
        dirty_vram->begin_pfn = begin_pfn;
        dirty_vram->end_pfn = end_pfn;
        d->arch.hvm.dirty_vram = dirty_vram;

        if ( (dirty_vram->sl1ma = xmalloc_array(paddr_t, nr)) == NULL )
            goto out_dirty_vram;
        memset(dirty_vram->sl1ma, ~0, sizeof(paddr_t) * nr);

        if ( (dirty_vram->dirty_bitmap = xzalloc_array(uint8_t, dirty_size)) == NULL )
            goto out_sl1ma;

        dirty_vram->last_dirty = NOW();

        /* Tell the caller that this time we could not track dirty bits. */
        rc = -ENODATA;
    }
    else if (dirty_vram->last_dirty == -1)
        /* still completely clean, just copy our empty bitmap */
        memcpy(dirty_bitmap, dirty_vram->dirty_bitmap, dirty_size);
    else
    {
        mfn_t map_mfn = INVALID_MFN;
        void *map_sl1p = NULL;

        /* Iterate over VRAM to track dirty bits. */
        for ( i = 0; i < nr; i++ ) {
            mfn_t mfn = get_gfn_query_unlocked(d, begin_pfn + i, &t);
            struct page_info *page;
            int dirty = 0;
            paddr_t sl1ma = dirty_vram->sl1ma[i];

            if ( !mfn_eq(mfn, INVALID_MFN) )
            {
                dirty = 1;
            }
            else
            {
                page = mfn_to_page(mfn);
                switch (page->u.inuse.type_info & PGT_count_mask)
                {
                case 0:
                    /* No guest reference, nothing to track. */
                    break;
                case 1:
                    /* One guest reference. */
                    if ( sl1ma == INVALID_PADDR )
                    {
                        /* We don't know which sl1e points to this, too bad. */
                        dirty = 1;
                        /* TODO: Heuristics for finding the single mapping of
                         * this gmfn */
                        flush_tlb |= sh_remove_all_mappings(d, mfn,
                                                            _gfn(begin_pfn + i));
                    }
                    else
                    {
                        /* Hopefully the most common case: only one mapping,
                         * whose dirty bit we can use. */
                        l1_pgentry_t *sl1e;
                        mfn_t sl1mfn = maddr_to_mfn(sl1ma);

                        if ( !mfn_eq(sl1mfn, map_mfn) )
                        {
                            if ( map_sl1p )
                                unmap_domain_page(map_sl1p);
                            map_sl1p = map_domain_page(sl1mfn);
                            map_mfn = sl1mfn;
                        }
                        sl1e = map_sl1p + (sl1ma & ~PAGE_MASK);

                        if ( l1e_get_flags(*sl1e) & _PAGE_DIRTY )
                        {
                            dirty = 1;
                            /* Note: this is atomic, so we may clear a
                             * _PAGE_ACCESSED set by another processor. */
                            l1e_remove_flags(*sl1e, _PAGE_DIRTY);
                            flush_tlb = 1;
                        }
                    }
                    break;
                default:
                    /* More than one guest reference,
                     * we don't afford tracking that. */
                    dirty = 1;
                    break;
                }
            }

            if ( dirty )
            {
                dirty_vram->dirty_bitmap[i / 8] |= 1 << (i % 8);
                dirty_vram->last_dirty = NOW();
            }
        }

        if ( map_sl1p )
            unmap_domain_page(map_sl1p);

        memcpy(dirty_bitmap, dirty_vram->dirty_bitmap, dirty_size);
        memset(dirty_vram->dirty_bitmap, 0, dirty_size);
        if ( dirty_vram->last_dirty + SECONDS(2) < NOW() )
        {
            /* was clean for more than two seconds, try to disable guest
             * write access */
            for ( i = begin_pfn; i < end_pfn; i++ )
            {
                mfn_t mfn = get_gfn_query_unlocked(d, i, &t);
                if ( !mfn_eq(mfn, INVALID_MFN) )
                    flush_tlb |= sh_remove_write_access(d, mfn, 1, 0);
            }
            dirty_vram->last_dirty = -1;
        }
    }
    if ( flush_tlb )
        flush_tlb_mask(d->dirty_cpumask);
    goto out;

out_sl1ma:
    xfree(dirty_vram->sl1ma);
out_dirty_vram:
    xfree(dirty_vram);
    dirty_vram = d->arch.hvm.dirty_vram = NULL;

out:
    paging_unlock(d);
    if ( rc == 0 && dirty_bitmap != NULL &&
         copy_to_guest(guest_dirty_bitmap, dirty_bitmap, dirty_size) )
    {
        paging_lock(d);
        for ( i = 0; i < dirty_size; i++ )
            dirty_vram->dirty_bitmap[i] |= dirty_bitmap[i];
        paging_unlock(d);
        rc = -EFAULT;
    }
    vfree(dirty_bitmap);
    p2m_unlock(p2m_get_hostp2m(d));
    return rc;
}

/**************************************************************************/
/* Shadow-control XEN_DOMCTL dispatcher */

int shadow_domctl(struct domain *d,
                  struct xen_domctl_shadow_op *sc,
                  XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int rc;
    bool preempted = false;

    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_OFF:
        if ( d->arch.paging.mode == PG_SH_enable )
            if ( (rc = shadow_test_disable(d)) != 0 )
                return rc;
        return 0;

    case XEN_DOMCTL_SHADOW_OP_ENABLE_TEST:
        return shadow_test_enable(d);

    case XEN_DOMCTL_SHADOW_OP_ENABLE:
        return paging_enable(d, sc->mode << PG_mode_shift);

    case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
        sc->mb = shadow_get_allocation(d);
        return 0;

    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        paging_lock(d);
        if ( sc->mb == 0 && shadow_mode_enabled(d) )
        {
            /* Can't set the allocation to zero unless the domain stops using
             * shadow pagetables first */
            dprintk(XENLOG_G_ERR, "Can't set shadow allocation to zero, "
                    "d%d is still using shadows\n", d->domain_id);
            paging_unlock(d);
            return -EINVAL;
        }
        rc = shadow_set_allocation(d, sc->mb << (20 - PAGE_SHIFT), &preempted);
        paging_unlock(d);
        if ( preempted )
            /* Not finished.  Set up to re-run the call. */
            rc = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        else
            /* Finished.  Return the new allocation */
            sc->mb = shadow_get_allocation(d);
        return rc;

    default:
        return -EINVAL;
    }
}


/**************************************************************************/
/* Auditing shadow tables */

void shadow_audit_tables(struct vcpu *v)
{
    /* Dispatch table for getting per-type functions */
    static const hash_vcpu_callback_t callbacks[SH_type_unused] = {
        NULL, /* none    */
#if SHADOW_AUDIT & (SHADOW_AUDIT_ENTRIES | SHADOW_AUDIT_ENTRIES_FULL)
        SHADOW_INTERNAL_NAME(sh_audit_l1_table, 2),  /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table, 2), /* fl1_32  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table, 2),  /* l2_32   */
        SHADOW_INTERNAL_NAME(sh_audit_l1_table, 3),  /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table, 3), /* fl1_pae */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table, 3),  /* l2_pae  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table, 3),  /* l2h_pae */
        SHADOW_INTERNAL_NAME(sh_audit_l1_table, 4),  /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table, 4), /* fl1_64  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table, 4),  /* l2_64   */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table, 4),  /* l2h_64   */
        SHADOW_INTERNAL_NAME(sh_audit_l3_table, 4),  /* l3_64   */
        SHADOW_INTERNAL_NAME(sh_audit_l4_table, 4),  /* l4_64   */
#endif
        NULL  /* All the rest */
    };
    unsigned int mask;

    if ( !(SHADOW_AUDIT & (SHADOW_AUDIT_ENTRIES | SHADOW_AUDIT_ENTRIES_FULL)) ||
         !SHADOW_AUDIT_ENABLE )
        return;

    if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_FULL )
    {
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        sh_oos_audit(v->domain);
#endif

        mask = SHF_page_type_mask; /* Audit every table in the system */
    }
    else 
    {
        /* Audit only the current mode's tables */
        switch ( v->arch.paging.mode->guest_levels )
        {
        case 2: mask = (SHF_L1_32|SHF_FL1_32|SHF_L2_32); break;
        case 3: mask = (SHF_L1_PAE|SHF_FL1_PAE|SHF_L2_PAE
                        |SHF_L2H_PAE); break;
        case 4: mask = (SHF_L1_64|SHF_FL1_64|SHF_L2_64
                        |SHF_L3_64|SHF_L4_64); break;
        default: BUG();
        }
    }

    hash_vcpu_foreach(v, mask, callbacks, INVALID_MFN);
}

#ifdef CONFIG_PV

void pv_l1tf_tasklet(void *data)
{
    struct domain *d = data;

    domain_pause(d);
    paging_lock(d);

    if ( !paging_mode_sh_forced(d) && !d->is_dying )
    {
        int ret = shadow_one_bit_enable(d, PG_SH_forced);

        if ( ret )
        {
            printk(XENLOG_G_ERR "d%d Failed to enable PG_SH_forced: %d\n",
                   d->domain_id, ret);
            domain_crash(d);
        }
    }

    paging_unlock(d);
    domain_unpause(d);
}

#endif /* CONFIG_PV */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
