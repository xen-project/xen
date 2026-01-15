/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * arch/x86/mm/shadow/oos.c
 *
 * Shadow code dealing with out-of-sync shadows.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#include <asm/shadow.h>

#include "private.h"

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)

#include <xen/trace.h>

/*
 * From time to time, we let a shadowed pagetable page go out of sync
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
 * over-engineer hash tables...).
 *
 * We keep a hash per vcpu, because we want as much as possible to do
 * the re-sync on the same vcpu we did the unsync on.
 */

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_FULL
void sh_oos_audit(struct domain *d)
{
    unsigned int idx, expected_idx, expected_idx_alt;
    struct page_info *pg;
    struct vcpu *v;

    for_each_vcpu(d, v)
    {
        for ( idx = 0; idx < SHADOW_OOS_PAGES; idx++ )
        {
            mfn_t *oos = v->arch.paging.shadow.oos;

            if ( mfn_eq(oos[idx], INVALID_MFN) )
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
            if ( !(pg->count_info & PGC_shadowed_pt) )
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
#endif

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

static int sh_remove_write_access_from_sl1p(struct domain *d, mfn_t gmfn,
                                            mfn_t smfn, unsigned long off)
{
    ASSERT(mfn_valid(smfn));
    ASSERT(mfn_valid(gmfn));

    switch ( mfn_to_page(smfn)->u.sh.type )
    {
    case SH_type_l1_32_shadow:
    case SH_type_fl1_32_shadow:
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p, 2)
            (d, gmfn, smfn, off);

    case SH_type_l1_pae_shadow:
    case SH_type_fl1_pae_shadow:
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p, 3)
            (d, gmfn, smfn, off);

    case SH_type_l1_64_shadow:
    case SH_type_fl1_64_shadow:
        return SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p, 4)
            (d, gmfn, smfn, off);

    default:
        return 0;
    }
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
                if ( mfn_eq(oos_fixup[idx].smfn[i], smfn) &&
                     (oos_fixup[idx].off[i] == off) )
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
                /*
                 * We should flush the TLBs now, because we removed a
                 * writable mapping, but since the shadow is already
                 * OOS we have no problem if another vcpu write to
                 * this page table. We just have to be very careful to
                 * *always* flush the tlbs on resync.
                 */
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
        /*
         * An unfindable writeable typecount has appeared, probably via a
         * grant table entry: can't shoot the mapping, so try to unshadow
         * the page.  If that doesn't work either, the guest is granting
         * his pagetables and must be killed after all.
         * This will flush the tlb, so we can return with no worries.
         */
        shadow_remove_all_shadows(d, gmfn);
        return 1;
    }

    if ( ftlb )
        guest_flush_tlb_mask(d, d->dirty_cpumask);

    return 0;
}

static inline void trace_resync(int event, mfn_t gmfn)
{
    if ( tb_init_done )
    {
        /* Convert gmfn to gfn */
        gfn_t gfn = mfn_to_gfn(current->domain, gmfn);

        trace(event, sizeof(gfn), &gfn);
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
    mfn_t *oos = v->arch.paging.shadow.oos;
    mfn_t *oos_snapshot = v->arch.paging.shadow.oos_snapshot;
    struct oos_fixup *oos_fixup = v->arch.paging.shadow.oos_fixup;
    struct oos_fixup fixup = { .next = 0 };

    for ( i = 0; i < SHADOW_OOS_FIXUPS; i++ )
        fixup.smfn[i] = INVALID_MFN;

    idx = mfn_x(gmfn) % SHADOW_OOS_PAGES;
    oidx = idx;

    if ( !mfn_eq(oos[idx], INVALID_MFN) &&
         (mfn_x(oos[idx]) % SHADOW_OOS_PAGES) == idx )
    {
        /* Punt the current occupant into the next slot */
        SWAP(oos[idx], gmfn);
        SWAP(oos_fixup[idx], fixup);
        swap = 1;
        idx = (idx + 1) % SHADOW_OOS_PAGES;
    }
    if ( !mfn_eq(oos[idx], INVALID_MFN) )
    {
        /* Crush the current occupant. */
        _sh_resync(v, oos[idx], &oos_fixup[idx], oos_snapshot[idx]);
        perfc_incr(shadow_unsync_evict);
    }
    oos[idx] = gmfn;
    oos_fixup[idx] = fixup;

    if ( swap )
        SWAP(oos_snapshot[idx], oos_snapshot[oidx]);

    copy_domain_page(oos_snapshot[oidx], oos[oidx]);
}

/* Remove an MFN from the list of out-of-sync guest pagetables */
void oos_hash_remove(struct domain *d, mfn_t gmfn)
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

/*
 * Figure out whether it's definitely safe not to sync this l1 table,
 * by making a call out to the mode in which that shadow was made.
 */
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

/*
 * Pull all out-of-sync pages back into sync.  Pages brought out of sync
 * on other vcpus are allowed to remain out of sync, but their contents
 * will be made safe (TLB flush semantics); pages unsynced by this vcpu
 * are brought back into sync and write-protected.  If skip != 0, we try
 * to avoid resyncing at all if we think we can get away with it.
 */
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
        if ( !mfn_eq(oos[idx], INVALID_MFN) )
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
            if ( mfn_eq(oos[idx], INVALID_MFN) )
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

/*
 * Allow a shadowed page to go out of sync. Unsyncs are traced in
 * multi.c:sh_page_fault()
 */
int sh_unsync(struct vcpu *v, mfn_t gmfn)
{
    struct page_info *pg;

    ASSERT(paging_locked_by_me(v->domain));

    SHADOW_PRINTK("%pv gmfn=%"PRI_mfn"\n", v, mfn_x(gmfn));

    pg = mfn_to_page(gmfn);

    /*
     * Guest page must be shadowed *only* as L1 and *only* once when out
     * of sync.  Also, get out now if it's already out of sync.
     * Also, can't safely unsync if some vcpus have paging disabled.
     */
    if ( (pg->shadow_flags &
          ((SHF_page_type_mask & ~SHF_L1_ANY) | SHF_out_of_sync)) ||
         sh_page_has_multiple_shadows(pg) ||
         !is_hvm_vcpu(v) ||
         !v->domain->arch.paging.shadow.oos_active )
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
