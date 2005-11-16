/******************************************************************************
 * arch/x86/shadow.c
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


#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/trace.h>

#define MFN_PINNED(_x) (frame_table[_x].u.inuse.type_info & PGT_pinned)
#define va_to_l1mfn(_ed, _va) \
    (l2e_get_pfn(linear_l2_table(_ed)[_va>>L2_PAGETABLE_SHIFT]))

static void shadow_free_snapshot(struct domain *d,
                                 struct out_of_sync_entry *entry);
static void remove_out_of_sync_entries(struct domain *d, unsigned long smfn);
static void free_writable_pte_predictions(struct domain *d);

#if SHADOW_DEBUG
static void mark_shadows_as_reflecting_snapshot(struct domain *d, unsigned long gpfn);
#endif

/********

There's a per-domain shadow table spin lock which works fine for SMP
hosts. We don't have to worry about interrupts as no shadow operations
happen in an interrupt context. It's probably not quite ready for SMP
guest operation as we have to worry about synchonisation between gpte
and spte updates. Its possible that this might only happen in a
hypercall context, in which case we'll probably at have a per-domain
hypercall lock anyhow (at least initially).

********/

static inline int
shadow_promote(struct domain *d, unsigned long gpfn, unsigned long gmfn,
               unsigned long new_type)
{
    struct pfn_info *page = pfn_to_page(gmfn);
    int pinned = 0, okay = 1;

    if ( page_out_of_sync(page) )
    {
        // Don't know how long ago this snapshot was taken.
        // Can't trust it to be recent enough.
        //
        __shadow_sync_mfn(d, gmfn);
    }

    if ( !shadow_mode_refcounts(d) )
        return 1;

    if ( unlikely(page_is_page_table(page)) )
        return 1;

    FSH_LOG("%s: gpfn=%lx gmfn=%lx nt=%08lx", __func__, gpfn, gmfn, new_type);

    if ( !shadow_remove_all_write_access(d, gpfn, gmfn) )
    {
        FSH_LOG("%s: couldn't find/remove all write accesses, gpfn=%lx gmfn=%lx",
                __func__, gpfn, gmfn);
#if 1 || defined(LIVE_DANGEROUSLY)
        set_bit(_PGC_page_table, &page->count_info);
        return 1;
#endif
        return 0;
        
    }

    // To convert this page to use as a page table, the writable count
    // should now be zero.  Test this by grabbing the page as an page table,
    // and then immediately releasing.  This will also deal with any
    // necessary TLB flushing issues for us.
    //
    // The cruft here about pinning doesn't really work right.  This
    // needs rethinking/rewriting...  Need to gracefully deal with the
    // TLB flushes required when promoting a writable page, and also deal
    // with any outstanding (external) writable refs to this page (by
    // refusing to promote it).  The pinning headache complicates this
    // code -- it would all get much simpler if we stop using
    // shadow_lock() and move the shadow code to BIGLOCK().
    //
    if ( unlikely(!get_page(page, d)) )
        BUG(); // XXX -- needs more thought for a graceful failure
    if ( unlikely(test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info)) )
    {
        pinned = 1;
        put_page_and_type(page);
    }
    if ( get_page_type(page, PGT_base_page_table) )
    {
        set_bit(_PGC_page_table, &page->count_info);
        put_page_type(page);
    }
    else
    {
        printk("shadow_promote: get_page_type failed "
               "dom%d gpfn=%lx gmfn=%lx t=%08lx\n",
               d->domain_id, gpfn, gmfn, new_type);
        okay = 0;
    }

    // Now put the type back to writable...
    if ( unlikely(!get_page_type(page, PGT_writable_page)) )
        BUG(); // XXX -- needs more thought for a graceful failure
    if ( unlikely(pinned) )
    {
        if ( unlikely(test_and_set_bit(_PGT_pinned,
                                       &page->u.inuse.type_info)) )
            BUG(); // hmm... someone pinned this again?
    }
    else
        put_page_and_type(page);

    return okay;
}

static inline void
shadow_demote(struct domain *d, unsigned long gpfn, unsigned long gmfn)
{
    if ( !shadow_mode_refcounts(d) )
        return;

    ASSERT(frame_table[gmfn].count_info & PGC_page_table);

    if ( shadow_max_pgtable_type(d, gpfn, NULL) == PGT_none )
    {
        clear_bit(_PGC_page_table, &frame_table[gmfn].count_info);

        if ( page_out_of_sync(pfn_to_page(gmfn)) )
        {
            remove_out_of_sync_entries(d, gmfn);
        }
    }
}

/*
 * Things in shadow mode that collect get_page() refs to the domain's
 * pages are:
 * - PGC_allocated takes a gen count, just like normal.
 * - A writable page can be pinned (paravirtualized guests may consider
 *   these pages to be L1s or L2s, and don't know the difference).
 *   Pinning a page takes a gen count (but, for domains in shadow mode,
 *   it *doesn't* take a type count)
 * - CR3 grabs a ref to whatever it points at, just like normal.
 * - Shadow mode grabs an initial gen count for itself, as a placehold
 *   for whatever references will exist.
 * - Shadow PTEs that point to a page take a gen count, just like regular
 *   PTEs.  However, they don't get a type count, as get_page_type() is
 *   hardwired to keep writable pages' counts at 1 for domains in shadow
 *   mode.
 * - Whenever we shadow a page, the entry in the shadow hash grabs a
 *   general ref to the page.
 * - Whenever a page goes out of sync, the out of sync entry grabs a
 *   general ref to the page.
 */
/*
 * pfn_info fields for pages allocated as shadow pages:
 *
 * All 32 bits of count_info are a simple count of refs to this shadow
 * from a) other shadow pages, b) current CR3's (aka ed->arch.shadow_table),
 * c) if it's a pinned shadow root pgtable, d) outstanding out-of-sync
 * references.
 *
 * u.inuse._domain is left NULL, to prevent accidently allow some random
 * domain from gaining permissions to map this page.
 *
 * u.inuse.type_info & PGT_type_mask remembers what kind of page is being
 * shadowed.
 * u.inuse.type_info & PGT_mfn_mask holds the mfn of the page being shadowed.
 * u.inuse.type_info & PGT_pinned says that an extra reference to this shadow
 * is currently exists because this is a shadow of a root page, and we
 * don't want to let those disappear just because no CR3 is currently pointing
 * at it.
 *
 * tlbflush_timestamp holds a min & max index of valid page table entries
 * within the shadow page.
 */

static inline unsigned long
alloc_shadow_page(struct domain *d,
                  unsigned long gpfn, unsigned long gmfn,
                  u32 psh_type)
{
    struct pfn_info *page;
    unsigned long smfn;
    int pin = 0;

    // Currently, we only keep pre-zero'ed pages around for use as L1's...
    // This will change.  Soon.
    //
    if ( psh_type == PGT_l1_shadow )
    {
        if ( !list_empty(&d->arch.free_shadow_frames) )
        {
            struct list_head *entry = d->arch.free_shadow_frames.next;
            page = list_entry(entry, struct pfn_info, list);
            list_del(entry);
            perfc_decr(free_l1_pages);
        }
        else
        {
            page = alloc_domheap_page(NULL);
            void *l1 = map_domain_page(page_to_pfn(page));
            memset(l1, 0, PAGE_SIZE);
            unmap_domain_page(l1);
        }
    }
    else
        page = alloc_domheap_page(NULL);

    if ( unlikely(page == NULL) )
    {
        printk("Couldn't alloc shadow page! dom%d count=%d\n",
               d->domain_id, d->arch.shadow_page_count);
        printk("Shadow table counts: l1=%d l2=%d hl2=%d snapshot=%d\n",
               perfc_value(shadow_l1_pages), 
               perfc_value(shadow_l2_pages),
               perfc_value(hl2_table_pages),
               perfc_value(snapshot_pages));
        BUG(); /* XXX FIXME: try a shadow flush to free up some memory. */
    }

    smfn = page_to_pfn(page);

    ASSERT( (gmfn & ~PGT_mfn_mask) == 0 );
    page->u.inuse.type_info = psh_type | gmfn;
    page->count_info = 0;
    page->tlbflush_timestamp = 0;

    switch ( psh_type )
    {
    case PGT_l1_shadow:
        if ( !shadow_promote(d, gpfn, gmfn, psh_type) )
            goto fail;
        perfc_incr(shadow_l1_pages);
        d->arch.shadow_page_count++;
        break;

    case PGT_l2_shadow:
        if ( !shadow_promote(d, gpfn, gmfn, psh_type) )
            goto fail;
        perfc_incr(shadow_l2_pages);
        d->arch.shadow_page_count++;
        if ( PGT_l2_page_table == PGT_root_page_table )
            pin = 1;

        break;

    case PGT_hl2_shadow:
        // Treat an hl2 as an L1 for purposes of promotion.
        // For external mode domains, treat them as an L2 for purposes of
        // pinning.
        //
        if ( !shadow_promote(d, gpfn, gmfn, PGT_l1_shadow) )
            goto fail;
        perfc_incr(hl2_table_pages);
        d->arch.hl2_page_count++;
        if ( shadow_mode_external(d) &&
             (PGT_l2_page_table == PGT_root_page_table) )
            pin = 1;

        break;

    case PGT_snapshot:
        perfc_incr(snapshot_pages);
        d->arch.snapshot_page_count++;
        break;

    default:
        printk("Alloc shadow weird page type type=%08x\n", psh_type);
        BUG();
        break;
    }

    // Don't add a new shadow of something that already has a snapshot.
    //
    ASSERT( (psh_type == PGT_snapshot) || !mfn_out_of_sync(gmfn) );

    set_shadow_status(d, gpfn, gmfn, smfn, psh_type);

    if ( pin )
        shadow_pin(smfn);

    return smfn;

  fail:
    FSH_LOG("promotion of pfn=%lx mfn=%lx failed!  external gnttab refs?",
            gpfn, gmfn);
    free_domheap_page(page);
    return 0;
}

static void inline
free_shadow_l1_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *pl1e = map_domain_page(smfn);
    int i;
    struct pfn_info *spage = pfn_to_page(smfn);
    u32 min_max = spage->tlbflush_timestamp;
    int min = SHADOW_MIN(min_max);
    int max = SHADOW_MAX(min_max);

    for ( i = min; i <= max; i++ )
    {
        shadow_put_page_from_l1e(pl1e[i], d);
        pl1e[i] = l1e_empty();
    }

    unmap_domain_page(pl1e);
}

static void inline
free_shadow_hl2_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *hl2 = map_domain_page(smfn);
    int i, limit;

    SH_VVLOG("%s: smfn=%lx freed", __func__, smfn);

#ifdef __i386__
    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
#else
    limit = 0; /* XXX x86/64 XXX */
#endif

    for ( i = 0; i < limit; i++ )
    {
        if ( l1e_get_flags(hl2[i]) & _PAGE_PRESENT )
            put_page(pfn_to_page(l1e_get_pfn(hl2[i])));
    }

    unmap_domain_page(hl2);
}

static void inline
free_shadow_l2_table(struct domain *d, unsigned long smfn, unsigned int type)
{
    l2_pgentry_t *pl2e = map_domain_page(smfn);
    int i, external = shadow_mode_external(d);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( external || is_guest_l2_slot(type, i) )
            if ( l2e_get_flags(pl2e[i]) & _PAGE_PRESENT )
                put_shadow_ref(l2e_get_pfn(pl2e[i]));

    if ( (PGT_base_page_table == PGT_l2_page_table) &&
         shadow_mode_translate(d) && !external )
    {
        // free the ref to the hl2
        //
        put_shadow_ref(l2e_get_pfn(pl2e[l2_table_offset(LINEAR_PT_VIRT_START)]));
    }

    unmap_domain_page(pl2e);
}

void free_shadow_page(unsigned long smfn)
{
    struct pfn_info *page = &frame_table[smfn];
    unsigned long gmfn = page->u.inuse.type_info & PGT_mfn_mask;
    struct domain *d = page_get_owner(pfn_to_page(gmfn));
    unsigned long gpfn = __mfn_to_gpfn(d, gmfn);
    unsigned long type = page->u.inuse.type_info & PGT_type_mask;

    SH_VVLOG("%s: free'ing smfn=%lx", __func__, smfn);

    ASSERT( ! IS_INVALID_M2P_ENTRY(gpfn) );

    delete_shadow_status(d, gpfn, gmfn, type);

    switch ( type )
    {
    case PGT_l1_shadow:
        perfc_decr(shadow_l1_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_l1_table(d, smfn);
        d->arch.shadow_page_count--;
        break;

    case PGT_l2_shadow:
        perfc_decr(shadow_l2_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_l2_table(d, smfn, page->u.inuse.type_info);
        d->arch.shadow_page_count--;
        break;

    case PGT_hl2_shadow:
        perfc_decr(hl2_table_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_hl2_table(d, smfn);
        d->arch.hl2_page_count--;
        break;

    case PGT_snapshot:
        perfc_decr(snapshot_pages);
        d->arch.snapshot_page_count--;
        break;

    default:
        printk("Free shadow weird page type mfn=%lx type=%" PRtype_info "\n",
               page_to_pfn(page), page->u.inuse.type_info);
        break;
    }

    // No TLB flushes are needed the next time this page gets allocated.
    //
    page->tlbflush_timestamp = 0;
    page->u.free.cpumask     = CPU_MASK_NONE;

    if ( type == PGT_l1_shadow )
    {
        list_add(&page->list, &d->arch.free_shadow_frames);
        perfc_incr(free_l1_pages);
    }
    else
        free_domheap_page(page);
}

void
remove_shadow(struct domain *d, unsigned long gpfn, u32 stype)
{
    unsigned long smfn;

    //printk("%s(gpfn=%lx, type=%x)\n", __func__, gpfn, stype);

    shadow_lock(d);

    while ( stype >= PGT_l1_shadow )
    {
        smfn = __shadow_status(d, gpfn, stype);
        if ( smfn && MFN_PINNED(smfn) )
            shadow_unpin(smfn);
        stype -= PGT_l1_shadow;
    }

    shadow_unlock(d);
}

static void inline
release_out_of_sync_entry(struct domain *d, struct out_of_sync_entry *entry)
{
    struct pfn_info *page;

    page = &frame_table[entry->gmfn];
        
    // Decrement ref count of guest & shadow pages
    //
    put_page(page);

    // Only use entries that have low bits clear...
    //
    if ( !(entry->writable_pl1e & (sizeof(l1_pgentry_t)-1)) )
    {
        put_shadow_ref(entry->writable_pl1e >> PAGE_SHIFT);
        entry->writable_pl1e = -2;
    }
    else
        ASSERT( entry->writable_pl1e == -1 );

    // Free the snapshot
    //
    shadow_free_snapshot(d, entry);
}

static void remove_out_of_sync_entries(struct domain *d, unsigned long gmfn)
{
    struct out_of_sync_entry *entry = d->arch.out_of_sync;
    struct out_of_sync_entry **prev = &d->arch.out_of_sync;
    struct out_of_sync_entry *found = NULL;

    // NB: Be careful not to call something that manipulates this list
    //     while walking it.  Collect the results into a separate list
    //     first, then walk that list.
    //
    while ( entry )
    {
        if ( entry->gmfn == gmfn )
        {
            // remove from out of sync list
            *prev = entry->next;

            // add to found list
            entry->next = found;
            found = entry;

            entry = *prev;
            continue;
        }
        prev = &entry->next;
        entry = entry->next;
    }

    prev = NULL;
    entry = found;
    while ( entry )
    {
        release_out_of_sync_entry(d, entry);

        prev = &entry->next;
        entry = entry->next;
    }

    // Add found list to free list
    if ( prev )
    {
        *prev = d->arch.out_of_sync_free;
        d->arch.out_of_sync_free = found;
    }
}

static void free_out_of_sync_state(struct domain *d)
{
    struct out_of_sync_entry *entry;

    // NB: Be careful not to call something that manipulates this list
    //     while walking it.  Remove one item at a time, and always
    //     restart from start of list.
    //
    while ( (entry = d->arch.out_of_sync) )
    {
        d->arch.out_of_sync = entry->next;
        release_out_of_sync_entry(d, entry);

        entry->next = d->arch.out_of_sync_free;
        d->arch.out_of_sync_free = entry;
    }
}

static void free_shadow_pages(struct domain *d)
{
    int                   i;
    struct shadow_status *x;
    struct vcpu          *v;
 
    /*
     * WARNING! The shadow page table must not currently be in use!
     * e.g., You are expected to have paused the domain and synchronized CR3.
     */

    if( !d->arch.shadow_ht ) return;

    shadow_audit(d, 1);

    // first, remove any outstanding refs from out_of_sync entries...
    //
    free_out_of_sync_state(d);

    // second, remove any outstanding refs from v->arch.shadow_table
    // and CR3.
    //
    for_each_vcpu(d, v)
    {
        if ( pagetable_get_paddr(v->arch.shadow_table) )
        {
            put_shadow_ref(pagetable_get_pfn(v->arch.shadow_table));
            v->arch.shadow_table = mk_pagetable(0);
        }

        if ( v->arch.monitor_shadow_ref )
        {
            put_shadow_ref(v->arch.monitor_shadow_ref);
            v->arch.monitor_shadow_ref = 0;
        }
    }

    // For external shadows, remove the monitor table's refs
    //
    if ( shadow_mode_external(d) )
    {
        for_each_vcpu(d, v)
        {
            l2_pgentry_t *mpl2e = v->arch.monitor_vtable;

            if ( mpl2e )
            {
                l2_pgentry_t hl2e = mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)];
                l2_pgentry_t smfn = mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)];

                if ( l2e_get_flags(hl2e) & _PAGE_PRESENT )
                {
                    put_shadow_ref(l2e_get_pfn(hl2e));
                    mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)] = l2e_empty();
                }
                if ( l2e_get_flags(smfn) & _PAGE_PRESENT )
                {
                    put_shadow_ref(l2e_get_pfn(smfn));
                    mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] = l2e_empty();
                }
            }
        }
    }

    // Now, the only refs to shadow pages that are left are from the shadow
    // pages themselves.  We just unpin the pinned pages, and the rest
    // should automatically disappear.
    //
    // NB: Beware: each explicitly or implicit call to free_shadow_page
    // can/will result in the hash bucket getting rewritten out from
    // under us...  First, collect the list of pinned pages, then
    // free them.
    //
    // FIXME: it would be good to just free all the pages referred to in
    // the hash table without going through each of them to decrement their
    // reference counts.  In shadow_mode_refcount(), we've gotta do the hard
    // work, but only for L1 shadows.  If we're not in refcount mode, then
    // there's no real hard work to do at all.  Need to be careful with the
    // writable_pte_predictions and snapshot entries in the hash table, but
    // that's about it.
    //
    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        u32 count;
        unsigned long *mfn_list;

        /* Skip empty buckets. */
        if ( d->arch.shadow_ht[i].gpfn_and_flags == 0 )
            continue;

        count = 0;

        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next ) {
	    /* Skip entries that are writable_pred) */
	    switch(x->gpfn_and_flags & PGT_type_mask){
		case PGT_l1_shadow:
		case PGT_l2_shadow:
		case PGT_l3_shadow:
		case PGT_l4_shadow:
		case PGT_hl2_shadow:
		    if ( MFN_PINNED(x->smfn) )
			count++;
		    break;
		case PGT_snapshot:
		case PGT_writable_pred:
		    break;
		default:
		    BUG();

	    }
	}

        if ( !count )
            continue;

        mfn_list = xmalloc_array(unsigned long, count);
        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next ) {
	    /* Skip entries that are writable_pred) */
	    switch(x->gpfn_and_flags & PGT_type_mask){
		case PGT_l1_shadow:
		case PGT_l2_shadow:
		case PGT_l3_shadow:
		case PGT_l4_shadow:
		case PGT_hl2_shadow:
		    if ( MFN_PINNED(x->smfn) )
			mfn_list[count++] = x->smfn;
		    break;
		case PGT_snapshot:
		case PGT_writable_pred:
		    break;
		default:
		    BUG();

	    }
	}

        while ( count )
        {
            shadow_unpin(mfn_list[--count]);
        }
        xfree(mfn_list);
    }

    // Now free the pre-zero'ed pages from the domain
    //
    struct list_head *list_ent, *tmp;
    list_for_each_safe(list_ent, tmp, &d->arch.free_shadow_frames)
    {
        list_del(list_ent);
        perfc_decr(free_l1_pages);

        struct pfn_info *page = list_entry(list_ent, struct pfn_info, list);
        free_domheap_page(page);
    }

    shadow_audit(d, 0);

    SH_VLOG("Free shadow table.");
}

void shadow_mode_init(void)
{
}

int _shadow_mode_refcounts(struct domain *d)
{
    return shadow_mode_refcounts(d);
}

static void alloc_monitor_pagetable(struct vcpu *v)
{
    unsigned long mmfn;
    l2_pgentry_t *mpl2e;
    struct pfn_info *mmfn_info;
    struct domain *d = v->domain;

    ASSERT(pagetable_get_paddr(v->arch.monitor_table) == 0);

    mmfn_info = alloc_domheap_page(NULL);
    ASSERT(mmfn_info != NULL);

    mmfn = page_to_pfn(mmfn_info);
    mpl2e = (l2_pgentry_t *)map_domain_page(mmfn);
    memset(mpl2e, 0, PAGE_SIZE);

#ifdef __i386__ /* XXX screws x86/64 build */
    memcpy(&mpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
#endif

    mpl2e[l2_table_offset(PERDOMAIN_VIRT_START)] =
        l2e_from_paddr(__pa(d->arch.mm_perdomain_pt),
                        __PAGE_HYPERVISOR);

    // map the phys_to_machine map into the Read-Only MPT space for this domain
    mpl2e[l2_table_offset(RO_MPT_VIRT_START)] =
        l2e_from_paddr(pagetable_get_paddr(d->arch.phys_table),
                        __PAGE_HYPERVISOR);

    // Don't (yet) have mappings for these...
    // Don't want to accidentally see the idle_pg_table's linear mapping.
    //
    mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)] = l2e_empty();
    mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] = l2e_empty();

    v->arch.monitor_table = mk_pagetable(mmfn << PAGE_SHIFT);
    v->arch.monitor_vtable = mpl2e;
}

/*
 * Free the pages for monitor_table and hl2_table
 */
void free_monitor_pagetable(struct vcpu *v)
{
    l2_pgentry_t *mpl2e, hl2e, sl2e;
    unsigned long mfn;

    ASSERT( pagetable_get_paddr(v->arch.monitor_table) );
    
    mpl2e = v->arch.monitor_vtable;

    /*
     * First get the mfn for hl2_table by looking at monitor_table
     */
    hl2e = mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)];
    if ( l2e_get_flags(hl2e) & _PAGE_PRESENT )
    {
        mfn = l2e_get_pfn(hl2e);
        ASSERT(mfn);
        put_shadow_ref(mfn);
    }

    sl2e = mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)];
    if ( l2e_get_flags(sl2e) & _PAGE_PRESENT )
    {
        mfn = l2e_get_pfn(sl2e);
        ASSERT(mfn);
        put_shadow_ref(mfn);
    }

    unmap_domain_page(mpl2e);

    /*
     * Then free monitor_table.
     * Note: for VMX guest, only BSP need do this free.
     */
    if (!(VMX_DOMAIN(v) && v->vcpu_id)) {
        mfn = pagetable_get_pfn(v->arch.monitor_table);
        unmap_domain_page(v->arch.monitor_vtable);
        free_domheap_page(&frame_table[mfn]);
    }

    v->arch.monitor_table = mk_pagetable(0);
    v->arch.monitor_vtable = 0;
}

int
set_p2m_entry(struct domain *d, unsigned long pfn, unsigned long mfn,
              struct domain_mmap_cache *l2cache,
              struct domain_mmap_cache *l1cache)
{
    unsigned long tabpfn = pagetable_get_pfn(d->arch.phys_table);
    l2_pgentry_t *l2, l2e;
    l1_pgentry_t *l1;
    struct pfn_info *l1page;
    unsigned long va = pfn << PAGE_SHIFT;

    ASSERT(tabpfn != 0);
    ASSERT(shadow_lock_is_acquired(d));

    l2 = map_domain_page_with_cache(tabpfn, l2cache);
    l2e = l2[l2_table_offset(va)];
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
    {
        l1page = alloc_domheap_page(NULL);
        if ( !l1page )
        {
            unmap_domain_page_with_cache(l2, l2cache);
            return 0;
        }

        l1 = map_domain_page_with_cache(page_to_pfn(l1page), l1cache);
        memset(l1, 0, PAGE_SIZE);
        unmap_domain_page_with_cache(l1, l1cache);

        l2e = l2e_from_page(l1page, __PAGE_HYPERVISOR);
        l2[l2_table_offset(va)] = l2e;
    }
    unmap_domain_page_with_cache(l2, l2cache);

    l1 = map_domain_page_with_cache(l2e_get_pfn(l2e), l1cache);
    l1[l1_table_offset(va)] = l1e_from_pfn(mfn, __PAGE_HYPERVISOR);
    unmap_domain_page_with_cache(l1, l1cache);

    return 1;
}

static int
alloc_p2m_table(struct domain *d)
{
    struct list_head *list_ent;
    struct pfn_info *page, *l2page;
    l2_pgentry_t *l2;
    unsigned long mfn, pfn;
    struct domain_mmap_cache l1cache, l2cache;

    l2page = alloc_domheap_page(NULL);
    if ( l2page == NULL )
        return 0;

    domain_mmap_cache_init(&l1cache);
    domain_mmap_cache_init(&l2cache);

    d->arch.phys_table = mk_pagetable(page_to_phys(l2page));
    l2 = map_domain_page_with_cache(page_to_pfn(l2page), &l2cache);
    memset(l2, 0, PAGE_SIZE);
    unmap_domain_page_with_cache(l2, &l2cache);

    list_ent = d->page_list.next;
    while ( list_ent != &d->page_list )
    {
        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);
        pfn = get_pfn_from_mfn(mfn);
        ASSERT(pfn != INVALID_M2P_ENTRY);
        ASSERT(pfn < (1u<<20));

        set_p2m_entry(d, pfn, mfn, &l2cache, &l1cache);

        list_ent = page->list.next;
    }

    list_ent = d->xenpage_list.next;
    while ( list_ent != &d->xenpage_list )
    {
        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);
        pfn = get_pfn_from_mfn(mfn);
        if ( (pfn != INVALID_M2P_ENTRY) &&
             (pfn < (1u<<20)) )
        {
            set_p2m_entry(d, pfn, mfn, &l2cache, &l1cache);
        }

        list_ent = page->list.next;
    }

    domain_mmap_cache_destroy(&l2cache);
    domain_mmap_cache_destroy(&l1cache);

    return 1;
}

static void
free_p2m_table(struct domain *d)
{
    // uh, this needs some work...  :)
    BUG();
}

int __shadow_mode_enable(struct domain *d, unsigned int mode)
{
    struct vcpu *v;
    int new_modes = (mode & ~d->arch.shadow_mode);

    // Gotta be adding something to call this function.
    ASSERT(new_modes);

    // can't take anything away by calling this function.
    ASSERT(!(d->arch.shadow_mode & ~mode));

    for_each_vcpu(d, v)
    {
        invalidate_shadow_ldt(v);

        // We need to set these up for __update_pagetables().
        // See the comment there.

        /*
         * arch.guest_vtable
         */
        if ( v->arch.guest_vtable &&
             (v->arch.guest_vtable != __linear_l2_table) )
        {
            unmap_domain_page(v->arch.guest_vtable);
        }
        if ( (mode & (SHM_translate | SHM_external)) == SHM_translate )
            v->arch.guest_vtable = __linear_l2_table;
        else
            v->arch.guest_vtable = NULL;

        /*
         * arch.shadow_vtable
         */
        if ( v->arch.shadow_vtable &&
             (v->arch.shadow_vtable != __shadow_linear_l2_table) )
        {
            unmap_domain_page(v->arch.shadow_vtable);
        }
        if ( !(mode & SHM_external) )
            v->arch.shadow_vtable = __shadow_linear_l2_table;
        else
            v->arch.shadow_vtable = NULL;

        /*
         * arch.hl2_vtable
         */
        if ( v->arch.hl2_vtable &&
             (v->arch.hl2_vtable != __linear_hl2_table) )
        {
            unmap_domain_page(v->arch.hl2_vtable);
        }
        if ( (mode & (SHM_translate | SHM_external)) == SHM_translate )
            v->arch.hl2_vtable = __linear_hl2_table;
        else
            v->arch.hl2_vtable = NULL;

        /*
         * arch.monitor_table & arch.monitor_vtable
         */
        if ( v->arch.monitor_vtable )
        {
            free_monitor_pagetable(v);
        }
        if ( mode & SHM_external )
        {
            alloc_monitor_pagetable(v);
        }
    }

    if ( new_modes & SHM_enable )
    {
        ASSERT( !d->arch.shadow_ht );
        d->arch.shadow_ht = xmalloc_array(struct shadow_status, shadow_ht_buckets);
        if ( d->arch.shadow_ht == NULL )
            goto nomem;

        memset(d->arch.shadow_ht, 0,
           shadow_ht_buckets * sizeof(struct shadow_status));
    }

    if ( new_modes & SHM_log_dirty )
    {
        ASSERT( !d->arch.shadow_dirty_bitmap );
        d->arch.shadow_dirty_bitmap_size = 
            (d->shared_info->arch.max_pfn +  63) & ~63;
        d->arch.shadow_dirty_bitmap = 
            xmalloc_array(unsigned long, d->arch.shadow_dirty_bitmap_size /
                                         (8 * sizeof(unsigned long)));
        if ( d->arch.shadow_dirty_bitmap == NULL )
        {
            d->arch.shadow_dirty_bitmap_size = 0;
            goto nomem;
        }
        memset(d->arch.shadow_dirty_bitmap, 0, 
               d->arch.shadow_dirty_bitmap_size/8);
    }

    if ( new_modes & SHM_translate )
    {
        if ( !(new_modes & SHM_external) )
        {
            ASSERT( !pagetable_get_paddr(d->arch.phys_table) );
            if ( !alloc_p2m_table(d) )
            {
                printk("alloc_p2m_table failed (out-of-memory?)\n");
                goto nomem;
            }
        }
        else
        {
            // external guests provide their own memory for their P2M maps.
            //
            ASSERT( d == page_get_owner(
                        &frame_table[pagetable_get_pfn(d->arch.phys_table)]) );
        }
    }

    // Get rid of any shadow pages from any previous shadow mode.
    //
    free_shadow_pages(d);

    /*
     * Tear down it's counts by disassembling its page-table-based ref counts.
     * Also remove CR3's gcount/tcount.
     * That leaves things like GDTs and LDTs and external refs in tact.
     *
     * Most pages will be writable tcount=0.
     * Some will still be L1 tcount=0 or L2 tcount=0.
     * Maybe some pages will be type none tcount=0.
     * Pages granted external writable refs (via grant tables?) will
     * still have a non-zero tcount.  That's OK.
     *
     * gcounts will generally be 1 for PGC_allocated.
     * GDTs and LDTs will have additional gcounts.
     * Any grant-table based refs will still be in the gcount.
     *
     * We attempt to grab writable refs to each page (thus setting its type).
     * Immediately put back those type refs.
     *
     * Assert that no pages are left with L1/L2/L3/L4 type.
     */
    audit_adjust_pgtables(d, -1, 1);

    d->arch.shadow_mode = mode;

    if ( shadow_mode_refcounts(d) )
    {
        struct list_head *list_ent = d->page_list.next;
        while ( list_ent != &d->page_list )
        {
            struct pfn_info *page = list_entry(list_ent, struct pfn_info, list);
            if ( !get_page_type(page, PGT_writable_page) )
                BUG();
            put_page_type(page);
            /*
             * We use tlbflush_timestamp as back pointer to smfn, and need to
             * clean up it.
             */
            if ( shadow_mode_external(d) )
                page->tlbflush_timestamp = 0;
            list_ent = page->list.next;
        }
    }

    audit_adjust_pgtables(d, 1, 1);

    return 0;

 nomem:
    if ( (new_modes & SHM_enable) )
    {
        xfree(d->arch.shadow_ht);
        d->arch.shadow_ht = NULL;
    }
    if ( (new_modes & SHM_log_dirty) )
    {
        xfree(d->arch.shadow_dirty_bitmap);
        d->arch.shadow_dirty_bitmap = NULL;
    }
    if ( (new_modes & SHM_translate) && !(new_modes & SHM_external) &&
         pagetable_get_paddr(d->arch.phys_table) )
    {
        free_p2m_table(d);
    }
    return -ENOMEM;
}

int shadow_mode_enable(struct domain *d, unsigned int mode)
{
    int rc;
    shadow_lock(d);
    rc = __shadow_mode_enable(d, mode);
    shadow_unlock(d);
    return rc;
}

static void
translate_l1pgtable(struct domain *d, l1_pgentry_t *p2m, unsigned long l1mfn)
{
    int i;
    l1_pgentry_t *l1;

    l1 = map_domain_page(l1mfn);
    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( is_guest_l1_slot(i) &&
             (l1e_get_flags(l1[i]) & _PAGE_PRESENT) )
        {
            unsigned long mfn = l1e_get_pfn(l1[i]);
            unsigned long gpfn = __mfn_to_gpfn(d, mfn);
            ASSERT(l1e_get_pfn(p2m[gpfn]) == mfn);
            l1[i] = l1e_from_pfn(gpfn, l1e_get_flags(l1[i]));
        }
    }
    unmap_domain_page(l1);
}

// This is not general enough to handle arbitrary pagetables
// with shared L1 pages, etc., but it is sufficient for bringing
// up dom0.
//
void
translate_l2pgtable(struct domain *d, l1_pgentry_t *p2m, unsigned long l2mfn,
                    unsigned int type)
{
    int i;
    l2_pgentry_t *l2;

    ASSERT(shadow_mode_translate(d) && !shadow_mode_external(d));

    l2 = map_domain_page(l2mfn);
    for (i = 0; i < L2_PAGETABLE_ENTRIES; i++)
    {
        if ( is_guest_l2_slot(type, i) &&
             (l2e_get_flags(l2[i]) & _PAGE_PRESENT) )
        {
            unsigned long mfn = l2e_get_pfn(l2[i]);
            unsigned long gpfn = __mfn_to_gpfn(d, mfn);
            ASSERT(l1e_get_pfn(p2m[gpfn]) == mfn);
            l2[i] = l2e_from_pfn(gpfn, l2e_get_flags(l2[i]));
            translate_l1pgtable(d, p2m, mfn);
        }
    }
    unmap_domain_page(l2);
}

static void free_shadow_ht_entries(struct domain *d)
{
    struct shadow_status *x, *n;

    SH_VLOG("freed tables count=%d l1=%d l2=%d",
            d->arch.shadow_page_count, perfc_value(shadow_l1_pages), 
            perfc_value(shadow_l2_pages));

    n = d->arch.shadow_ht_extras;
    while ( (x = n) != NULL )
    {
        d->arch.shadow_extras_count--;
        n = *((struct shadow_status **)(&x[shadow_ht_extra_size]));
        xfree(x);
    }

    d->arch.shadow_ht_extras = NULL;
    d->arch.shadow_ht_free = NULL;

    ASSERT(d->arch.shadow_extras_count == 0);
    SH_VLOG("freed extras, now %d", d->arch.shadow_extras_count);

    if ( d->arch.shadow_dirty_bitmap != NULL )
    {
        xfree(d->arch.shadow_dirty_bitmap);
        d->arch.shadow_dirty_bitmap = 0;
        d->arch.shadow_dirty_bitmap_size = 0;
    }

    xfree(d->arch.shadow_ht);
    d->arch.shadow_ht = NULL;
}

static void free_out_of_sync_entries(struct domain *d)
{
    struct out_of_sync_entry *x, *n;

    n = d->arch.out_of_sync_extras;
    while ( (x = n) != NULL )
    {
        d->arch.out_of_sync_extras_count--;
        n = *((struct out_of_sync_entry **)(&x[out_of_sync_extra_size]));
        xfree(x);
    }

    d->arch.out_of_sync_extras = NULL;
    d->arch.out_of_sync_free = NULL;
    d->arch.out_of_sync = NULL;

    ASSERT(d->arch.out_of_sync_extras_count == 0);
    FSH_LOG("freed extra out_of_sync entries, now %d",
            d->arch.out_of_sync_extras_count);
}

void __shadow_mode_disable(struct domain *d)
{
    if ( unlikely(!shadow_mode_enabled(d)) )
        return;

    free_shadow_pages(d);
    free_writable_pte_predictions(d);

#ifndef NDEBUG
    int i;
    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        if ( d->arch.shadow_ht[i].gpfn_and_flags != 0 )
        {
            printk("%s: d->arch.shadow_ht[%x].gpfn_and_flags=%lx\n",
                   __FILE__, i, d->arch.shadow_ht[i].gpfn_and_flags);
            BUG();
        }
    }
#endif

    d->arch.shadow_mode = 0;

    free_shadow_ht_entries(d);
    free_out_of_sync_entries(d);

    struct vcpu *v;
    for_each_vcpu(d, v)
    {
        update_pagetables(v);
    }
}

static int shadow_mode_table_op(
    struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int      op = sc->op;
    int               i, rc = 0;
    struct vcpu *v;

    ASSERT(shadow_lock_is_acquired(d));

    SH_VLOG("shadow mode table op %lx %lx count %d",
            (unsigned long)pagetable_get_pfn(d->vcpu[0]->arch.guest_table),  /* XXX SMP */
            (unsigned long)pagetable_get_pfn(d->vcpu[0]->arch.shadow_table), /* XXX SMP */
            d->arch.shadow_page_count);

    shadow_audit(d, 1);

    switch ( op )
    {
    case DOM0_SHADOW_CONTROL_OP_FLUSH:
        free_shadow_pages(d);

        d->arch.shadow_fault_count       = 0;
        d->arch.shadow_dirty_count       = 0;
        d->arch.shadow_dirty_net_count   = 0;
        d->arch.shadow_dirty_block_count = 0;

        break;
   
    case DOM0_SHADOW_CONTROL_OP_CLEAN:
        free_shadow_pages(d);

        sc->stats.fault_count       = d->arch.shadow_fault_count;
        sc->stats.dirty_count       = d->arch.shadow_dirty_count;
        sc->stats.dirty_net_count   = d->arch.shadow_dirty_net_count;
        sc->stats.dirty_block_count = d->arch.shadow_dirty_block_count;

        d->arch.shadow_fault_count       = 0;
        d->arch.shadow_dirty_count       = 0;
        d->arch.shadow_dirty_net_count   = 0;
        d->arch.shadow_dirty_block_count = 0;
 
        if ( (sc->dirty_bitmap == NULL) || 
             (d->arch.shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }

        if(sc->pages > d->arch.shadow_dirty_bitmap_size)
            sc->pages = d->arch.shadow_dirty_bitmap_size; 

#define chunk (8*1024) /* Transfer and clear in 1kB chunks for L1 cache. */
        for ( i = 0; i < sc->pages; i += chunk )
        {
            int bytes = ((((sc->pages - i) > chunk) ?
                          chunk : (sc->pages - i)) + 7) / 8;
     
            if (copy_to_user(
                    sc->dirty_bitmap + (i/(8*sizeof(unsigned long))),
                    d->arch.shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
                    bytes))
            {
                rc = -EINVAL;
                break;
            }

            memset(
                d->arch.shadow_dirty_bitmap + (i/(8*sizeof(unsigned long))),
                0, bytes);
        }

        break;

    case DOM0_SHADOW_CONTROL_OP_PEEK:
        sc->stats.fault_count       = d->arch.shadow_fault_count;
        sc->stats.dirty_count       = d->arch.shadow_dirty_count;
        sc->stats.dirty_net_count   = d->arch.shadow_dirty_net_count;
        sc->stats.dirty_block_count = d->arch.shadow_dirty_block_count;
 

        if ( (sc->dirty_bitmap == NULL) || 
             (d->arch.shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }
 
        if(sc->pages > d->arch.shadow_dirty_bitmap_size)
            sc->pages = d->arch.shadow_dirty_bitmap_size; 

        if (copy_to_user(sc->dirty_bitmap, 
                         d->arch.shadow_dirty_bitmap, (sc->pages+7)/8))
        {
            rc = -EINVAL;
            break;
        }

        break;

    default:
        rc = -EINVAL;
        break;
    }

    SH_VLOG("shadow mode table op : page count %d", d->arch.shadow_page_count);
    shadow_audit(d, 1);

    for_each_vcpu(d,v)
        __update_pagetables(v);

    return rc;
}

int shadow_mode_control(struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int op = sc->op;
    int          rc = 0;
    struct vcpu *v;

    if ( unlikely(d == current->domain) )
    {
        DPRINTK("Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }   

    domain_pause(d);

    shadow_lock(d);

    switch ( op )
    {
    case DOM0_SHADOW_CONTROL_OP_OFF:
        __shadow_sync_all(d);
        __shadow_mode_disable(d);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_TEST:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(d, SHM_enable);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(
            d, d->arch.shadow_mode|SHM_enable|SHM_log_dirty);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_TRANSLATE:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(
            d, d->arch.shadow_mode|SHM_enable|SHM_refcounts|SHM_translate);
        break;

    default:
        rc = shadow_mode_enabled(d) ? shadow_mode_table_op(d, sc) : -EINVAL;
        break;
    }

    shadow_unlock(d);

    for_each_vcpu(d,v)
        update_pagetables(v);

    domain_unpause(d);

    return rc;
}

unsigned long
gpfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
    ASSERT( shadow_mode_translate(d) );

    perfc_incrc(gpfn_to_mfn_foreign);

    unsigned long va = gpfn << PAGE_SHIFT;
    unsigned long tabpfn = pagetable_get_pfn(d->arch.phys_table);
    l2_pgentry_t *l2 = map_domain_page(tabpfn);
    l2_pgentry_t l2e = l2[l2_table_offset(va)];
    unmap_domain_page(l2);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
    {
        printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%lx) => 0 l2e=%" PRIpte "\n",
               d->domain_id, gpfn, l2e_get_intpte(l2e));
        return INVALID_MFN;
    }
    l1_pgentry_t *l1 = map_domain_page(l2e_get_pfn(l2e));
    l1_pgentry_t l1e = l1[l1_table_offset(va)];
    unmap_domain_page(l1);

#if 0
    printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%lx) => %lx tabpfn=%lx l2e=%lx l1tab=%lx, l1e=%lx\n",
           d->domain_id, gpfn, l1_pgentry_val(l1e) >> PAGE_SHIFT, tabpfn, l2e, l1tab, l1e);
#endif

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) )
    {
        printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%lx) => 0 l1e=%" PRIpte "\n",
               d->domain_id, gpfn, l1e_get_intpte(l1e));
        return INVALID_MFN;
    }

    return l1e_get_pfn(l1e);
}

static unsigned long
shadow_hl2_table(struct domain *d, unsigned long gpfn, unsigned long gmfn,
                unsigned long smfn)
{
    unsigned long hl2mfn;
    l1_pgentry_t *hl2;
    int limit;

    ASSERT(PGT_base_page_table == PGT_l2_page_table);

    if ( unlikely(!(hl2mfn = alloc_shadow_page(d, gpfn, gmfn, PGT_hl2_shadow))) )
    {
        printk("Couldn't alloc an HL2 shadow for pfn=%lx mfn=%lx\n",
               gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    SH_VVLOG("shadow_hl2_table(gpfn=%lx, gmfn=%lx, smfn=%lx) => %lx",
             gpfn, gmfn, smfn, hl2mfn);
    perfc_incrc(shadow_hl2_table_count);

    hl2 = map_domain_page(hl2mfn);

    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;

    memset(hl2, 0, limit * sizeof(l1_pgentry_t));

    if ( !shadow_mode_external(d) )
    {
        memset(&hl2[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 0,
               HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

        // Setup easy access to the GL2, SL2, and HL2 frames.
        //
        hl2[l2_table_offset(LINEAR_PT_VIRT_START)] =
            l1e_from_pfn(gmfn, __PAGE_HYPERVISOR);
        hl2[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l1e_from_pfn(smfn, __PAGE_HYPERVISOR);
        hl2[l2_table_offset(PERDOMAIN_VIRT_START)] =
            l1e_from_pfn(hl2mfn, __PAGE_HYPERVISOR);
    }

    unmap_domain_page(hl2);

    return hl2mfn;
}

/*
 * This could take and use a snapshot, and validate the entire page at
 * once, or it could continue to fault in entries one at a time...
 * Might be worth investigating...
 */
static unsigned long shadow_l2_table(
    struct domain *d, unsigned long gpfn, unsigned long gmfn)
{
    unsigned long smfn;
    l2_pgentry_t *spl2e;

    SH_VVLOG("shadow_l2_table(gpfn=%lx, gmfn=%lx)", gpfn, gmfn);

    perfc_incrc(shadow_l2_table_count);

    if ( unlikely(!(smfn = alloc_shadow_page(d, gpfn, gmfn, PGT_l2_shadow))) )
    {
        printk("Couldn't alloc an L2 shadow for pfn=%lx mfn=%lx\n",
               gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    spl2e = (l2_pgentry_t *)map_domain_page(smfn);

    /* Install hypervisor and 2x linear p.t. mapings. */
    if ( (PGT_base_page_table == PGT_l2_page_table) &&
         !shadow_mode_external(d) )
    {
        /*
         * We could proactively fill in PDEs for pages that are already
         * shadowed *and* where the guest PDE has _PAGE_ACCESSED set
         * (restriction required for coherence of the accessed bit). However,
         * we tried it and it didn't help performance. This is simpler. 
         */
        memset(spl2e, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE*sizeof(l2_pgentry_t));

        /* Install hypervisor and 2x linear p.t. mapings. */
        memcpy(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
               &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
               HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

        spl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l2e_from_pfn(smfn, __PAGE_HYPERVISOR);

        spl2e[l2_table_offset(PERDOMAIN_VIRT_START)] =
            l2e_from_paddr(__pa(page_get_owner(&frame_table[gmfn])->arch.mm_perdomain_pt),
                            __PAGE_HYPERVISOR);

        if ( shadow_mode_translate(d) ) // NB: not external
        {
            unsigned long hl2mfn;

            spl2e[l2_table_offset(RO_MPT_VIRT_START)] =
                l2e_from_paddr(pagetable_get_paddr(d->arch.phys_table),
                                __PAGE_HYPERVISOR);

            if ( unlikely(!(hl2mfn = __shadow_status(d, gpfn, PGT_hl2_shadow))) )
                hl2mfn = shadow_hl2_table(d, gpfn, gmfn, smfn);

            // shadow_mode_translate (but not external) sl2 tables hold a
            // ref to their hl2.
            //
            if ( !get_shadow_ref(hl2mfn) )
                BUG();
            
            spl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
                l2e_from_pfn(hl2mfn, __PAGE_HYPERVISOR);
        }
        else
            spl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
                l2e_from_pfn(gmfn, __PAGE_HYPERVISOR);
    }
    else
    {
        memset(spl2e, 0, L2_PAGETABLE_ENTRIES*sizeof(l2_pgentry_t));        
    }

    unmap_domain_page(spl2e);

    SH_VLOG("shadow_l2_table(%lx -> %lx)", gmfn, smfn);
    return smfn;
}

void shadow_map_l1_into_current_l2(unsigned long va)
{ 
    struct vcpu *v = current;
    struct domain *d = v->domain;
    l1_pgentry_t *gpl1e, *spl1e;
    l2_pgentry_t gl2e, sl2e;
    unsigned long gl1pfn, gl1mfn, sl1mfn;
    int i, init_table = 0;

    __guest_get_l2e(v, va, &gl2e);
    ASSERT(l2e_get_flags(gl2e) & _PAGE_PRESENT);
    gl1pfn = l2e_get_pfn(gl2e);

    if ( !(sl1mfn = __shadow_status(d, gl1pfn, PGT_l1_shadow)) )
    {
        /* This L1 is NOT already shadowed so we need to shadow it. */
        SH_VVLOG("4a: l1 not shadowed");

        gl1mfn = __gpfn_to_mfn(d, gl1pfn);
        if ( unlikely(!VALID_MFN(gl1mfn)) )
        {
            // Attempt to use an invalid pfn as an L1 page.
            // XXX this needs to be more graceful!
            BUG();
        }

        if ( unlikely(!(sl1mfn =
                        alloc_shadow_page(d, gl1pfn, gl1mfn, PGT_l1_shadow))) )
        {
            printk("Couldn't alloc an L1 shadow for pfn=%lx mfn=%lx\n",
                   gl1pfn, gl1mfn);
            BUG(); /* XXX Need to deal gracefully with failure. */
        }

        perfc_incrc(shadow_l1_table_count);
        init_table = 1;
    }
    else
    {
        /* This L1 is shadowed already, but the L2 entry is missing. */
        SH_VVLOG("4b: was shadowed, l2 missing (%lx)", sl1mfn);
    }

#ifndef NDEBUG
    l2_pgentry_t old_sl2e;
    __shadow_get_l2e(v, va, &old_sl2e);
    ASSERT( !(l2e_get_flags(old_sl2e) & _PAGE_PRESENT) );
#endif

    if ( !get_shadow_ref(sl1mfn) )
        BUG();
    l2pde_general(d, &gl2e, &sl2e, sl1mfn);
    __guest_set_l2e(v, va, gl2e);
    __shadow_set_l2e(v, va, sl2e);

    if ( init_table )
    {
        l1_pgentry_t sl1e;
        int index = l1_table_offset(va);
        int min = 1, max = 0;

        gpl1e = &(linear_pg_table[l1_linear_offset(va) &
                              ~(L1_PAGETABLE_ENTRIES-1)]);

        spl1e = &(shadow_linear_pg_table[l1_linear_offset(va) &
                                     ~(L1_PAGETABLE_ENTRIES-1)]);

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            l1pte_propagate_from_guest(d, gpl1e[i], &sl1e);
            if ( (l1e_get_flags(sl1e) & _PAGE_PRESENT) &&
                 unlikely(!shadow_get_page_from_l1e(sl1e, d)) )
                sl1e = l1e_empty();
            if ( l1e_get_flags(sl1e) == 0 )
            {
                // First copy entries from 0 until first invalid.
                // Then copy entries from index until first invalid.
                //
                if ( i < index ) {
                    i = index - 1;
                    continue;
                }
                break;
            }
            spl1e[i] = sl1e;
            if ( unlikely(i < min) )
                min = i;
            if ( likely(i > max) )
                max = i;
            set_guest_back_ptr(d, sl1e, sl1mfn, i);
        }

        frame_table[sl1mfn].tlbflush_timestamp =
            SHADOW_ENCODE_MIN_MAX(min, max);
    }
}

void shadow_invlpg(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;
    l1_pgentry_t gpte, spte;

    ASSERT(shadow_mode_enabled(d));

    shadow_lock(d);

    __shadow_sync_va(v, va);

    // XXX mafetter: will need to think about 4MB pages...

    // It's not strictly necessary to update the shadow here,
    // but it might save a fault later.
    //
    if (__copy_from_user(&gpte, &linear_pg_table[va >> PAGE_SHIFT],
                         sizeof(gpte))) {
        perfc_incrc(shadow_invlpg_faults);
        shadow_unlock(d);
        return;
    }
    l1pte_propagate_from_guest(d, gpte, &spte);
    shadow_set_l1e(va, spte, 1);

    shadow_unlock(d);
}

struct out_of_sync_entry *
shadow_alloc_oos_entry(struct domain *d)
{
    struct out_of_sync_entry *f, *extra;
    unsigned size, i;

    if ( unlikely(d->arch.out_of_sync_free == NULL) )
    {
        FSH_LOG("Allocate more fullshadow tuple blocks.");

        size = sizeof(void *) + (out_of_sync_extra_size * sizeof(*f));
        extra = xmalloc_bytes(size);

        /* XXX Should be more graceful here. */
        if ( extra == NULL )
            BUG();

        memset(extra, 0, size);

        /* Record the allocation block so it can be correctly freed later. */
        d->arch.out_of_sync_extras_count++;
        *((struct out_of_sync_entry **)&extra[out_of_sync_extra_size]) = 
            d->arch.out_of_sync_extras;
        d->arch.out_of_sync_extras = &extra[0];

        /* Thread a free chain through the newly-allocated nodes. */
        for ( i = 0; i < (out_of_sync_extra_size - 1); i++ )
            extra[i].next = &extra[i+1];
        extra[i].next = NULL;

        /* Add the new nodes to the free list. */
        d->arch.out_of_sync_free = &extra[0];
    }

    /* Allocate a new node from the quicklist. */
    f = d->arch.out_of_sync_free;
    d->arch.out_of_sync_free = f->next;

    return f;
}

static inline unsigned long
shadow_make_snapshot(
    struct domain *d, unsigned long gpfn, unsigned long gmfn)
{
    unsigned long smfn, sl1mfn = 0;
    void *original, *snapshot;
    u32 min_max = 0;
    int min, max, length;

    if ( test_and_set_bit(_PGC_out_of_sync, &frame_table[gmfn].count_info) )
    {
        ASSERT(__shadow_status(d, gpfn, PGT_snapshot));
        return SHADOW_SNAPSHOT_ELSEWHERE;
    }

    perfc_incrc(shadow_make_snapshot);

    if ( unlikely(!(smfn = alloc_shadow_page(d, gpfn, gmfn, PGT_snapshot))) )
    {
        printk("Couldn't alloc fullshadow snapshot for pfn=%lx mfn=%lx!\n"
               "Dom%d snapshot_count_count=%d\n",
               gpfn, gmfn, d->domain_id, d->arch.snapshot_page_count);
        BUG(); /* XXX FIXME: try a shadow flush to free up some memory. */
    }

    if ( !get_shadow_ref(smfn) )
        BUG();

    if ( shadow_mode_refcounts(d) &&
         (shadow_max_pgtable_type(d, gpfn, &sl1mfn) == PGT_l1_shadow) )
        min_max = pfn_to_page(sl1mfn)->tlbflush_timestamp;
    pfn_to_page(smfn)->tlbflush_timestamp = min_max;

    min = SHADOW_MIN(min_max);
    max = SHADOW_MAX(min_max);
    length = max - min + 1;
    perfc_incr_histo(snapshot_copies, length, PT_UPDATES);

    min *= sizeof(l1_pgentry_t);
    length *= sizeof(l1_pgentry_t);

    original = map_domain_page(gmfn);
    snapshot = map_domain_page(smfn);
    memcpy(snapshot + min, original + min, length);
    unmap_domain_page(original);
    unmap_domain_page(snapshot);

    return smfn;
}

static void
shadow_free_snapshot(struct domain *d, struct out_of_sync_entry *entry)
{
    void *snapshot;

    if ( entry->snapshot_mfn == SHADOW_SNAPSHOT_ELSEWHERE )
        return;

    // Clear the out_of_sync bit.
    //
    clear_bit(_PGC_out_of_sync, &frame_table[entry->gmfn].count_info);

    // XXX Need to think about how to protect the domain's
    // information less expensively.
    //
    snapshot = map_domain_page(entry->snapshot_mfn);
    memset(snapshot, 0, PAGE_SIZE);
    unmap_domain_page(snapshot);

    put_shadow_ref(entry->snapshot_mfn);
}

struct out_of_sync_entry *
__shadow_mark_mfn_out_of_sync(struct vcpu *v, unsigned long gpfn,
                             unsigned long mfn)
{
    struct domain *d = v->domain;
    struct pfn_info *page = &frame_table[mfn];
    struct out_of_sync_entry *entry = shadow_alloc_oos_entry(d);

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(pfn_valid(mfn));

#ifndef NDEBUG
    u32 type = page->u.inuse.type_info & PGT_type_mask;
    if ( shadow_mode_refcounts(d) )
    {
        ASSERT(type == PGT_writable_page);
    }
    else
    {
        ASSERT(type && (type < PGT_l4_page_table));
    }
#endif

    FSH_LOG("%s(gpfn=%lx, mfn=%lx) c=%08x t=%08lx", __func__,
            gpfn, mfn, page->count_info, page->u.inuse.type_info);

    // XXX this will require some more thought...  Cross-domain sharing and
    //     modification of page tables?  Hmm...
    //
    if ( d != page_get_owner(page) )
        BUG();

    perfc_incrc(shadow_mark_mfn_out_of_sync_calls);

    entry->v = v;
    entry->gpfn = gpfn;
    entry->gmfn = mfn;
    entry->writable_pl1e = -1;

#if SHADOW_DEBUG
    mark_shadows_as_reflecting_snapshot(d, gpfn);
#endif

    // increment guest's ref count to represent the entry in the
    // full shadow out-of-sync list.
    //
    get_page(page, d);

    return entry;
}

struct out_of_sync_entry *
shadow_mark_mfn_out_of_sync(struct vcpu *v, unsigned long gpfn,
                             unsigned long mfn)
{
    struct out_of_sync_entry *entry =
      __shadow_mark_mfn_out_of_sync(v, gpfn, mfn);
    struct domain *d = v->domain;

    entry->snapshot_mfn = shadow_make_snapshot(d, gpfn, mfn);
    // Add to the out-of-sync list
    //
    entry->next = d->arch.out_of_sync;
    d->arch.out_of_sync = entry;

    return entry;
}

void shadow_mark_va_out_of_sync(
    struct vcpu *v, unsigned long gpfn, unsigned long mfn, unsigned long va)
{
    struct out_of_sync_entry *entry =
        __shadow_mark_mfn_out_of_sync(v, gpfn, mfn);
    l2_pgentry_t sl2e;
    struct domain *d = v->domain;

    // We need the address of shadow PTE that maps @va.
    // It might not exist yet.  Make sure it's there.
    //
    __shadow_get_l2e(v, va, &sl2e);
    if ( !(l2e_get_flags(sl2e) & _PAGE_PRESENT) )
    {
        // either this L1 isn't shadowed yet, or the shadow isn't linked into
        // the current L2.
        shadow_map_l1_into_current_l2(va);
        __shadow_get_l2e(v, va, &sl2e);
    }
    ASSERT(l2e_get_flags(sl2e) & _PAGE_PRESENT);

    entry->snapshot_mfn = shadow_make_snapshot(d, gpfn, mfn);
    // NB: this is stored as a machine address.
    entry->writable_pl1e =
        l2e_get_paddr(sl2e) | (sizeof(l1_pgentry_t) * l1_table_offset(va));
    ASSERT( !(entry->writable_pl1e & (sizeof(l1_pgentry_t)-1)) );
    entry->va = va;

    // Increment shadow's page count to represent the reference
    // inherent in entry->writable_pl1e
    //
    if ( !get_shadow_ref(l2e_get_pfn(sl2e)) )
        BUG();

    // Add to the out-of-sync list
    //
    entry->next = d->arch.out_of_sync;
    d->arch.out_of_sync = entry;

    FSH_LOG("mark_out_of_sync(va=%lx -> writable_pl1e=%lx)",
            va, entry->writable_pl1e);
}

/*
 * Returns 1 if the snapshot for @gmfn exists and its @index'th entry matches.
 * Returns 0 otherwise.
 */
static int snapshot_entry_matches(
    struct domain *d, l1_pgentry_t *guest_pt,
    unsigned long gpfn, unsigned index)
{
    unsigned long smfn = __shadow_status(d, gpfn, PGT_snapshot);
    l1_pgentry_t *snapshot, gpte; // could be L1s or L2s or ...
    int entries_match;

    perfc_incrc(snapshot_entry_matches_calls);

    if ( !smfn )
        return 0;

    snapshot = map_domain_page(smfn);

    if (__copy_from_user(&gpte, &guest_pt[index],
                         sizeof(gpte))) {
        unmap_domain_page(snapshot);
        return 0;
    }

    // This could probably be smarter, but this is sufficent for
    // our current needs.
    //
    entries_match = !l1e_has_changed(gpte, snapshot[index],
                                     PAGE_FLAG_MASK);

    unmap_domain_page(snapshot);

#ifdef PERF_COUNTERS
    if ( entries_match )
        perfc_incrc(snapshot_entry_matches_true);
#endif

    return entries_match;
}

/*
 * Returns 1 if va's shadow mapping is out-of-sync.
 * Returns 0 otherwise.
 */
int __shadow_out_of_sync(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;
    unsigned long l2mfn = pagetable_get_pfn(v->arch.guest_table);
    unsigned long l2pfn = __mfn_to_gpfn(d, l2mfn);
    l2_pgentry_t l2e;
    unsigned long l1pfn, l1mfn;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(VALID_M2P(l2pfn));

    perfc_incrc(shadow_out_of_sync_calls);

    if ( page_out_of_sync(&frame_table[l2mfn]) &&
         !snapshot_entry_matches(d, (l1_pgentry_t *)v->arch.guest_vtable,
                                 l2pfn, l2_table_offset(va)) )
        return 1;

    __guest_get_l2e(v, va, &l2e);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 0;

    l1pfn = l2e_get_pfn(l2e);
    l1mfn = __gpfn_to_mfn(d, l1pfn);

    // If the l1 pfn is invalid, it can't be out of sync...
    if ( !VALID_MFN(l1mfn) )
        return 0;

    if ( page_out_of_sync(&frame_table[l1mfn]) &&
         !snapshot_entry_matches(
             d, &linear_pg_table[l1_linear_offset(va) & ~(L1_PAGETABLE_ENTRIES-1)],
             l1pfn, l1_table_offset(va)) )
        return 1;

    return 0;
}

#define GPFN_TO_GPTEPAGE(_gpfn) ((_gpfn) / (PAGE_SIZE / sizeof(l1_pgentry_t)))
static inline unsigned long
predict_writable_pte_page(struct domain *d, unsigned long gpfn)
{
    return __shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), PGT_writable_pred);
}

static inline void
increase_writable_pte_prediction(struct domain *d, unsigned long gpfn, unsigned long prediction)
{
    unsigned long score = prediction & PGT_score_mask;
    int create = (score == 0);

    // saturating addition
    score = (score + (1u << PGT_score_shift)) & PGT_score_mask;
    score = score ? score : PGT_score_mask;

    prediction = (prediction & PGT_mfn_mask) | score;

    //printk("increase gpfn=%lx pred=%lx create=%d\n", gpfn, prediction, create);
    set_shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), 0, prediction, PGT_writable_pred);

    if ( create )
        perfc_incr(writable_pte_predictions);
}

static inline void
decrease_writable_pte_prediction(struct domain *d, unsigned long gpfn, unsigned long prediction)
{
    unsigned long score = prediction & PGT_score_mask;
    ASSERT(score);

    // divide score by 2...  We don't like bad predictions.
    //
    score = (score >> 1) & PGT_score_mask;

    prediction = (prediction & PGT_mfn_mask) | score;

    //printk("decrease gpfn=%lx pred=%lx score=%lx\n", gpfn, prediction, score);

    if ( score )
        set_shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), 0, prediction, PGT_writable_pred);
    else
    {
        delete_shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), 0, PGT_writable_pred);
        perfc_decr(writable_pte_predictions);
    }
}

static void
free_writable_pte_predictions(struct domain *d)
{
    int i;
    struct shadow_status *x;

    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        u32 count;
        unsigned long *gpfn_list;

        /* Skip empty buckets. */
        if ( d->arch.shadow_ht[i].gpfn_and_flags == 0 )
            continue;

        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next )
            if ( (x->gpfn_and_flags & PGT_type_mask) == PGT_writable_pred )
                count++;

        gpfn_list = xmalloc_array(unsigned long, count);
        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next )
            if ( (x->gpfn_and_flags & PGT_type_mask) == PGT_writable_pred )
                gpfn_list[count++] = x->gpfn_and_flags & PGT_mfn_mask;

        while ( count )
        {
            count--;
            /* delete_shadow_status() may do a shadow_audit(), so we need to
             * keep an accurate count of writable_pte_predictions to keep it
             * happy.
             */
            delete_shadow_status(d, gpfn_list[count], 0, PGT_writable_pred);
            perfc_decr(writable_pte_predictions);
        }

        xfree(gpfn_list);
    }
}

static int fix_entry(
    struct domain *d, 
    l1_pgentry_t *pt, u32 *found, int is_l1_shadow, u32 max_refs_to_find)
{
    l1_pgentry_t old = *pt;
    l1_pgentry_t new = old;

    l1e_remove_flags(new,_PAGE_RW);
    if ( is_l1_shadow && !shadow_get_page_from_l1e(new, d) )
        BUG();
    (*found)++;
    *pt = new;
    if ( is_l1_shadow )
        shadow_put_page_from_l1e(old, d);

    return (*found == max_refs_to_find);
}

static u32 remove_all_write_access_in_ptpage(
    struct domain *d, unsigned long pt_pfn, unsigned long pt_mfn,
    unsigned long readonly_gpfn, unsigned long readonly_gmfn,
    u32 max_refs_to_find, unsigned long prediction)
{
    l1_pgentry_t *pt = map_domain_page(pt_mfn);
    l1_pgentry_t match;
    unsigned long flags = _PAGE_RW | _PAGE_PRESENT;
    int i;
    u32 found = 0;
    int is_l1_shadow =
        ((frame_table[pt_mfn].u.inuse.type_info & PGT_type_mask) ==
         PGT_l1_shadow);

    match = l1e_from_pfn(readonly_gmfn, flags);

    if ( shadow_mode_external(d) ) {
        i = (frame_table[readonly_gmfn].u.inuse.type_info & PGT_va_mask) 
            >> PGT_va_shift;

        if ( (i >= 0 && i <= L1_PAGETABLE_ENTRIES) &&
             !l1e_has_changed(pt[i], match, flags) && 
             fix_entry(d, &pt[i], &found, is_l1_shadow, max_refs_to_find) &&
             !prediction )
            goto out;
    }

    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( unlikely(!l1e_has_changed(pt[i], match, flags)) && 
             fix_entry(d, &pt[i], &found, is_l1_shadow, max_refs_to_find) )
            break;
    }

out:
    unmap_domain_page(pt);

    return found;
}

int shadow_remove_all_write_access(
    struct domain *d, unsigned long readonly_gpfn, unsigned long readonly_gmfn)
{
    int i;
    struct shadow_status *a;
    u32 found = 0, write_refs;
    unsigned long predicted_smfn;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(VALID_MFN(readonly_gmfn));

    perfc_incrc(remove_write_access);

    // If it's not a writable page, then no writable refs can be outstanding.
    //
    if ( (frame_table[readonly_gmfn].u.inuse.type_info & PGT_type_mask) !=
         PGT_writable_page )
    {
        perfc_incrc(remove_write_not_writable);
        return 1;
    }

    // How many outstanding writable PTEs for this page are there?
    //
    write_refs =
        (frame_table[readonly_gmfn].u.inuse.type_info & PGT_count_mask);
    if ( write_refs && MFN_PINNED(readonly_gmfn) )
    {
        write_refs--;
    }

    if ( write_refs == 0 )
    {
        perfc_incrc(remove_write_no_work);
        return 1;
    }
    
    if ( shadow_mode_external(d) ) {
        if (write_refs-- == 0) 
            return 0;

         // Use the back pointer to locate the shadow page that can contain
         // the PTE of interest
         if ( (predicted_smfn = frame_table[readonly_gmfn].tlbflush_timestamp) ) {
             found += remove_all_write_access_in_ptpage(
                 d, predicted_smfn, predicted_smfn, readonly_gpfn, readonly_gmfn, write_refs, 0);
             if ( found == write_refs )
                 return 0;
         }
    }

    // Search all the shadow L1 page tables...
    //
    for (i = 0; i < shadow_ht_buckets; i++)
    {
        a = &d->arch.shadow_ht[i];
        while ( a && a->gpfn_and_flags )
        {
            if ( (a->gpfn_and_flags & PGT_type_mask) == PGT_l1_shadow )
            {
                found += remove_all_write_access_in_ptpage(d, a->gpfn_and_flags & PGT_mfn_mask, a->smfn, readonly_gpfn, readonly_gmfn, write_refs - found, a->gpfn_and_flags & PGT_mfn_mask);
                if ( found == write_refs )
                    return 0;
            }

            a = a->next;
        }
    }

    FSH_LOG("%s: looking for %d refs, found %d refs",
            __func__, write_refs, found);

    return 0;
}

static u32 remove_all_access_in_page(
    struct domain *d, unsigned long l1mfn, unsigned long forbidden_gmfn)
{
    l1_pgentry_t *pl1e = map_domain_page(l1mfn);
    l1_pgentry_t match, ol2e;
    unsigned long flags  = _PAGE_PRESENT;
    int i;
    u32 count = 0;
    int is_l1_shadow =
        ((frame_table[l1mfn].u.inuse.type_info & PGT_type_mask) ==
         PGT_l1_shadow);

    match = l1e_from_pfn(forbidden_gmfn, flags);
    
    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( l1e_has_changed(pl1e[i], match, flags) )
            continue;

        ol2e = pl1e[i];
        pl1e[i] = l1e_empty();
        count++;

        if ( is_l1_shadow )
            shadow_put_page_from_l1e(ol2e, d);
        else /* must be an hl2 page */
            put_page(&frame_table[forbidden_gmfn]);
    }

    unmap_domain_page(pl1e);

    return count;
}

u32 shadow_remove_all_access(struct domain *d, unsigned long forbidden_gmfn)
{
    int i;
    struct shadow_status *a;
    u32 count = 0;

    if ( unlikely(!shadow_mode_enabled(d)) )
        return 0;

    ASSERT(shadow_lock_is_acquired(d));
    perfc_incrc(remove_all_access);

    for (i = 0; i < shadow_ht_buckets; i++)
    {
        a = &d->arch.shadow_ht[i];
        while ( a && a->gpfn_and_flags )
        {
            switch (a->gpfn_and_flags & PGT_type_mask)
            {
            case PGT_l1_shadow:
            case PGT_l2_shadow:
            case PGT_l3_shadow:
            case PGT_l4_shadow:
            case PGT_hl2_shadow:
                count += remove_all_access_in_page(d, a->smfn, forbidden_gmfn);
                break;
            case PGT_snapshot:
            case PGT_writable_pred:
                // these can't hold refs to the forbidden page
                break;
            default:
                BUG();
            }

            a = a->next;
        }
    }

    return count;
}    

static int resync_all(struct domain *d, u32 stype)
{
    struct out_of_sync_entry *entry;
    unsigned i;
    unsigned long smfn;
    void *guest, *shadow, *snapshot;
    int need_flush = 0, external = shadow_mode_external(d);
    int unshadow;
    int changed;

    ASSERT(shadow_lock_is_acquired(d));

    for ( entry = d->arch.out_of_sync; entry; entry = entry->next)
    {
        if ( entry->snapshot_mfn == SHADOW_SNAPSHOT_ELSEWHERE )
            continue;

        smfn = __shadow_status(d, entry->gpfn, stype);

        if ( !smfn )
        {
            // For heavy weight shadows: no need to update refcounts if
            // there's no shadow page.
            //
            if ( shadow_mode_refcounts(d) )
                continue;

            // For light weight shadows: only need up resync the refcounts to
            // the new contents of the guest page iff this it has the right
            // page type.
            //
            if ( stype != ( pfn_to_page(entry->gmfn)->u.inuse.type_info & PGT_type_mask) )
                continue;
        }

        FSH_LOG("resyncing t=%08x gpfn=%lx gmfn=%lx smfn=%lx snapshot_mfn=%lx",
                stype, entry->gpfn, entry->gmfn, smfn, entry->snapshot_mfn);

        // Compare guest's new contents to its snapshot, validating
        // and updating its shadow as appropriate.
        //
        guest    = map_domain_page(entry->gmfn);
        snapshot = map_domain_page(entry->snapshot_mfn);

        if ( smfn )
            shadow = map_domain_page(smfn);
        else
            shadow = NULL;

        unshadow = 0;

        switch ( stype ) {
        case PGT_l1_shadow:
        {
            l1_pgentry_t *guest1 = guest;
            l1_pgentry_t *shadow1 = shadow;
            l1_pgentry_t *snapshot1 = snapshot;
            int unshadow_l1 = 0;

            ASSERT(shadow_mode_write_l1(d) ||
                   shadow_mode_write_all(d) || shadow_mode_wr_pt_pte(d));

            if ( !shadow_mode_refcounts(d) )
                revalidate_l1(d, guest1, snapshot1);

            if ( !smfn )
                break;

            u32 min_max_shadow = pfn_to_page(smfn)->tlbflush_timestamp;
            int min_shadow = SHADOW_MIN(min_max_shadow);
            int max_shadow = SHADOW_MAX(min_max_shadow);

            u32 min_max_snapshot =
                pfn_to_page(entry->snapshot_mfn)->tlbflush_timestamp;
            int min_snapshot = SHADOW_MIN(min_max_snapshot);
            int max_snapshot = SHADOW_MAX(min_max_snapshot);

            changed = 0;

            for ( i = min_shadow; i <= max_shadow; i++ )
            {
                if ( (i < min_snapshot) || (i > max_snapshot) ||
                     l1e_has_changed(guest1[i], snapshot1[i], PAGE_FLAG_MASK) )
                {
                    int error;

                    error = validate_pte_change(d, guest1[i], &shadow1[i]);
                    if ( error ==  -1 ) 
                        unshadow_l1 = 1;
                    else {
                        need_flush |= error;
                        set_guest_back_ptr(d, shadow1[i], smfn, i);
                    }

                    // can't update snapshots of linear page tables -- they
                    // are used multiple times...
                    //
                    // snapshot[i] = new_pte;
                    changed++;
                }
            }
            perfc_incrc(resync_l1);
            perfc_incr_histo(wpt_updates, changed, PT_UPDATES);
            perfc_incr_histo(l1_entries_checked, max_shadow - min_shadow + 1, PT_UPDATES);
            if (unshadow_l1) {
                l2_pgentry_t l2e;

                __shadow_get_l2e(entry->v, entry->va, &l2e);
                if (l2e_get_flags(l2e) & _PAGE_PRESENT) {
                    l2e_remove_flags(l2e, _PAGE_PRESENT);
                    __shadow_set_l2e(entry->v, entry->va, l2e);

                    if (entry->v == current)
                        need_flush = 1;
                }
            }

            break;
        }
        case PGT_l2_shadow:
        {
            int max = -1;

            l2_pgentry_t *guest2 = guest;
            l2_pgentry_t *shadow2 = shadow;
            l2_pgentry_t *snapshot2 = snapshot;

            ASSERT(shadow_mode_write_all(d) || shadow_mode_wr_pt_pte(d));
            BUG_ON(!shadow_mode_refcounts(d)); // not yet implemented

            changed = 0;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            {
#if CONFIG_X86_PAE
                BUG();  /* FIXME: need type_info */
#endif
                if ( !is_guest_l2_slot(0,i) && !external )
                    continue;

                l2_pgentry_t new_pde = guest2[i];
                if ( l2e_has_changed(new_pde, snapshot2[i], PAGE_FLAG_MASK))
                {
                    need_flush |= validate_pde_change(d, new_pde, &shadow2[i]);

                    // can't update snapshots of linear page tables -- they
                    // are used multiple times...
                    //
                    // snapshot[i] = new_pde;

                    changed++;
                }
                if ( l2e_get_intpte(new_pde) != 0 ) /* FIXME: check flags? */
                    max = i;

                // XXX - This hack works for linux guests.
                //       Need a better solution long term.
                if ( !(l2e_get_flags(new_pde) & _PAGE_PRESENT) &&
                     unlikely(l2e_get_intpte(new_pde) != 0) &&
                     !unshadow && MFN_PINNED(smfn) )
                    unshadow = 1;
            }
            if ( max == -1 )
                unshadow = 1;
            perfc_incrc(resync_l2);
            perfc_incr_histo(shm_l2_updates, changed, PT_UPDATES);
            break;
        }
        case PGT_hl2_shadow:
        {
            l2_pgentry_t *guest2 = guest;
            l2_pgentry_t *snapshot2 = snapshot;
            l1_pgentry_t *shadow2 = shadow;
            
            ASSERT(shadow_mode_write_all(d) || shadow_mode_wr_pt_pte(d));
            BUG_ON(!shadow_mode_refcounts(d)); // not yet implemented

            changed = 0;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            {
#if CONFIG_X86_PAE
                BUG();  /* FIXME: need type_info */
#endif
                if ( !is_guest_l2_slot(0, i) && !external )
                    continue;

                l2_pgentry_t new_pde = guest2[i];
                if ( l2e_has_changed(new_pde, snapshot2[i], PAGE_FLAG_MASK) )
                {
                    need_flush |= validate_hl2e_change(d, new_pde, &shadow2[i]);

                    // can't update snapshots of linear page tables -- they
                    // are used multiple times...
                    //
                    // snapshot[i] = new_pde;

                    changed++;
                }
            }
            perfc_incrc(resync_hl2);
            perfc_incr_histo(shm_hl2_updates, changed, PT_UPDATES);
            break;
        }
        default:
            BUG();
        }

        if ( smfn )
            unmap_domain_page(shadow);
        unmap_domain_page(snapshot);
        unmap_domain_page(guest);

        if ( unlikely(unshadow) )
        {
            perfc_incrc(unshadow_l2_count);
            shadow_unpin(smfn);
            if ( unlikely(shadow_mode_external(d)) )
            {
                unsigned long hl2mfn;

                if ( (hl2mfn = __shadow_status(d, entry->gpfn, PGT_hl2_shadow)) &&
                     MFN_PINNED(hl2mfn) )
                    shadow_unpin(hl2mfn);
            }
        }
    }

    return need_flush;
}

void __shadow_sync_all(struct domain *d)
{
    struct out_of_sync_entry *entry;
    int need_flush = 0;

    perfc_incrc(shadow_sync_all);

    ASSERT(shadow_lock_is_acquired(d));

    // First, remove all write permissions to the page tables
    //
    for ( entry = d->arch.out_of_sync; entry; entry = entry->next)
    {
        // Skip entries that have low bits set...  Those aren't
        // real PTEs.
        //
        if ( entry->writable_pl1e & (sizeof(l1_pgentry_t)-1) )
            continue;

        l1_pgentry_t *ppte = (l1_pgentry_t *)(
            (char *)map_domain_page(entry->writable_pl1e >> PAGE_SHIFT) +
            (entry->writable_pl1e & ~PAGE_MASK));
        l1_pgentry_t opte = *ppte;
        l1_pgentry_t npte = opte;
        l1e_remove_flags(npte, _PAGE_RW);

        if ( (l1e_get_flags(npte) & _PAGE_PRESENT) &&
             !shadow_get_page_from_l1e(npte, d) )
            BUG();
        *ppte = npte;
        set_guest_back_ptr(d, npte, (entry->writable_pl1e) >> PAGE_SHIFT, 
                           (entry->writable_pl1e & ~PAGE_MASK)/sizeof(l1_pgentry_t));
        shadow_put_page_from_l1e(opte, d);

        unmap_domain_page(ppte);
    }

    // XXX mafetter: SMP
    //
    // With the current algorithm, we've gotta flush all the TLBs
    // before we can safely continue.  I don't think we want to
    // do it this way, so I think we should consider making
    // entirely private copies of the shadow for each vcpu, and/or
    // possibly having a mix of private and shared shadow state
    // (any path from a PTE that grants write access to an out-of-sync
    // page table page needs to be vcpu private).
    //
#if 0 // this should be enabled for SMP guests...
    flush_tlb_mask(cpu_online_map);
#endif
    need_flush = 1;

    // Second, resync all L1 pages, then L2 pages, etc...
    //
    need_flush |= resync_all(d, PGT_l1_shadow);
    if ( shadow_mode_translate(d) )
        need_flush |= resync_all(d, PGT_hl2_shadow);
    need_flush |= resync_all(d, PGT_l2_shadow);

    if ( need_flush && !unlikely(shadow_mode_external(d)) )
        local_flush_tlb();

    free_out_of_sync_state(d);
}

int shadow_fault(unsigned long va, struct cpu_user_regs *regs)
{
    l1_pgentry_t gpte, spte, orig_gpte;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    l2_pgentry_t gpde;

    spte = l1e_empty();

    SH_VVLOG("shadow_fault( va=%lx, code=%lu )",
             va, (unsigned long)regs->error_code);
    perfc_incrc(shadow_fault_calls);
    
    check_pagetable(v, "pre-sf");

    /*
     * Don't let someone else take the guest's table pages out-of-sync.
     */
    shadow_lock(d);

    /* XXX - FIX THIS COMMENT!!!
     * STEP 1. Check to see if this fault might have been caused by an
     *         out-of-sync table page entry, or if we should pass this
     *         fault onto the guest.
     */
    __shadow_sync_va(v, va);

    /*
     * STEP 2. Check the guest PTE.
     */
    __guest_get_l2e(v, va, &gpde);
    if ( unlikely(!(l2e_get_flags(gpde) & _PAGE_PRESENT)) )
    {
        SH_VVLOG("shadow_fault - EXIT: L1 not present");
        perfc_incrc(shadow_fault_bail_pde_not_present);
        goto fail;
    }

    // This can't fault because we hold the shadow lock and we've ensured that
    // the mapping is in-sync, so the check of the PDE's present bit, above,
    // covers this access.
    //
    orig_gpte = gpte = linear_pg_table[l1_linear_offset(va)];
    if ( unlikely(!(l1e_get_flags(gpte) & _PAGE_PRESENT)) )
    {
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%" PRIpte ")",
                 l1e_get_intpte(gpte));
        perfc_incrc(shadow_fault_bail_pte_not_present);
        goto fail;
    }

    /* Write fault? */
    if ( regs->error_code & 2 )  
    {
        int allow_writes = 0;

        if ( unlikely(!(l1e_get_flags(gpte) & _PAGE_RW)) )
        {
            if ( shadow_mode_page_writable(va, regs, l1e_get_pfn(gpte)) )
            {
                allow_writes = 1;
                l1e_add_flags(gpte, _PAGE_RW);
            }
            else
            {
                /* Write fault on a read-only mapping. */
                SH_VVLOG("shadow_fault - EXIT: wr fault on RO page (%" PRIpte ")", 
                         l1e_get_intpte(gpte));
                perfc_incrc(shadow_fault_bail_ro_mapping);
                goto fail;
            }
        }
        else if ( unlikely(!shadow_mode_wr_pt_pte(d) && mfn_is_page_table(l1e_get_pfn(gpte))) )
        {
            SH_LOG("l1pte_write_fault: no write access to page table page");
            domain_crash_synchronous();
        }

        if ( unlikely(!l1pte_write_fault(v, &gpte, &spte, va)) )
        {
            SH_VVLOG("shadow_fault - EXIT: l1pte_write_fault failed");
            perfc_incrc(write_fault_bail);
            shadow_unlock(d);
            return 0;
        }

        if ( allow_writes )
            l1e_remove_flags(gpte, _PAGE_RW);
    }
    else
    {
        if ( !l1pte_read_fault(d, &gpte, &spte) )
        {
            SH_VVLOG("shadow_fault - EXIT: l1pte_read_fault failed");
            perfc_incrc(read_fault_bail);
            shadow_unlock(d);
            return 0;
        }
    }

    /*
     * STEP 3. Write the modified shadow PTE and guest PTE back to the tables.
     */
    if ( l1e_has_changed(orig_gpte, gpte, PAGE_FLAG_MASK) )
    {
        /* XXX Watch out for read-only L2 entries! (not used in Linux). */
        if ( unlikely(__copy_to_user(&linear_pg_table[l1_linear_offset(va)],
                                     &gpte, sizeof(gpte))) )
        {
            printk("%s() failed, crashing domain %d "
                   "due to a read-only L2 page table (gpde=%" PRIpte "), va=%lx\n",
                   __func__,d->domain_id, l2e_get_intpte(gpde), va);
            domain_crash_synchronous();
        }

        // if necessary, record the page table page as dirty
        if ( unlikely(shadow_mode_log_dirty(d)) )
            __mark_dirty(d, __gpfn_to_mfn(d, l2e_get_pfn(gpde)));
    }

    shadow_set_l1e(va, spte, 1);

    perfc_incrc(shadow_fault_fixed);
    d->arch.shadow_fault_count++;

    shadow_unlock(d);

    check_pagetable(v, "post-sf");
    return EXCRET_fault_fixed;

 fail:
    shadow_unlock(d);
    return 0;
}

void shadow_l1_normal_pt_update(
    struct domain *d,
    unsigned long pa, l1_pgentry_t gpte,
    struct domain_mmap_cache *cache)
{
    unsigned long sl1mfn;    
    l1_pgentry_t *spl1e, spte;

    shadow_lock(d);

    sl1mfn = __shadow_status(current->domain, pa >> PAGE_SHIFT, PGT_l1_shadow);
    if ( sl1mfn )
    {
        SH_VVLOG("shadow_l1_normal_pt_update pa=%p, gpte=%" PRIpte,
                 (void *)pa, l1e_get_intpte(gpte));
        l1pte_propagate_from_guest(current->domain, gpte, &spte);

        spl1e = map_domain_page_with_cache(sl1mfn, cache);
        spl1e[(pa & ~PAGE_MASK) / sizeof(l1_pgentry_t)] = spte;
        unmap_domain_page_with_cache(spl1e, cache);
    }

    shadow_unlock(d);
}

void shadow_l2_normal_pt_update(
    struct domain *d,
    unsigned long pa, l2_pgentry_t gpde,
    struct domain_mmap_cache *cache)
{
    unsigned long sl2mfn;
    l2_pgentry_t *spl2e;

    shadow_lock(d);

    sl2mfn = __shadow_status(current->domain, pa >> PAGE_SHIFT, PGT_l2_shadow);
    if ( sl2mfn )
    {
        SH_VVLOG("shadow_l2_normal_pt_update pa=%p, gpde=%" PRIpte,
                 (void *)pa, l2e_get_intpte(gpde));
        spl2e = map_domain_page_with_cache(sl2mfn, cache);
        validate_pde_change(d, gpde,
                            &spl2e[(pa & ~PAGE_MASK) / sizeof(l2_pgentry_t)]);
        unmap_domain_page_with_cache(spl2e, cache);
    }

    shadow_unlock(d);
}

#if CONFIG_PAGING_LEVELS >= 3
void shadow_l3_normal_pt_update(
    struct domain *d,
    unsigned long pa, l3_pgentry_t gpde,
    struct domain_mmap_cache *cache)
{
    BUG(); // not yet implemented
}
#endif

#if CONFIG_PAGING_LEVELS >= 4
void shadow_l4_normal_pt_update(
    struct domain *d,
    unsigned long pa, l4_pgentry_t gpde,
    struct domain_mmap_cache *cache)
{
    BUG(); // not yet implemented
}
#endif

int shadow_do_update_va_mapping(unsigned long va,
                                l1_pgentry_t val,
                                struct vcpu *v)
{
    struct domain *d = v->domain;
    l1_pgentry_t spte;
    int rc = 0;

    shadow_lock(d);

    //printk("%s(va=%p, val=%p)\n", __func__, (void *)va, (void *)l1e_get_intpte(val));
        
    // This is actually overkill - we don't need to sync the L1 itself,
    // just everything involved in getting to this L1 (i.e. we need
    // linear_pg_table[l1_linear_offset(va)] to be in sync)...
    //
    __shadow_sync_va(v, va);

    l1pte_propagate_from_guest(d, val, &spte);
    shadow_set_l1e(va, spte, 0);

    /*
     * If we're in log-dirty mode then we need to note that we've updated
     * the PTE in the PT-holding page. We need the machine frame number
     * for this.
     */
    if ( shadow_mode_log_dirty(d) )
        __mark_dirty(d, va_to_l1mfn(v, va));

// out:
    shadow_unlock(d);

    return rc;
}


/*
 * What lives where in the 32-bit address space in the various shadow modes,
 * and what it uses to get/maintain that mapping.
 *
 * SHADOW MODE:      none         enable         translate         external
 * 
 * 4KB things:
 * guest_vtable    lin_l2     mapped per gl2   lin_l2 via hl2   mapped per gl2
 * shadow_vtable     n/a         sh_lin_l2       sh_lin_l2      mapped per gl2
 * hl2_vtable        n/a            n/a        lin_hl2 via hl2  mapped per gl2
 * monitor_vtable    n/a            n/a             n/a           mapped once
 *
 * 4MB things:
 * guest_linear  lin via gl2    lin via gl2      lin via hl2      lin via hl2
 * shadow_linear     n/a      sh_lin via sl2   sh_lin via sl2   sh_lin via sl2
 * monitor_linear    n/a            n/a             n/a              ???
 * perdomain      perdomain      perdomain       perdomain        perdomain
 * R/O M2P         R/O M2P        R/O M2P           n/a              n/a
 * R/W M2P         R/W M2P        R/W M2P         R/W M2P          R/W M2P
 * P2M               n/a            n/a           R/O M2P          R/O M2P
 *
 * NB:
 * update_pagetables(), __update_pagetables(), shadow_mode_enable(),
 * shadow_l2_table(), shadow_hl2_table(), and alloc_monitor_pagetable()
 * all play a part in maintaining these mappings.
 */
void __update_pagetables(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long gmfn = pagetable_get_pfn(v->arch.guest_table);
    unsigned long gpfn = __mfn_to_gpfn(d, gmfn);
    unsigned long smfn, hl2mfn, old_smfn;

    int max_mode = ( shadow_mode_external(d) ? SHM_external
                     : shadow_mode_translate(d) ? SHM_translate
                     : shadow_mode_enabled(d) ? SHM_enable
                     : 0 );

    ASSERT( ! IS_INVALID_M2P_ENTRY(gpfn) );
    ASSERT( max_mode );

    /*
     *  arch.guest_vtable
     */
    if ( max_mode & (SHM_enable | SHM_external) )
    {
        if ( likely(v->arch.guest_vtable != NULL) )
            unmap_domain_page(v->arch.guest_vtable);
        v->arch.guest_vtable = map_domain_page(gmfn);
    }

    /*
     *  arch.shadow_table
     */
    if ( unlikely(!(smfn = __shadow_status(d, gpfn, PGT_base_page_table))) )
        smfn = shadow_l2_table(d, gpfn, gmfn);
    if ( !get_shadow_ref(smfn) )
        BUG();
    old_smfn = pagetable_get_pfn(v->arch.shadow_table);
    v->arch.shadow_table = mk_pagetable(smfn << PAGE_SHIFT);
    if ( old_smfn )
        put_shadow_ref(old_smfn);

    SH_VVLOG("__update_pagetables(gmfn=%lx, smfn=%lx)", gmfn, smfn);

    /*
     * arch.shadow_vtable
     */
    if ( max_mode == SHM_external )
    {
        if ( v->arch.shadow_vtable )
            unmap_domain_page(v->arch.shadow_vtable);
        v->arch.shadow_vtable = map_domain_page(smfn);
    }

    /*
     * arch.hl2_vtable
     */

    // if max_mode == SHM_translate, then the hl2 is already installed
    // correctly in its smfn, and there's nothing to do.
    //
    if ( max_mode == SHM_external )
    {
        if ( unlikely(!(hl2mfn = __shadow_status(d, gpfn, PGT_hl2_shadow))) )
            hl2mfn = shadow_hl2_table(d, gpfn, gmfn, smfn);
        if ( v->arch.hl2_vtable )
            unmap_domain_page(v->arch.hl2_vtable);
        v->arch.hl2_vtable = map_domain_page(hl2mfn);
    }

    /*
     * fixup pointers in monitor table, as necessary
     */
    if ( max_mode == SHM_external )
    {
        l2_pgentry_t *mpl2e = v->arch.monitor_vtable;
        l2_pgentry_t old_hl2e = mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)];
        l2_pgentry_t old_sl2e = mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)];

        ASSERT( shadow_mode_translate(d) );

        if ( !get_shadow_ref(hl2mfn) )
            BUG();
        mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
            l2e_from_pfn(hl2mfn, __PAGE_HYPERVISOR);
        if ( l2e_get_flags(old_hl2e) & _PAGE_PRESENT )
            put_shadow_ref(l2e_get_pfn(old_hl2e));

        if ( !get_shadow_ref(smfn) )
            BUG();
        mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l2e_from_pfn(smfn, __PAGE_HYPERVISOR);
        if ( l2e_get_flags(old_sl2e) & _PAGE_PRESENT )
            put_shadow_ref(l2e_get_pfn(old_sl2e));

        // XXX - maybe this can be optimized somewhat??
        local_flush_tlb();
    }
}


/************************************************************************/
/************************************************************************/
/************************************************************************/

#if SHADOW_DEBUG

// The following is entirely for _check_pagetable()'s benefit.
// _check_pagetable() wants to know whether a given entry in a
// shadow page table is supposed to be the shadow of the guest's
// current entry, or the shadow of the entry held in the snapshot
// taken above.
//
// Here, we mark all currently existing entries as reflecting
// the snapshot, above.  All other places in xen that update
// the shadow will keep the shadow in sync with the guest's
// entries (via l1pte_propagate_from_guest and friends), which clear
// the SHADOW_REFLECTS_SNAPSHOT bit.
//
static void
mark_shadows_as_reflecting_snapshot(struct domain *d, unsigned long gpfn)
{
    unsigned long smfn;
    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
    unsigned i;

    if ( (smfn = __shadow_status(d, gpfn, PGT_l1_shadow)) )
    {
        l1e = map_domain_page(smfn);
        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
            if ( is_guest_l1_slot(i) &&
                 (l1e_get_flags(l1e[i]) & _PAGE_PRESENT) )
                l1e_add_flags(l1e[i], SHADOW_REFLECTS_SNAPSHOT);
        unmap_domain_page(l1e);
    }

    if ( (smfn = __shadow_status(d, gpfn, PGT_l2_shadow)) )
    {
        l2e = map_domain_page(smfn);
        for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            if ( is_guest_l2_slot(0, i) &&
                 (l2e_get_flags(l2e[i]) & _PAGE_PRESENT) )
                l2e_add_flags(l2e[i], SHADOW_REFLECTS_SNAPSHOT);
        unmap_domain_page(l2e);
    }
}

// BUG: these are not SMP safe...
static int sh_l2_present;
static int sh_l1_present;
static char *sh_check_name;
int shadow_status_noswap;

#define v2m(_v, _adr) ({                                                     \
    unsigned long _a  = (unsigned long)(_adr);                               \
    l2_pgentry_t _pde = shadow_linear_l2_table(_v)[l2_table_offset(_a)];     \
    unsigned long _pa = -1;                                                  \
    if ( l2e_get_flags(_pde) & _PAGE_PRESENT )                               \
    {                                                                        \
        l1_pgentry_t _pte;                                                   \
        _pte = shadow_linear_pg_table[l1_linear_offset(_a)];                 \
        if ( l1e_get_flags(_pte) & _PAGE_PRESENT )                           \
            _pa = l1e_get_paddr(_pte);                                       \
    }                                                                        \
    _pa | (_a & ~PAGE_MASK);                                                 \
})

#define FAIL(_f, _a...)                                                      \
    do {                                                                     \
        printk("XXX %s-FAIL (%d,%d,%d) " _f " at %s(%d)\n",                  \
               sh_check_name, level, l2_idx, l1_idx, ## _a,                  \
               __FILE__, __LINE__);                                          \
        printk("guest_pte=%" PRIpte " eff_guest_pte=%" PRIpte                \
               " shadow_pte=%" PRIpte " snapshot_pte=%" PRIpte               \
               " &guest=%p &shadow=%p &snap=%p v2m(&guest)=%p"               \
               " v2m(&shadow)=%p v2m(&snap)=%p ea=%08x\n",                   \
               l1e_get_intpte(guest_pte), l1e_get_intpte(eff_guest_pte),     \
               l1e_get_intpte(shadow_pte), l1e_get_intpte(snapshot_pte),     \
               p_guest_pte, p_shadow_pte, p_snapshot_pte,                    \
               (void *)v2m(v, p_guest_pte), (void *)v2m(v, p_shadow_pte),    \
               (void *)v2m(v, p_snapshot_pte),                               \
               (l2_idx << L2_PAGETABLE_SHIFT) |                              \
               (l1_idx << L1_PAGETABLE_SHIFT));                              \
        errors++;                                                            \
    } while ( 0 )

static int check_pte(
    struct vcpu *v,
    l1_pgentry_t *p_guest_pte,
    l1_pgentry_t *p_shadow_pte,
    l1_pgentry_t *p_snapshot_pte,
    int level, int l2_idx, int l1_idx)
{
    struct domain *d = v->domain;
    l1_pgentry_t guest_pte = *p_guest_pte;
    l1_pgentry_t shadow_pte = *p_shadow_pte;
    l1_pgentry_t snapshot_pte = p_snapshot_pte ? *p_snapshot_pte : l1e_empty();
    l1_pgentry_t eff_guest_pte = l1e_empty();
    unsigned long mask, eff_guest_pfn, eff_guest_mfn, shadow_mfn;
    int errors = 0, guest_writable;
    int page_table_page;

    if ( (l1e_get_intpte(shadow_pte) == 0) ||
         (l1e_get_intpte(shadow_pte) == 0xdeadface) ||
         (l1e_get_intpte(shadow_pte) == 0x00000E00) )
        return errors;  /* always safe */

    if ( !(l1e_get_flags(shadow_pte) & _PAGE_PRESENT) )
        FAIL("Non zero not present shadow_pte");

    if ( level == 2 ) sh_l2_present++;
    if ( level == 1 ) sh_l1_present++;

    if ( (l1e_get_flags(shadow_pte) & SHADOW_REFLECTS_SNAPSHOT) && p_snapshot_pte )
        eff_guest_pte = snapshot_pte;
    else
        eff_guest_pte = guest_pte;

    if ( !(l1e_get_flags(eff_guest_pte) & _PAGE_PRESENT) )
        FAIL("Guest not present yet shadow is");

    mask = ~(_PAGE_GLOBAL|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW|_PAGE_AVAIL|PAGE_MASK);

    if ( ((l1e_get_intpte(shadow_pte) & mask) != (l1e_get_intpte(eff_guest_pte) & mask)) )
        FAIL("Corrupt?");

    if ( (level == 1) &&
         (l1e_get_flags(shadow_pte) & _PAGE_DIRTY) &&
         !(l1e_get_flags(eff_guest_pte) & _PAGE_DIRTY) )
        FAIL("Dirty coherence");

    if ( (l1e_get_flags(shadow_pte) & _PAGE_ACCESSED) &&
         !(l1e_get_flags(eff_guest_pte) & _PAGE_ACCESSED) )
        FAIL("Accessed coherence");

    if ( l1e_get_flags(shadow_pte) & _PAGE_GLOBAL )
        FAIL("global bit set in shadow");

    eff_guest_pfn = l1e_get_pfn(eff_guest_pte);
    eff_guest_mfn = __gpfn_to_mfn(d, eff_guest_pfn);
    shadow_mfn = l1e_get_pfn(shadow_pte);

    if ( !VALID_MFN(eff_guest_mfn) && !shadow_mode_refcounts(d) )
        FAIL("%s: invalid eff_guest_pfn=%lx eff_guest_pte=%" PRIpte "\n",
             __func__, eff_guest_pfn, l1e_get_intpte(eff_guest_pte));

    page_table_page = mfn_is_page_table(eff_guest_mfn);

    guest_writable =
        (l1e_get_flags(eff_guest_pte) & _PAGE_RW) ||
        (shadow_mode_write_l1(d) && (level == 1) && mfn_out_of_sync(eff_guest_mfn));

    if ( (l1e_get_flags(shadow_pte) & _PAGE_RW ) && !guest_writable )
    {
        printk("eff_guest_pfn=%lx eff_guest_mfn=%lx shadow_mfn=%lx t=%lx page_table_page=%d\n",
               eff_guest_pfn, eff_guest_mfn, shadow_mfn,
               frame_table[eff_guest_mfn].u.inuse.type_info,
               page_table_page);
        FAIL("RW coherence");
    }

    if ( (level == 1) &&
         (l1e_get_flags(shadow_pte) & _PAGE_RW ) &&
         !(guest_writable && (l1e_get_flags(eff_guest_pte) & _PAGE_DIRTY)) )
    {
        printk("eff_guest_pfn=%lx eff_guest_mfn=%lx shadow_mfn=%lx t=%lx page_table_page=%d\n",
               eff_guest_pfn, eff_guest_mfn, shadow_mfn,
               frame_table[eff_guest_mfn].u.inuse.type_info,
               page_table_page);
        FAIL("RW2 coherence");
    }
 
    if ( eff_guest_mfn == shadow_mfn )
    {
        if ( level > 1 )
            FAIL("Linear map ???");    /* XXX this will fail on BSD */
    }
    else
    {
        if ( level < 2 )
            FAIL("Shadow in L1 entry?");

        if ( level == 2 )
        {
            if ( __shadow_status(d, eff_guest_pfn, PGT_l1_shadow) != shadow_mfn )
                FAIL("shadow_mfn problem eff_guest_pfn=%lx shadow_mfn=%lx", eff_guest_pfn,
                     __shadow_status(d, eff_guest_pfn, PGT_l1_shadow));
        }
        else
            BUG(); // XXX -- not handled yet.
    }

    return errors;
}
#undef FAIL
#undef v2m

static int check_l1_table(
    struct vcpu *v, unsigned long gpfn,
    unsigned long gmfn, unsigned long smfn, unsigned l2_idx)
{
    struct domain *d = v->domain;
    int i;
    unsigned long snapshot_mfn;
    l1_pgentry_t *p_guest, *p_shadow, *p_snapshot = NULL;
    int errors = 0;

    if ( page_out_of_sync(pfn_to_page(gmfn)) )
    {
        snapshot_mfn = __shadow_status(d, gpfn, PGT_snapshot);
        ASSERT(snapshot_mfn);
        p_snapshot = map_domain_page(snapshot_mfn);
    }

    p_guest  = map_domain_page(gmfn);
    p_shadow = map_domain_page(smfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        errors += check_pte(v, p_guest+i, p_shadow+i,
                            p_snapshot ? p_snapshot+i : NULL,
                            1, l2_idx, i);
 
    unmap_domain_page(p_shadow);
    unmap_domain_page(p_guest);
    if ( p_snapshot )
        unmap_domain_page(p_snapshot);

    return errors;
}

#define FAILPT(_f, _a...)                                         \
    do {                                                          \
        printk("XXX FAIL %s-PT " _f "\n", sh_check_name, ## _a ); \
        errors++;                                                 \
    } while ( 0 )

int check_l2_table(
    struct vcpu *v, unsigned long gmfn, unsigned long smfn, int oos_pdes)
{
    struct domain *d = v->domain;
    l2_pgentry_t *gpl2e = (l2_pgentry_t *)map_domain_page(gmfn);
    l2_pgentry_t *spl2e = (l2_pgentry_t *)map_domain_page(smfn);
    l2_pgentry_t match;
    int i;
    int errors = 0;
    int limit;

    if ( !oos_pdes && (page_get_owner(pfn_to_page(gmfn)) != d) )
        FAILPT("domain doesn't own page");
    if ( oos_pdes && (page_get_owner(pfn_to_page(gmfn)) != NULL) )
        FAILPT("bogus owner for snapshot page");
    if ( page_get_owner(pfn_to_page(smfn)) != NULL )
        FAILPT("shadow page mfn=0x%lx is owned by someone, domid=%d",
               smfn, page_get_owner(pfn_to_page(smfn))->domain_id);

#if 0
    if ( memcmp(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
                &gpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
                ((SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT) -
                 DOMAIN_ENTRIES_PER_L2_PAGETABLE) * sizeof(l2_pgentry_t)) )
    {
        for ( i = DOMAIN_ENTRIES_PER_L2_PAGETABLE; 
              i < (SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT);
              i++ )
            printk("+++ (%d) %lx %lx\n",i,
                   l2_pgentry_val(gpl2e[i]), l2_pgentry_val(spl2e[i]));
        FAILPT("hypervisor entries inconsistent");
    }

    if ( (l2_pgentry_val(spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]) != 
          l2_pgentry_val(gpl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT])) )
        FAILPT("hypervisor linear map inconsistent");
#endif

    match = l2e_from_pfn(smfn, __PAGE_HYPERVISOR);
    if ( !shadow_mode_external(d) &&
         l2e_has_changed(spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT],
                         match, PAGE_FLAG_MASK))
    {
        FAILPT("hypervisor shadow linear map inconsistent %" PRIpte " %" PRIpte,
               l2e_get_intpte(spl2e[SH_LINEAR_PT_VIRT_START >>
                                   L2_PAGETABLE_SHIFT]),
               l2e_get_intpte(match));
    }

    match = l2e_from_paddr(__pa(d->arch.mm_perdomain_pt), __PAGE_HYPERVISOR);
    if ( !shadow_mode_external(d) &&
         l2e_has_changed(spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT],
                         match, PAGE_FLAG_MASK))
    {
        FAILPT("hypervisor per-domain map inconsistent saw %" PRIpte ", expected (va=%p) %" PRIpte,
               l2e_get_intpte(spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT]),
               d->arch.mm_perdomain_pt,
               l2e_get_intpte(match));
    }

#ifdef __i386__
    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
#else
    limit = 0; /* XXX x86/64 XXX */
#endif

    /* Check the whole L2. */
    for ( i = 0; i < limit; i++ )
        errors += check_pte(v,
                            (l1_pgentry_t*)(&gpl2e[i]), /* Hmm, dirty ... */
                            (l1_pgentry_t*)(&spl2e[i]),
                            NULL,
                            2, i, 0);

    unmap_domain_page(spl2e);
    unmap_domain_page(gpl2e);

#if 1
    if ( errors )
        printk("check_l2_table returning %d errors\n", errors);
#endif

    return errors;
}
#undef FAILPT

int _check_pagetable(struct vcpu *v, char *s)
{
    struct domain *d = v->domain;
    pagetable_t pt = v->arch.guest_table;
    unsigned long gptbase = pagetable_get_paddr(pt);
    unsigned long ptbase_pfn, smfn;
    unsigned long i;
    l2_pgentry_t *gpl2e, *spl2e;
    unsigned long ptbase_mfn = 0;
    int errors = 0, limit, oos_pdes = 0;

    //_audit_domain(d, AUDIT_QUIET);
    shadow_lock(d);

    sh_check_name = s;
    //SH_VVLOG("%s-PT Audit", s);
    sh_l2_present = sh_l1_present = 0;
    perfc_incrc(check_pagetable);

    ptbase_mfn = gptbase >> PAGE_SHIFT;
    ptbase_pfn = __mfn_to_gpfn(d, ptbase_mfn);

    if ( !(smfn = __shadow_status(d, ptbase_pfn, PGT_base_page_table)) )
    {
        printk("%s-PT %lx not shadowed\n", s, gptbase);
        goto out;
    }
    if ( page_out_of_sync(pfn_to_page(ptbase_mfn)) )
    {
        ptbase_mfn = __shadow_status(d, ptbase_pfn, PGT_snapshot);
        oos_pdes = 1;
        ASSERT(ptbase_mfn);
    }
 
    errors += check_l2_table(v, ptbase_mfn, smfn, oos_pdes);

    gpl2e = (l2_pgentry_t *) map_domain_page(ptbase_mfn);
    spl2e = (l2_pgentry_t *) map_domain_page(smfn);

    /* Go back and recurse. */
#ifdef __i386__
    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
#else
    limit = 0; /* XXX x86/64 XXX */
#endif

    for ( i = 0; i < limit; i++ )
    {
        unsigned long gl1pfn = l2e_get_pfn(gpl2e[i]);
        unsigned long gl1mfn = __gpfn_to_mfn(d, gl1pfn);
        unsigned long sl1mfn = l2e_get_pfn(spl2e[i]);

        if ( l2e_get_intpte(spl2e[i]) != 0 )  /* FIXME: check flags? */
        {
            errors += check_l1_table(v, gl1pfn, gl1mfn, sl1mfn, i);
        }
    }

    unmap_domain_page(spl2e);
    unmap_domain_page(gpl2e);

#if 0
    SH_VVLOG("PT verified : l2_present = %d, l1_present = %d",
             sh_l2_present, sh_l1_present);
#endif

 out:
    if ( errors )
        BUG();

    shadow_unlock(d);

    return errors;
}

int _check_all_pagetables(struct vcpu *v, char *s)
{
    struct domain *d = v->domain;
    int i;
    struct shadow_status *a;
    unsigned long gmfn;
    int errors = 0;

    shadow_status_noswap = 1;

    sh_check_name = s;
    SH_VVLOG("%s-PT Audit domid=%d", s, d->domain_id);
    sh_l2_present = sh_l1_present = 0;
    perfc_incrc(check_all_pagetables);

    for (i = 0; i < shadow_ht_buckets; i++)
    {
        a = &d->arch.shadow_ht[i];
        while ( a && a->gpfn_and_flags )
        {
            gmfn = __gpfn_to_mfn(d, a->gpfn_and_flags & PGT_mfn_mask);

            switch ( a->gpfn_and_flags & PGT_type_mask )
            {
            case PGT_l1_shadow:
                errors += check_l1_table(v, a->gpfn_and_flags & PGT_mfn_mask,
                                         gmfn, a->smfn, 0);
                break;
            case PGT_l2_shadow:
                errors += check_l2_table(v, gmfn, a->smfn,
                                         page_out_of_sync(pfn_to_page(gmfn)));
                break;
            case PGT_l3_shadow:
            case PGT_l4_shadow:
            case PGT_hl2_shadow:
                BUG(); // XXX - ought to fix this...
                break;
            case PGT_snapshot:
            case PGT_writable_pred:
                break;
            default:
                errors++;
                printk("unexpected shadow type %lx, gpfn=%lx, "
                       "gmfn=%lx smfn=%lx\n",
                       a->gpfn_and_flags & PGT_type_mask,
                       a->gpfn_and_flags & PGT_mfn_mask,
                       gmfn, a->smfn);
                BUG();
            }
            a = a->next;
        }
    }

    shadow_status_noswap = 0;

    if ( errors )
        BUG();

    return errors;
}

#endif // SHADOW_DEBUG

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
