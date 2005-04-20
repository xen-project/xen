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
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/trace.h>

static void shadow_free_snapshot(struct domain *d,
                                 struct out_of_sync_entry *entry);
static void remove_out_of_sync_entries(struct domain *d, unsigned long smfn);

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

    if ( unlikely(page_is_page_table(page)) )
        return 1;

    FSH_LOG("%s: gpfn=%p gmfn=%p nt=%p", __func__, gpfn, gmfn, new_type);

    if ( !shadow_remove_all_write_access(d, gpfn, gmfn) )
    {
        FSH_LOG("%s: couldn't find/remove all write accesses, gpfn=%p gmfn=%p",
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
    // code -- it would all much get simpler if we stop using
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
               "dom%d gpfn=%p gmfn=%p t=%x\n",
               d->id, gpfn, gmfn, new_type);
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
            void *l1 = map_domain_mem(page_to_pfn(page) << PAGE_SHIFT);
            memset(l1, 0, PAGE_SIZE);
            unmap_domain_mem(l1);
        }
    }
    else
        page = alloc_domheap_page(NULL);

    if ( unlikely(page == NULL) )
    {
        printk("Couldn't alloc shadow page! dom%d count=%d\n",
               d->id, d->arch.shadow_page_count);
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
    FSH_LOG("promotion of pfn=%p mfn=%p failed!  external gnttab refs?",
            gpfn, gmfn);
    free_domheap_page(page);
    return 0;
}

static void inline
free_shadow_l1_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *pl1e = map_domain_mem(smfn << PAGE_SHIFT);
    int i;
    struct pfn_info *spage = pfn_to_page(smfn);
    u32 min_max = spage->tlbflush_timestamp;
    int min = SHADOW_MIN(min_max);
    int max = SHADOW_MAX(min_max);

    for ( i = min; i <= max; i++ )
    {
        put_page_from_l1e(pl1e[i], d);
        pl1e[i] = l1e_empty();
    }

    unmap_domain_mem(pl1e);
}

static void inline
free_shadow_hl2_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *hl2 = map_domain_mem(smfn << PAGE_SHIFT);
    int i, limit;

    SH_VVLOG("%s: smfn=%p freed\n", __func__, smfn);

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

    unmap_domain_mem(hl2);
}

static void inline
free_shadow_l2_table(struct domain *d, unsigned long smfn)
{
    unsigned long *pl2e = map_domain_mem(smfn << PAGE_SHIFT);
    int i, external = shadow_mode_external(d);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( external || is_guest_l2_slot(i) )
            if ( pl2e[i] & _PAGE_PRESENT )
                put_shadow_ref(pl2e[i] >> PAGE_SHIFT);

    if ( (PGT_base_page_table == PGT_l2_page_table) &&
         shadow_mode_translate(d) && !external )
    {
        // free the ref to the hl2
        //
        put_shadow_ref(pl2e[l2_table_offset(LINEAR_PT_VIRT_START)]
                       >> PAGE_SHIFT);
    }

    unmap_domain_mem(pl2e);
}

void free_shadow_page(unsigned long smfn)
{
    struct pfn_info *page = &frame_table[smfn];
    unsigned long gmfn = page->u.inuse.type_info & PGT_mfn_mask;
    struct domain *d = page_get_owner(pfn_to_page(gmfn));
    unsigned long gpfn = __mfn_to_gpfn(d, gmfn);
    unsigned long type = page->u.inuse.type_info & PGT_type_mask;

    SH_VVLOG("%s: free'ing smfn=%p", __func__, smfn);

    ASSERT( ! IS_INVALID_M2P_ENTRY(gpfn) );

    delete_shadow_status(d, gpfn, gmfn, type);

    switch ( type )
    {
    case PGT_l1_shadow:
        perfc_decr(shadow_l1_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_l1_table(d, smfn);
        break;

    case PGT_l2_shadow:
        perfc_decr(shadow_l2_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_l2_table(d, smfn);
        break;

    case PGT_hl2_shadow:
        perfc_decr(hl2_table_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_hl2_table(d, smfn);
        break;

    case PGT_snapshot:
        perfc_decr(snapshot_pages);
        break;

    default:
        printk("Free shadow weird page type mfn=%08x type=%08x\n",
               page-frame_table, page->u.inuse.type_info);
        break;
    }

    d->arch.shadow_page_count--;

    // No TLB flushes are needed the next time this page gets allocated.
    //
    page->tlbflush_timestamp = 0;
    page->u.free.cpu_mask = 0;

    if ( type == PGT_l1_shadow )
    {
        list_add(&page->list, &d->arch.free_shadow_frames);
        perfc_incr(free_l1_pages);
    }
    else
        free_domheap_page(page);
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
    struct exec_domain   *ed;
 
    /*
     * WARNING! The shadow page table must not currently be in use!
     * e.g., You are expected to have paused the domain and synchronized CR3.
     */

    if( !d->arch.shadow_ht ) return;

    shadow_audit(d, 1);

    // first, remove any outstanding refs from out_of_sync entries...
    //
    free_out_of_sync_state(d);

    // second, remove any outstanding refs from ed->arch.shadow_table...
    //
    for_each_exec_domain(d, ed)
    {
        if ( pagetable_val(ed->arch.shadow_table) )
        {
            put_shadow_ref(pagetable_val(ed->arch.shadow_table) >> PAGE_SHIFT);
            ed->arch.shadow_table = mk_pagetable(0);
        }
    }

    // For external shadows, remove the monitor table's refs
    //
    if ( shadow_mode_external(d) )
    {
        for_each_exec_domain(d, ed)
        {
            l2_pgentry_t *mpl2e = ed->arch.monitor_vtable;
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

    // Now, the only refs to shadow pages that are left are from the shadow
    // pages themselves.  We just unpin the pinned pages, and the rest
    // should automatically disappear.
    //
    // NB: Beware: each explicitly or implicit call to free_shadow_page
    // can/will result in the hash bucket getting rewritten out from
    // under us...  First, collect the list of pinned pages, then
    // free them.
    //
#define PINNED(_x) (frame_table[_x].u.inuse.type_info & PGT_pinned)
    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        u32 count;
        unsigned long *mfn_list;

        /* Skip empty buckets. */
        x = &d->arch.shadow_ht[i];
        if ( x->gpfn_and_flags == 0 )
            continue;

        count = 0;
        for ( ; x != NULL; x = x->next )
            if ( PINNED(x->smfn) )
                count++;
        if ( !count )
            continue;

        mfn_list = xmalloc_array(unsigned long, count);
        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next )
            if ( PINNED(x->smfn) )
                mfn_list[count++] = x->smfn;

        while ( count )
        {
            shadow_unpin(mfn_list[--count]);
        }
        xfree(mfn_list);
    }
#undef PINNED

    shadow_audit(d, 0);

    SH_LOG("Free shadow table.");
}

void shadow_mode_init(void)
{
}

int _shadow_mode_enabled(struct domain *d)
{
    return shadow_mode_enabled(d);
}

static void alloc_monitor_pagetable(struct exec_domain *ed)
{
    unsigned long mmfn;
    l2_pgentry_t *mpl2e;
    struct pfn_info *mmfn_info;
    struct domain *d = ed->domain;

    ASSERT(pagetable_val(ed->arch.monitor_table) == 0);

    mmfn_info = alloc_domheap_page(NULL);
    ASSERT(mmfn_info != NULL);

    mmfn = (unsigned long) (mmfn_info - frame_table);
    mpl2e = (l2_pgentry_t *) map_domain_mem(mmfn << PAGE_SHIFT);
    memset(mpl2e, 0, PAGE_SIZE);

#ifdef __i386__ /* XXX screws x86/64 build */
    memcpy(&mpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
#endif

    mpl2e[l2_table_offset(PERDOMAIN_VIRT_START)] =
        l2e_create_phys(__pa(d->arch.mm_perdomain_pt),
                        __PAGE_HYPERVISOR);

    // map the phys_to_machine map into the Read-Only MPT space for this domain
    mpl2e[l2_table_offset(RO_MPT_VIRT_START)] =
        l2e_create_phys(pagetable_val(d->arch.phys_table),
                        __PAGE_HYPERVISOR);

    // Don't (yet) have mappings for these...
    // Don't want to accidentally see the idle_pg_table's linear mapping.
    //
    mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)] = l2e_empty();
    mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] = l2e_empty();

    ed->arch.monitor_table = mk_pagetable(mmfn << PAGE_SHIFT);
    ed->arch.monitor_vtable = mpl2e;
}

/*
 * Free the pages for monitor_table and hl2_table
 */
void free_monitor_pagetable(struct exec_domain *ed)
{
    l2_pgentry_t *mpl2e, hl2e, sl2e;
    unsigned long mfn;

    ASSERT( pagetable_val(ed->arch.monitor_table) );
    ASSERT( shadow_mode_external(ed->domain) );
    
    mpl2e = ed->arch.monitor_vtable;

    /*
     * First get the mfn for hl2_table by looking at monitor_table
     */
    hl2e = mpl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT];
    if ( l2e_get_flags(hl2e) & _PAGE_PRESENT )
    {
        mfn = l2e_get_pfn(hl2e);
        ASSERT(mfn);
        put_shadow_ref(mfn);
    }

    sl2e = mpl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT];
    if ( l2e_get_flags(sl2e) & _PAGE_PRESENT )
    {
        mfn = l2e_get_pfn(sl2e);
        ASSERT(mfn);
        put_shadow_ref(mfn);
    }

    unmap_domain_mem(mpl2e);

    /*
     * Then free monitor_table.
     */
    mfn = (pagetable_val(ed->arch.monitor_table)) >> PAGE_SHIFT;
    free_domheap_page(&frame_table[mfn]);

    ed->arch.monitor_table = mk_pagetable(0);
    ed->arch.monitor_vtable = 0;
}

int
set_p2m_entry(struct domain *d, unsigned long pfn, unsigned long mfn)
{
    unsigned long phystab = pagetable_val(d->arch.phys_table);
    l2_pgentry_t *l2, l2e;
    l1_pgentry_t *l1;
    struct pfn_info *l1page;
    unsigned long va = pfn << PAGE_SHIFT;

    ASSERT( phystab );

    l2 = map_domain_mem(phystab);
    l2e = l2[l2_table_offset(va)];
    if ( !l2e_get_value(l2e) ) /* FIXME: check present bit? */
    {
        l1page = alloc_domheap_page(NULL);
        if ( !l1page )
            return 0;

        l1 = map_domain_mem(page_to_pfn(l1page) << PAGE_SHIFT);
        memset(l1, 0, PAGE_SIZE);
        unmap_domain_mem(l1);

        l2e = l2e_create_pfn(page_to_pfn(l1page), __PAGE_HYPERVISOR);
        l2[l2_table_offset(va)] = l2e;
    }
    unmap_domain_mem(l2);

    l1 = map_domain_mem(l2e_get_phys(l2e));
    l1[l1_table_offset(va)] = l1e_create_pfn(mfn, __PAGE_HYPERVISOR);
    unmap_domain_mem(l1);

    return 1;
}

static int
alloc_p2m_table(struct domain *d)
{
    struct list_head *list_ent;
    struct pfn_info *page, *l2page;
    l2_pgentry_t *l2;
    unsigned long mfn, pfn;

    l2page = alloc_domheap_page(NULL);
    if ( !l2page )
        return 0;
    d->arch.phys_table = mk_pagetable(page_to_pfn(l2page) << PAGE_SHIFT);
    l2 = map_domain_mem(page_to_pfn(l2page) << PAGE_SHIFT);
    memset(l2, 0, PAGE_SIZE);
    unmap_domain_mem(l2);

    list_ent = d->page_list.next;
    while ( list_ent != &d->page_list )
    {
        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);
        pfn = machine_to_phys_mapping[mfn];
        ASSERT(pfn != INVALID_M2P_ENTRY);
        ASSERT(pfn < (1u<<20));

        set_p2m_entry(d, pfn, mfn);

        list_ent = page->list.next;
    }

    list_ent = d->xenpage_list.next;
    while ( list_ent != &d->xenpage_list )
    {
        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);
        pfn = machine_to_phys_mapping[mfn];
        if ( (pfn != INVALID_M2P_ENTRY) &&
             (pfn < (1u<<20)) )
        {
            set_p2m_entry(d, pfn, mfn);
        }

        list_ent = page->list.next;
    }

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
    struct exec_domain *ed;
    int new_modes = (mode & ~d->arch.shadow_mode);

    // Gotta be adding something to call this function.
    ASSERT(new_modes);

    // can't take anything away by calling this function.
    ASSERT(!(d->arch.shadow_mode & ~mode));

    for_each_exec_domain(d, ed)
    {
        invalidate_shadow_ldt(ed);

        // We need to set these up for __update_pagetables().
        // See the comment there.

        /*
         * arch.guest_vtable
         */
        if ( ed->arch.guest_vtable &&
             (ed->arch.guest_vtable != __linear_l2_table) )
        {
            unmap_domain_mem(ed->arch.guest_vtable);
        }
        if ( (mode & (SHM_translate | SHM_external)) == SHM_translate )
            ed->arch.guest_vtable = __linear_l2_table;
        else
            ed->arch.guest_vtable = NULL;

        /*
         * arch.shadow_vtable
         */
        if ( ed->arch.shadow_vtable &&
             (ed->arch.shadow_vtable != __shadow_linear_l2_table) )
        {
            unmap_domain_mem(ed->arch.shadow_vtable);
        }
        if ( !(mode & SHM_external) )
            ed->arch.shadow_vtable = __shadow_linear_l2_table;
        else
            ed->arch.shadow_vtable = NULL;

        /*
         * arch.hl2_vtable
         */
        if ( ed->arch.hl2_vtable &&
             (ed->arch.hl2_vtable != __linear_hl2_table) )
        {
            unmap_domain_mem(ed->arch.hl2_vtable);
        }
        if ( (mode & (SHM_translate | SHM_external)) == SHM_translate )
            ed->arch.hl2_vtable = __linear_hl2_table;
        else
            ed->arch.hl2_vtable = NULL;

        /*
         * arch.monitor_table & arch.monitor_vtable
         */
        if ( ed->arch.monitor_vtable )
        {
            free_monitor_pagetable(ed);
        }
        if ( mode & SHM_external )
        {
            alloc_monitor_pagetable(ed);
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
        d->arch.shadow_dirty_bitmap_size = (d->max_pages + 63) & ~63;
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
            ASSERT( !pagetable_val(d->arch.phys_table) );
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
            ASSERT( d == page_get_owner(&frame_table[pagetable_val(
                                        d->arch.phys_table)>>PAGE_SHIFT]) );
        }
    }

    printk("audit1\n");
    _audit_domain(d, AUDIT_ALREADY_LOCKED | AUDIT_ERRORS_OK);
    printk("audit1 done\n");

    // Get rid of any shadow pages from any previous shadow mode.
    //
    free_shadow_pages(d);

    printk("audit2\n");
    _audit_domain(d, AUDIT_ALREADY_LOCKED | AUDIT_ERRORS_OK);
    printk("audit2 done\n");

    // Turn off writable page tables.
    // It doesn't mix with shadow mode.
    // And shadow mode offers a superset of functionality.
    //
    vm_assist(d, VMASST_CMD_disable, VMASST_TYPE_writable_pagetables);

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

    struct list_head *list_ent = d->page_list.next;
    while ( list_ent != &d->page_list )
    {
        struct pfn_info *page = list_entry(list_ent, struct pfn_info, list);
        if ( !get_page_type(page, PGT_writable_page) )
            BUG();
        put_page_type(page);

        list_ent = page->list.next;
    }

    audit_adjust_pgtables(d, 1, 1);

    printk("audit3\n");
    _audit_domain(d, AUDIT_ALREADY_LOCKED);
    printk("audit3 done\n");

    return 0;

 nomem:
    if ( (new_modes & SHM_enable) && (d->arch.shadow_ht != NULL) )
    {
        xfree(d->arch.shadow_ht);
        d->arch.shadow_ht = NULL;
    }
    if ( (new_modes & SHM_log_dirty) && (d->arch.shadow_dirty_bitmap != NULL) )
    {
        xfree(d->arch.shadow_dirty_bitmap);
        d->arch.shadow_dirty_bitmap = NULL;
    }
    if ( (new_modes & SHM_translate) && !(new_modes & SHM_external) &&
         pagetable_val(d->arch.phys_table) )
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

    l1 = map_domain_mem(l1mfn << PAGE_SHIFT);
    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( is_guest_l1_slot(i) &&
             (l1e_get_flags(l1[i]) & _PAGE_PRESENT) )
        {
            unsigned long mfn = l1e_get_pfn(l1[i]);
            unsigned long gpfn = __mfn_to_gpfn(d, mfn);
            ASSERT(l1e_get_pfn(p2m[gpfn]) == mfn);
            l1[i] = l1e_create_pfn(gpfn, l1e_get_flags(l1[i]));
        }
    }
    unmap_domain_mem(l1);
}

// This is not general enough to handle arbitrary pagetables
// with shared L1 pages, etc., but it is sufficient for bringing
// up dom0.
//
void
translate_l2pgtable(struct domain *d, l1_pgentry_t *p2m, unsigned long l2mfn)
{
    int i;
    l2_pgentry_t *l2;

    ASSERT(shadow_mode_translate(d) && !shadow_mode_external(d));

    l2 = map_domain_mem(l2mfn << PAGE_SHIFT);
    for (i = 0; i < L2_PAGETABLE_ENTRIES; i++)
    {
        if ( is_guest_l2_slot(i) &&
             (l2e_get_flags(l2[i]) & _PAGE_PRESENT) )
        {
            unsigned long mfn = l2e_get_pfn(l2[i]);
            unsigned long gpfn = __mfn_to_gpfn(d, mfn);
            ASSERT(l1e_get_pfn(p2m[gpfn]) == mfn);
            l2[i] = l2e_create_pfn(gpfn, l2e_get_flags(l2[i]));
            translate_l1pgtable(d, p2m, mfn);
        }
    }
    unmap_domain_mem(l2);
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
    SH_LOG("freed extras, now %d", d->arch.shadow_extras_count);

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
    // This needs rethinking for the full shadow mode stuff.
    //
    // Among other things, ref counts need to be restored to a sensible
    // state for a non-shadow-mode guest...
    // This is probably easiest to do by stealing code from audit_domain().
    //
    BUG();

    free_shadow_pages(d);
    
    d->arch.shadow_mode = 0;

    free_shadow_ht_entries(d);
    free_out_of_sync_entries(d);
}

static int shadow_mode_table_op(
    struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int      op = sc->op;
    int               i, rc = 0;
    struct exec_domain *ed;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));

    SH_VLOG("shadow mode table op %p %p count %d",
            pagetable_val(d->exec_domain[0]->arch.guest_table),  /* XXX SMP */
            pagetable_val(d->exec_domain[0]->arch.shadow_table), /* XXX SMP */
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
 
        if ( (d->max_pages > sc->pages) || 
             (sc->dirty_bitmap == NULL) || 
             (d->arch.shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }
 
        sc->pages = d->max_pages;

#define chunk (8*1024) /* Transfer and clear in 1kB chunks for L1 cache. */
        for ( i = 0; i < d->max_pages; i += chunk )
        {
            int bytes = ((((d->max_pages - i) > chunk) ?
                          chunk : (d->max_pages - i)) + 7) / 8;
     
            if (copy_to_user(
                    sc->dirty_bitmap + (i/(8*sizeof(unsigned long))),
                    d->arch.shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
                    bytes))
            {
                // copy_to_user can fail when copying to guest app memory.
                // app should zero buffer after mallocing, and pin it
                rc = -EINVAL;
                memset(
                    d->arch.shadow_dirty_bitmap + 
                    (i/(8*sizeof(unsigned long))),
                    0, (d->max_pages/8) - (i/(8*sizeof(unsigned long))));
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
 
        if ( (d->max_pages > sc->pages) || 
             (sc->dirty_bitmap == NULL) || 
             (d->arch.shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }
 
        sc->pages = d->max_pages;
        if (copy_to_user(
            sc->dirty_bitmap, d->arch.shadow_dirty_bitmap, (d->max_pages+7)/8))
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

    for_each_exec_domain(d,ed)
        __update_pagetables(ed);

    return rc;
}

int shadow_mode_control(struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int op = sc->op;
    int          rc = 0;
    struct exec_domain *ed;

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
        shadow_mode_disable(d);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_TEST:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(d, SHM_enable);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(d, d->arch.shadow_mode|SHM_enable|SHM_log_dirty);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_TRANSLATE:
        free_shadow_pages(d);
        rc = __shadow_mode_enable(d, d->arch.shadow_mode|SHM_enable|SHM_translate);
        break;

    default:
        rc = shadow_mode_enabled(d) ? shadow_mode_table_op(d, sc) : -EINVAL;
        break;
    }

    shadow_unlock(d);

    for_each_exec_domain(d,ed)
        update_pagetables(ed);

    domain_unpause(d);

    return rc;
}

/*
 * XXX KAF: Why is this VMX specific?
 */
void vmx_shadow_clear_state(struct domain *d)
{
    SH_VVLOG("%s:", __func__);
    shadow_lock(d);
    free_shadow_pages(d);
    shadow_unlock(d);
    update_pagetables(d->exec_domain[0]);
}

unsigned long
gpfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
    ASSERT( shadow_mode_translate(d) );

    perfc_incrc(gpfn_to_mfn_foreign);

    unsigned long va = gpfn << PAGE_SHIFT;
    unsigned long phystab = pagetable_val(d->arch.phys_table);
    l2_pgentry_t *l2 = map_domain_mem(phystab);
    l2_pgentry_t l2e = l2[l2_table_offset(va)];
    unmap_domain_mem(l2);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
    {
        printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%p) => 0 l2e=%p\n",
               d->id, gpfn, l2e_get_value(l2e));
        return INVALID_MFN;
    }
    unsigned long l1tab = l2e_get_phys(l2e);
    l1_pgentry_t *l1 = map_domain_mem(l1tab);
    l1_pgentry_t l1e = l1[l1_table_offset(va)];
    unmap_domain_mem(l1);

#if 0
    printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%p) => %p phystab=%p l2e=%p l1tab=%p, l1e=%p\n",
           d->id, gpfn, l1_pgentry_val(l1e) >> PAGE_SHIFT, phystab, l2e, l1tab, l1e);
#endif

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) )
    {
        printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%p) => 0 l1e=%p\n",
               d->id, gpfn, l1e_get_value(l1e));
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
        printk("Couldn't alloc an HL2 shadow for pfn=%p mfn=%p\n", gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    SH_VVLOG("shadow_hl2_table(gpfn=%p, gmfn=%p, smfn=%p) => %p",
             gpfn, gmfn, smfn, hl2mfn);
    perfc_incrc(shadow_hl2_table_count);

    hl2 = map_domain_mem(hl2mfn << PAGE_SHIFT);

#ifdef __i386__
    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
#else
    limit = 0; /* XXX x86/64 XXX */
#endif

    memset(hl2, 0, limit * sizeof(l1_pgentry_t));

    if ( !shadow_mode_external(d) )
    {
        memset(&hl2[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 0,
               HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

        // Setup easy access to the GL2, SL2, and HL2 frames.
        //
        hl2[l2_table_offset(LINEAR_PT_VIRT_START)] =
            l1e_create_pfn(gmfn, __PAGE_HYPERVISOR);
        hl2[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l1e_create_pfn(smfn, __PAGE_HYPERVISOR);
        hl2[l2_table_offset(PERDOMAIN_VIRT_START)] =
            l1e_create_pfn(hl2mfn, __PAGE_HYPERVISOR);
    }

    unmap_domain_mem(hl2);

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

    SH_VVLOG("shadow_l2_table(gpfn=%p, gmfn=%p)", gpfn, gmfn);

    perfc_incrc(shadow_l2_table_count);

    if ( unlikely(!(smfn = alloc_shadow_page(d, gpfn, gmfn, PGT_l2_shadow))) )
    {
        printk("Couldn't alloc an L2 shadow for pfn=%p mfn=%p\n", gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    spl2e = (l2_pgentry_t *)map_domain_mem(smfn << PAGE_SHIFT);

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
            l2e_create_pfn(smfn, __PAGE_HYPERVISOR);

        spl2e[l2_table_offset(PERDOMAIN_VIRT_START)] =
            l2e_create_phys(__pa(page_get_owner(&frame_table[gmfn])->arch.mm_perdomain_pt),
                            __PAGE_HYPERVISOR);

        if ( shadow_mode_translate(d) ) // NB: not external
        {
            unsigned long hl2mfn;

            spl2e[l2_table_offset(RO_MPT_VIRT_START)] =
                l2e_create_phys(pagetable_val(d->arch.phys_table),
                                __PAGE_HYPERVISOR);

            if ( unlikely(!(hl2mfn = __shadow_status(d, gpfn, PGT_hl2_shadow))) )
                hl2mfn = shadow_hl2_table(d, gpfn, gmfn, smfn);

            // shadow_mode_translate (but not external) sl2 tables hold a
            // ref to their hl2.
            //
            if ( !get_shadow_ref(hl2mfn) )
                BUG();
            
            spl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
                l2e_create_pfn(hl2mfn, __PAGE_HYPERVISOR);
        }
        else
            spl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
                l2e_create_pfn(gmfn, __PAGE_HYPERVISOR);
    }
    else
    {
        memset(spl2e, 0, L2_PAGETABLE_ENTRIES*sizeof(l2_pgentry_t));        
    }

    unmap_domain_mem(spl2e);

    SH_VLOG("shadow_l2_table(%p -> %p)", gmfn, smfn);
    return smfn;
}

void shadow_map_l1_into_current_l2(unsigned long va)
{ 
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    l1_pgentry_t *gpl1e, *spl1e;
    l2_pgentry_t gl2e, sl2e;
    unsigned long gl1pfn, gl1mfn, sl1mfn;
    int i, init_table = 0;

    __guest_get_l2e(ed, va, &gl2e);
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
            printk("Couldn't alloc an L1 shadow for pfn=%p mfn=%p\n",
                   gl1pfn, gl1mfn);
            BUG(); /* XXX Need to deal gracefully with failure. */
        }

        perfc_incrc(shadow_l1_table_count);
        init_table = 1;
    }
    else
    {
        /* This L1 is shadowed already, but the L2 entry is missing. */
        SH_VVLOG("4b: was shadowed, l2 missing (%p)", sl1mfn);
    }

#ifndef NDEBUG
    l2_pgentry_t old_sl2e;
    __shadow_get_l2e(ed, va, &old_sl2e);
    ASSERT( !(l2e_get_flags(old_sl2e) & _PAGE_PRESENT) );
#endif

    if ( !get_shadow_ref(sl1mfn) )
        BUG();
    l2pde_general(d, &gl2e, &sl2e, sl1mfn);
    __guest_set_l2e(ed, va, gl2e);
    __shadow_set_l2e(ed, va, sl2e);

    if ( init_table )
    {
        gpl1e = &(linear_pg_table[l1_linear_offset(va) &
                              ~(L1_PAGETABLE_ENTRIES-1)]);

        spl1e = &(shadow_linear_pg_table[l1_linear_offset(va) &
                                     ~(L1_PAGETABLE_ENTRIES-1)]);

        l1_pgentry_t sl1e;
        int index = l1_table_offset(va);
        int min = 1, max = 0;

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            l1pte_propagate_from_guest(d, gpl1e[i], &sl1e);
            if ( (l1e_get_flags(sl1e) & _PAGE_PRESENT) &&
                 !shadow_get_page_from_l1e(sl1e, d) )
                sl1e = l1e_empty();
            if ( l1e_get_value(sl1e) == 0 ) /* FIXME: check flags? */
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
        }

        frame_table[sl1mfn].tlbflush_timestamp =
            SHADOW_ENCODE_MIN_MAX(min, max);
    }
}

void shadow_invlpg(struct exec_domain *ed, unsigned long va)
{
    struct domain *d = ed->domain;
    l1_pgentry_t gpte, spte;

    ASSERT(shadow_mode_enabled(d));

    shadow_lock(d);

    __shadow_sync_va(ed, va);

    // XXX mafetter: will need to think about 4MB pages...

    // It's not strictly necessary to update the shadow here,
    // but it might save a fault later.
    //
    if (__copy_from_user(&gpte, &linear_pg_table[va >> PAGE_SHIFT],
                         sizeof(gpte))) {
        perfc_incrc(shadow_invlpg_faults);
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
    unsigned long smfn, sl1mfn;
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
        printk("Couldn't alloc fullshadow snapshot for pfn=%p mfn=%p!\n"
               "Dom%d snapshot_count_count=%d\n",
               gpfn, gmfn, d->id, d->arch.snapshot_page_count);
        BUG(); /* XXX FIXME: try a shadow flush to free up some memory. */
    }

    if ( !get_shadow_ref(smfn) )
        BUG();

    if ( shadow_max_pgtable_type(d, gpfn, &sl1mfn) == PGT_l1_shadow )
        min_max = pfn_to_page(sl1mfn)->tlbflush_timestamp;
    pfn_to_page(smfn)->tlbflush_timestamp = min_max;

    min = SHADOW_MIN(min_max);
    max = SHADOW_MAX(min_max);
    length = max - min + 1;
    perfc_incr_histo(snapshot_copies, length, PT_UPDATES);

    min *= sizeof(l1_pgentry_t);
    length *= sizeof(l1_pgentry_t);

    original = map_domain_mem(gmfn << PAGE_SHIFT);
    snapshot = map_domain_mem(smfn << PAGE_SHIFT);
    memcpy(snapshot + min, original + min, length);
    unmap_domain_mem(original);
    unmap_domain_mem(snapshot);

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
    snapshot = map_domain_mem(entry->snapshot_mfn << PAGE_SHIFT);
    memset(snapshot, 0, PAGE_SIZE);
    unmap_domain_mem(snapshot);

    put_shadow_ref(entry->snapshot_mfn);
}

struct out_of_sync_entry *
shadow_mark_mfn_out_of_sync(struct exec_domain *ed, unsigned long gpfn,
                             unsigned long mfn)
{
    struct domain *d = ed->domain;
    struct pfn_info *page = &frame_table[mfn];
    struct out_of_sync_entry *entry = shadow_alloc_oos_entry(d);

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(pfn_valid(mfn));
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page);

    FSH_LOG("%s(gpfn=%p, mfn=%p) c=%p t=%p", __func__,
            gpfn, mfn, page->count_info, page->u.inuse.type_info);

    // XXX this will require some more thought...  Cross-domain sharing and
    //     modification of page tables?  Hmm...
    //
    if ( d != page_get_owner(page) )
        BUG();

    perfc_incrc(shadow_mark_mfn_out_of_sync_calls);

    entry->gpfn = gpfn;
    entry->gmfn = mfn;
    entry->snapshot_mfn = shadow_make_snapshot(d, gpfn, mfn);
    entry->writable_pl1e = -1;

    // increment guest's ref count to represent the entry in the
    // full shadow out-of-sync list.
    //
    get_page(page, d);

    // Add to the out-of-sync list
    //
    entry->next = d->arch.out_of_sync;
    d->arch.out_of_sync = entry;

    return entry;
}

void shadow_mark_va_out_of_sync(
    struct exec_domain *ed, unsigned long gpfn, unsigned long mfn, unsigned long va)
{
    struct out_of_sync_entry *entry =
        shadow_mark_mfn_out_of_sync(ed, gpfn, mfn);
    l2_pgentry_t sl2e;

    // We need the address of shadow PTE that maps @va.
    // It might not exist yet.  Make sure it's there.
    //
    __shadow_get_l2e(ed, va, &sl2e);
    if ( !(l2e_get_flags(sl2e) & _PAGE_PRESENT) )
    {
        // either this L1 isn't shadowed yet, or the shadow isn't linked into
        // the current L2.
        shadow_map_l1_into_current_l2(va);
        __shadow_get_l2e(ed, va, &sl2e);
    }
    ASSERT(l2e_get_flags(sl2e) & _PAGE_PRESENT);

    // NB: this is stored as a machine address.
    entry->writable_pl1e =
        l2e_get_phys(sl2e) | (sizeof(l1_pgentry_t) * l1_table_offset(va));
    ASSERT( !(entry->writable_pl1e & (sizeof(l1_pgentry_t)-1)) );

    // Increment shadow's page count to represent the reference
    // inherent in entry->writable_pl1e
    //
    if ( !get_shadow_ref(l2e_get_pfn(sl2e)) )
        BUG();

    FSH_LOG("mark_out_of_sync(va=%p -> writable_pl1e=%p)",
            va, entry->writable_pl1e);
}

/*
 * Returns 1 if the snapshot for @gmfn exists and its @index'th entry matches.
 * Returns 0 otherwise.
 */
static int snapshot_entry_matches(
    struct exec_domain *ed, unsigned long gmfn, unsigned index)
{
    unsigned long gpfn = __mfn_to_gpfn(ed->domain, gmfn);
    unsigned long smfn = __shadow_status(ed->domain, gpfn, PGT_snapshot);
    unsigned long *guest, *snapshot;
    int compare;

    ASSERT( ! IS_INVALID_M2P_ENTRY(gpfn) );

    perfc_incrc(snapshot_entry_matches_calls);

    if ( !smfn )
        return 0;

    guest    = map_domain_mem(gmfn << PAGE_SHIFT);
    snapshot = map_domain_mem(smfn << PAGE_SHIFT);

    // This could probably be smarter, but this is sufficent for
    // our current needs.
    //
    compare = (guest[index] == snapshot[index]);

    unmap_domain_mem(guest);
    unmap_domain_mem(snapshot);

#ifdef PERF_COUNTERS
    if ( compare )
        perfc_incrc(snapshot_entry_matches_true);
#endif

    return compare;
}

/*
 * Returns 1 if va's shadow mapping is out-of-sync.
 * Returns 0 otherwise.
 */
int __shadow_out_of_sync(struct exec_domain *ed, unsigned long va)
{
    struct domain *d = ed->domain;
    unsigned long l2mfn = pagetable_val(ed->arch.guest_table) >> PAGE_SHIFT;
    l2_pgentry_t l2e;
    unsigned long l1mfn;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));

    perfc_incrc(shadow_out_of_sync_calls);

    if ( page_out_of_sync(&frame_table[l2mfn]) &&
         !snapshot_entry_matches(ed, l2mfn, l2_table_offset(va)) )
        return 1;

    __guest_get_l2e(ed, va, &l2e);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 0;

    l1mfn = __gpfn_to_mfn(d, l2e_get_pfn(l2e));

    // If the l1 pfn is invalid, it can't be out of sync...
    if ( !VALID_MFN(l1mfn) )
        return 0;

    if ( page_out_of_sync(&frame_table[l1mfn]) &&
         !snapshot_entry_matches(ed, l1mfn, l1_table_offset(va)) )
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

    //printk("increase gpfn=%p pred=%p create=%d\n", gpfn, prediction, create);
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

    //printk("decrease gpfn=%p pred=%p score=%p\n", gpfn, prediction, score);

    if ( score )
        set_shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), 0, prediction, PGT_writable_pred);
    else
    {
        delete_shadow_status(d, GPFN_TO_GPTEPAGE(gpfn), 0, PGT_writable_pred);
        perfc_decr(writable_pte_predictions);
    }
}

static u32 remove_all_write_access_in_ptpage(
    struct domain *d, unsigned long pt_pfn, unsigned long pt_mfn,
    unsigned long readonly_gpfn, unsigned long readonly_gmfn,
    u32 max_refs_to_find, unsigned long prediction)
{
    l1_pgentry_t *pt = map_domain_mem(pt_mfn << PAGE_SHIFT);
    l1_pgentry_t match;
    unsigned long flags = _PAGE_RW | _PAGE_PRESENT;
    int i;
    u32 found = 0;
    int is_l1_shadow =
        ((frame_table[pt_mfn].u.inuse.type_info & PGT_type_mask) ==
         PGT_l1_shadow);

    match = l1e_create_pfn(readonly_gmfn, flags);

    // returns true if all refs have been found and fixed.
    //
    int fix_entry(int i)
    {
        l1_pgentry_t old = pt[i];
        l1_pgentry_t new = old;

        l1e_remove_flags(&new,_PAGE_RW);
        if ( is_l1_shadow && !shadow_get_page_from_l1e(new, d) )
            BUG();
        found++;
        pt[i] = new;
        if ( is_l1_shadow )
            put_page_from_l1e(old, d);

#if 0
        printk("removed write access to pfn=%p mfn=%p in smfn=%p entry %x "
               "is_l1_shadow=%d\n",
               readonly_gpfn, readonly_gmfn, pt_mfn, i, is_l1_shadow);
#endif

        return (found == max_refs_to_find);
    }

    i = readonly_gpfn & (L1_PAGETABLE_ENTRIES - 1);
    if ( !l1e_has_changed(&pt[i], &match, flags) && fix_entry(i) )
    {
        perfc_incrc(remove_write_fast_exit);
        increase_writable_pte_prediction(d, readonly_gpfn, prediction);
        unmap_domain_mem(pt);
        return found;
    }
 
    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( unlikely(!l1e_has_changed(&pt[i], &match, flags)) && fix_entry(i) )
            break;
    }

    unmap_domain_mem(pt);

    return found;
#undef MATCH_ENTRY
}

int shadow_remove_all_write_access(
    struct domain *d, unsigned long readonly_gpfn, unsigned long readonly_gmfn)
{
    int i;
    struct shadow_status *a;
    u32 found = 0, fixups, write_refs;
    unsigned long prediction, predicted_gpfn, predicted_smfn;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
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
    if ( write_refs &&
         (frame_table[readonly_gmfn].u.inuse.type_info & PGT_pinned) )
    {
        write_refs--;
    }

    if ( write_refs == 0 )
    {
        perfc_incrc(remove_write_no_work);
        return 1;
    }

    // Before searching all the L1 page tables, check the typical culprit first
    //
    if ( (prediction = predict_writable_pte_page(d, readonly_gpfn)) )
    {
        predicted_gpfn = prediction & PGT_mfn_mask;
        if ( (predicted_smfn = __shadow_status(d, predicted_gpfn, PGT_l1_shadow)) &&
             (fixups = remove_all_write_access_in_ptpage(d, predicted_gpfn, predicted_smfn, readonly_gpfn, readonly_gmfn, write_refs, prediction)) )
        {
            found += fixups;
            if ( found == write_refs )
            {
                perfc_incrc(remove_write_predicted);
                return 1;
            }
        }
        else
        {
            perfc_incrc(remove_write_bad_prediction);
            decrease_writable_pte_prediction(d, readonly_gpfn, prediction);
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
                    return 1;
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
    l1_pgentry_t *pl1e = map_domain_mem(l1mfn << PAGE_SHIFT);
    l1_pgentry_t match;
    unsigned long flags  = _PAGE_PRESENT;
    int i;
    u32 count = 0;
    int is_l1_shadow =
        ((frame_table[l1mfn].u.inuse.type_info & PGT_type_mask) ==
         PGT_l1_shadow);

    match = l1e_create_pfn(forbidden_gmfn, flags);
    
    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
    {
        if ( unlikely(!l1e_has_changed(&pl1e[i], &match, flags) == 0) )
        {
            l1_pgentry_t ol2e = pl1e[i];
            pl1e[i] = l1e_empty();
            count++;

            if ( is_l1_shadow )
                put_page_from_l1e(ol2e, d);
            else /* must be an hl2 page */
                put_page(&frame_table[forbidden_gmfn]);
        }
    }

    unmap_domain_mem(pl1e);

    return count;
}

u32 shadow_remove_all_access(struct domain *d, unsigned long forbidden_gmfn)
{
    int i;
    struct shadow_status *a;
    u32 count = 0;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
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

    ASSERT(spin_is_locked(&d->arch.shadow_lock));

    for ( entry = d->arch.out_of_sync; entry; entry = entry->next)
    {
        if ( entry->snapshot_mfn == SHADOW_SNAPSHOT_ELSEWHERE )
            continue;

        if ( !(smfn = __shadow_status(d, entry->gpfn, stype)) )
            continue;

        FSH_LOG("resyncing t=%p gpfn=%p gmfn=%p smfn=%p snapshot_mfn=%p",
                stype, entry->gpfn, entry->gmfn, smfn, entry->snapshot_mfn);

        // Compare guest's new contents to its snapshot, validating
        // and updating its shadow as appropriate.
        //
        guest    = map_domain_mem(entry->gmfn         << PAGE_SHIFT);
        snapshot = map_domain_mem(entry->snapshot_mfn << PAGE_SHIFT);
        shadow   = map_domain_mem(smfn                << PAGE_SHIFT);
        unshadow = 0;

        switch ( stype ) {
        case PGT_l1_shadow:
        {
            u32 min_max_shadow = pfn_to_page(smfn)->tlbflush_timestamp;
            int min_shadow = SHADOW_MIN(min_max_shadow);
            int max_shadow = SHADOW_MAX(min_max_shadow);

            u32 min_max_snapshot =
                pfn_to_page(entry->snapshot_mfn)->tlbflush_timestamp;
            int min_snapshot = SHADOW_MIN(min_max_snapshot);
            int max_snapshot = SHADOW_MAX(min_max_snapshot);

            l1_pgentry_t *guest1 = guest;
            l1_pgentry_t *shadow1 = shadow;
            l1_pgentry_t *snapshot1 = snapshot;

            changed = 0;

            for ( i = min_shadow; i <= max_shadow; i++ )
            {
                if ( (i < min_snapshot) || (i > max_snapshot) ||
                     l1e_has_changed(&guest1[i], &snapshot1[i], PAGE_FLAG_MASK) )
                {
                    need_flush |= validate_pte_change(d, guest1[i], &shadow1[i]);

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
            break;
        }
        case PGT_l2_shadow:
        {
            int max = -1;

            l2_pgentry_t *guest2 = guest;
            l2_pgentry_t *shadow2 = shadow;
            l2_pgentry_t *snapshot2 = snapshot;

            changed = 0;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            {
                if ( !is_guest_l2_slot(i) && !external )
                    continue;

                l2_pgentry_t new_pde = guest2[i];
                if ( l2e_has_changed(&new_pde, &snapshot2[i], PAGE_FLAG_MASK))
                {
                    need_flush |= validate_pde_change(d, new_pde, &shadow2[i]);

                    // can't update snapshots of linear page tables -- they
                    // are used multiple times...
                    //
                    // snapshot[i] = new_pde;

                    changed++;
                }
                if ( l2e_get_value(new_pde) != 0 ) /* FIXME: check flags? */
                    max = i;

                // XXX - This hack works for linux guests.
                //       Need a better solution long term.
                if ( !(l2e_get_flags(new_pde) & _PAGE_PRESENT) &&
                     unlikely(l2e_get_value(new_pde) != 0) &&
                     !unshadow &&
                     (frame_table[smfn].u.inuse.type_info & PGT_pinned) )
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
            
            changed = 0;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            {
                if ( !is_guest_l2_slot(i) && !external )
                    continue;

                l2_pgentry_t new_pde = guest2[i];
                if ( l2e_has_changed(&new_pde, &snapshot2[i], PAGE_FLAG_MASK) )
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

        unmap_domain_mem(shadow);
        unmap_domain_mem(snapshot);
        unmap_domain_mem(guest);

        if ( unlikely(unshadow) )
        {
            perfc_incrc(unshadow_l2_count);
            shadow_unpin(smfn);
            if ( unlikely(shadow_mode_external(d)) )
            {
                unsigned long hl2mfn;

                if ( (hl2mfn = __shadow_status(d, entry->gpfn, PGT_hl2_shadow)) &&
                     (frame_table[hl2mfn].u.inuse.type_info & PGT_pinned) )
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

    ASSERT(spin_is_locked(&d->arch.shadow_lock));

    // First, remove all write permissions to the page tables
    //
    for ( entry = d->arch.out_of_sync; entry; entry = entry->next)
    {
        // Skip entries that have low bits set...  Those aren't
        // real PTEs.
        //
        if ( entry->writable_pl1e & (sizeof(l1_pgentry_t)-1) )
            continue;

        l1_pgentry_t *ppte = map_domain_mem(entry->writable_pl1e);
        l1_pgentry_t opte = *ppte;
        l1_pgentry_t npte = opte;
        l1e_remove_flags(&opte, _PAGE_RW);

        if ( (l1e_get_flags(npte) & _PAGE_PRESENT) &&
             !shadow_get_page_from_l1e(npte, d) )
            BUG();
        *ppte = npte;
        put_page_from_l1e(opte, d);

        unmap_domain_mem(ppte);
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
    flush_tlb_mask(((1 << smp_num_cpus) - 1) & ~(1 << smp_processor_id()));
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

int shadow_fault(unsigned long va, struct xen_regs *regs)
{
    l1_pgentry_t gpte, spte, orig_gpte;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    l2_pgentry_t gpde;

    spte = l1e_empty();

    SH_VVLOG("shadow_fault( va=%p, code=%lu )", va, regs->error_code );
    perfc_incrc(shadow_fault_calls);
    
    check_pagetable(ed, "pre-sf");

    /*
     * Don't let someone else take the guest's table pages out-of-sync.
     */
    shadow_lock(d);

    /* XXX - FIX THIS COMMENT!!!
     * STEP 1. Check to see if this fault might have been caused by an
     *         out-of-sync table page entry, or if we should pass this
     *         fault onto the guest.
     */
    __shadow_sync_va(ed, va);

    /*
     * STEP 2. Check the guest PTE.
     */
    __guest_get_l2e(ed, va, &gpde);
    if ( unlikely(!(l1e_get_flags(gpte) & _PAGE_PRESENT)) )
    {
        SH_VVLOG("shadow_fault - EXIT: L1 not present" );
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
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
        perfc_incrc(shadow_fault_bail_pte_not_present);
        goto fail;
    }

    /* Write fault? */
    if ( regs->error_code & 2 )  
    {
        if ( unlikely(!(l1e_get_flags(gpte) & _PAGE_RW)) )
        {
            /* Write fault on a read-only mapping. */
            SH_VVLOG("shadow_fault - EXIT: wr fault on RO page (%lx)", gpte);
            perfc_incrc(shadow_fault_bail_ro_mapping);
            goto fail;
        }

        if ( !l1pte_write_fault(ed, &gpte, &spte, va) )
        {
            SH_VVLOG("shadow_fault - EXIT: l1pte_write_fault failed");
            perfc_incrc(write_fault_bail);
            shadow_unlock(d);
            return 0;
        }
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

    /* XXX Watch out for read-only L2 entries! (not used in Linux). */
    if ( unlikely(__copy_to_user(&linear_pg_table[l1_linear_offset(va)],
                                 &gpte, sizeof(gpte))) )
    {
        printk("shadow_fault() failed, crashing domain %d "
               "due to a read-only L2 page table (gpde=%p), va=%p\n",
               d->id, gpde, va);
        domain_crash_synchronous();
    }

    // if necessary, record the page table page as dirty
    if ( unlikely(shadow_mode_log_dirty(d)) &&
         l1e_has_changed(&orig_gpte, &gpte, PAGE_FLAG_MASK))
        mark_dirty(d, __gpfn_to_mfn(d, l2e_get_pfn(gpde)));

    shadow_set_l1e(va, spte, 1);

    perfc_incrc(shadow_fault_fixed);
    d->arch.shadow_fault_count++;

    shadow_unlock(d);

    check_pagetable(ed, "post-sf");
    return EXCRET_fault_fixed;

 fail:
    shadow_unlock(d);
    return 0;
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
void __update_pagetables(struct exec_domain *ed)
{
    struct domain *d = ed->domain;
    unsigned long gmfn = pagetable_val(ed->arch.guest_table) >> PAGE_SHIFT;
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
        if ( likely(ed->arch.guest_vtable != NULL) )
            unmap_domain_mem(ed->arch.guest_vtable);
        ed->arch.guest_vtable = map_domain_mem(gmfn << PAGE_SHIFT);
    }

    /*
     *  arch.shadow_table
     */
    if ( unlikely(!(smfn = __shadow_status(d, gpfn, PGT_base_page_table))) )
        smfn = shadow_l2_table(d, gpfn, gmfn);
    if ( !get_shadow_ref(smfn) )
        BUG();
    old_smfn = pagetable_val(ed->arch.shadow_table) >> PAGE_SHIFT;
    ed->arch.shadow_table = mk_pagetable(smfn << PAGE_SHIFT);
    if ( old_smfn )
        put_shadow_ref(old_smfn);

    SH_VVLOG("__update_pagetables(gmfn=%p, smfn=%p)", gmfn, smfn);

    /*
     * arch.shadow_vtable
     */
    if ( max_mode == SHM_external )
    {
        if ( ed->arch.shadow_vtable )
            unmap_domain_mem(ed->arch.shadow_vtable);
        ed->arch.shadow_vtable = map_domain_mem(smfn << PAGE_SHIFT);
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
        if ( ed->arch.hl2_vtable )
            unmap_domain_mem(ed->arch.hl2_vtable);
        ed->arch.hl2_vtable = map_domain_mem(hl2mfn << PAGE_SHIFT);
    }

    /*
     * fixup pointers in monitor table, as necessary
     */
    if ( max_mode == SHM_external )
    {
        l2_pgentry_t *mpl2e = ed->arch.monitor_vtable;
        l2_pgentry_t old_hl2e = mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)];
        l2_pgentry_t old_sl2e = mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)];

        ASSERT( shadow_mode_translate(d) );

        if ( !get_shadow_ref(hl2mfn) )
            BUG();
        mpl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
            l2e_create_pfn(hl2mfn, __PAGE_HYPERVISOR);
        if ( l2e_get_flags(old_hl2e) & _PAGE_PRESENT )
            put_shadow_ref(l2e_get_pfn(old_hl2e));

        if ( !get_shadow_ref(smfn) )
            BUG();
        mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l2e_create_pfn(smfn, __PAGE_HYPERVISOR);
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

// BUG: these are not SMP safe...
static int sh_l2_present;
static int sh_l1_present;
char * sh_check_name;
int shadow_status_noswap;

#define v2m(adr) ({                                                      \
    unsigned long _a  = (unsigned long)(adr);                            \
    l1_pgentry_t _pte = shadow_linear_pg_table[_a >> PAGE_SHIFT];        \
    unsigned long _pa = l1e_get_phys(_pte);                              \
    _pa | (_a & ~PAGE_MASK);                                             \
})

#define FAIL(_f, _a...)                                                      \
    do {                                                                     \
        printk("XXX %s-FAIL (%d,%d,%d)" _f "\n"                              \
               "g=%08lx s=%08lx &g=%08lx &s=%08lx"                           \
               " v2m(&g)=%08lx v2m(&s)=%08lx ea=%08lx\n",                    \
               sh_check_name, level, l2_idx, l1_idx, ## _a ,                 \
               gpte, spte, pgpte, pspte,                                     \
               v2m(pgpte), v2m(pspte),                                       \
               (l2_idx << L2_PAGETABLE_SHIFT) |                              \
               (l1_idx << L1_PAGETABLE_SHIFT));                              \
        errors++;                                                            \
    } while ( 0 )

static int check_pte(
    struct domain *d, l1_pgentry_t *pgpte, l1_pgentry_t *pspte, 
    int level, int l2_idx, int l1_idx, int oos_ptes)
{
    l1_pgentry_t gpte = *pgpte;
    l1_pgentry_t spte = *pspte;
    unsigned long mask, gpfn, smfn, gmfn;
    int errors = 0;
    int page_table_page;

    if ( (l1e_get_value(spte) == 0) ||
         (l1e_get_value(spte) == 0xdeadface) ||
         (l1e_get_value(spte) == 0x00000E00) )
        return errors;  /* always safe */

    if ( !(l1e_get_flags(spte) & _PAGE_PRESENT) )
        FAIL("Non zero not present spte");

    if ( level == 2 ) sh_l2_present++;
    if ( level == 1 ) sh_l1_present++;

    if ( !(l1e_get_flags(gpte) & _PAGE_PRESENT) )
        FAIL("Guest not present yet shadow is");

    mask = ~(_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW);

    if ( l1e_has_changed(&spte, &gpte, mask) )
        FAIL("Corrupt?");

    if ( (level == 1) &&
         (l1e_get_flags(spte) & _PAGE_DIRTY ) &&
         !(l1e_get_flags(gpte) & _PAGE_DIRTY) && !oos_ptes )
        FAIL("Dirty coherence");

    if ( (l1e_get_flags(spte) & _PAGE_ACCESSED ) &&
         !(l1e_get_flags(gpte) & _PAGE_ACCESSED) && !oos_ptes )
        FAIL("Accessed coherence");

    smfn = l1e_get_pfn(spte);
    gpfn = l1e_get_pfn(gpte);
    gmfn = __gpfn_to_mfn(d, gpfn);

    if ( !VALID_MFN(gmfn) )
        FAIL("invalid gpfn=%p gpte=%p\n", __func__, gpfn,
             l1e_get_value(gpte));

    page_table_page = mfn_is_page_table(gmfn);

    if ( (l1e_get_flags(spte) & _PAGE_RW ) &&
         !(l1e_get_flags(gpte) & _PAGE_RW) && !oos_ptes )
    {
        printk("gpfn=%p gmfn=%p smfn=%p t=0x%08x page_table_page=%d "
               "oos_ptes=%d\n",
               gpfn, gmfn, smfn,
               frame_table[gmfn].u.inuse.type_info,
               page_table_page, oos_ptes);
        FAIL("RW coherence");
    }

    if ( (level == 1) &&
         (l1e_get_flags(spte) & _PAGE_RW ) &&
         !((l1e_get_flags(gpte) & _PAGE_RW) &&
           (l1e_get_flags(gpte) & _PAGE_DIRTY)) &&
         !oos_ptes )
    {
        printk("gpfn=%p gmfn=%p smfn=%p t=0x%08x page_table_page=%d "
               "oos_ptes=%d\n",
               gpfn, gmfn, smfn,
               frame_table[gmfn].u.inuse.type_info,
               page_table_page, oos_ptes);
        FAIL("RW2 coherence");
    }
 
    if ( gmfn == smfn )
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
            if ( __shadow_status(d, gpfn, PGT_l1_shadow) != smfn )
                FAIL("smfn problem gpfn=%p smfn=%p", gpfn,
                     __shadow_status(d, gpfn, PGT_l1_shadow));
        }
        else
            BUG(); // XXX -- not handled yet.
    }

    return errors;
}

static int check_l1_table(
    struct domain *d, unsigned long gpfn,
    unsigned long gmfn, unsigned long smfn, unsigned l2_idx)
{
    int i;
    l1_pgentry_t *gpl1e, *spl1e;
    int errors = 0, oos_ptes = 0;

    if ( page_out_of_sync(pfn_to_page(gmfn)) )
    {
        gmfn = __shadow_status(d, gpfn, PGT_snapshot);
        oos_ptes = 1;
        ASSERT(gmfn);
    }

    gpl1e = map_domain_mem(gmfn << PAGE_SHIFT);
    spl1e = map_domain_mem(smfn << PAGE_SHIFT);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        errors += check_pte(d, &gpl1e[i], &spl1e[i], 1, l2_idx, i, oos_ptes);
 
    unmap_domain_mem(spl1e);
    unmap_domain_mem(gpl1e);

    return errors;
}

#define FAILPT(_f, _a...)                                         \
    do {                                                          \
        printk("XXX FAIL %s-PT " _f "\n", sh_check_name, ## _a ); \
        errors++;                                                 \
    } while ( 0 )

int check_l2_table(
    struct domain *d, unsigned long gmfn, unsigned long smfn, int oos_pdes)
{
    l2_pgentry_t *gpl2e = (l2_pgentry_t *)map_domain_mem(gmfn << PAGE_SHIFT);
    l2_pgentry_t *spl2e = (l2_pgentry_t *)map_domain_mem(smfn << PAGE_SHIFT);
    l2_pgentry_t match;
    int i;
    int errors = 0;
    int limit;

    if ( !oos_pdes && (page_get_owner(pfn_to_page(gmfn)) != d) )
        FAILPT("domain doesn't own page");
    if ( oos_pdes && (page_get_owner(pfn_to_page(gmfn)) != NULL) )
        FAILPT("bogus owner for snapshot page");
    if ( page_get_owner(pfn_to_page(smfn)) != NULL )
        FAILPT("shadow page mfn=0x%08x is owned by someone, domid=%d",
               smfn, page_get_owner(pfn_to_page(smfn))->id);

#if 0
    if ( memcmp(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
                &gpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
                ((SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT) -
                 DOMAIN_ENTRIES_PER_L2_PAGETABLE) * sizeof(l2_pgentry_t)) )
    {
        for ( i = DOMAIN_ENTRIES_PER_L2_PAGETABLE; 
              i < (SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT);
              i++ )
            printk("+++ (%d) %p %p\n",i,
                   l2_pgentry_val(gpl2e[i]), l2_pgentry_val(spl2e[i]));
        FAILPT("hypervisor entries inconsistent");
    }

    if ( (l2_pgentry_val(spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]) != 
          l2_pgentry_val(gpl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT])) )
        FAILPT("hypervisor linear map inconsistent");
#endif

    match = l2e_create_pfn(smfn, __PAGE_HYPERVISOR);
    if ( !shadow_mode_external(d) &&
         l2e_has_changed(&spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT],
                         &match, PAGE_FLAG_MASK))
    {
        FAILPT("hypervisor shadow linear map inconsistent %p %p",
               l2e_get_value(spl2e[SH_LINEAR_PT_VIRT_START >>
                                   L2_PAGETABLE_SHIFT]),
               l2e_get_value(match));
    }

    match = l2e_create_phys(__pa(d->arch.mm_perdomain_pt), __PAGE_HYPERVISOR);
    if ( !shadow_mode_external(d) &&
         l2e_has_changed(&spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT],
                         &match, PAGE_FLAG_MASK))
    {
        FAILPT("hypervisor per-domain map inconsistent saw %p, expected (va=%p) %p",
               l2e_get_value(spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT]),
               d->arch.mm_perdomain_pt,
               l2e_get_value(match));
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
        errors += check_pte(d,
                            (l1_pgentry_t*)(&gpl2e[i]), /* Hmm, dirty ... */
                            (l1_pgentry_t*)(&spl2e[i]),
                            2, i, 0, 0);

    unmap_domain_mem(spl2e);
    unmap_domain_mem(gpl2e);

#if 1
    if ( errors )
        printk("check_l2_table returning %d errors\n", errors);
#endif

    return errors;
}

int _check_pagetable(struct exec_domain *ed, char *s)
{
    struct domain *d = ed->domain;
    pagetable_t pt = ed->arch.guest_table;
    unsigned long gptbase = pagetable_val(pt);
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
        printk("%s-PT %p not shadowed\n", s, gptbase);
        goto out;
    }
    if ( page_out_of_sync(pfn_to_page(ptbase_mfn)) )
    {
        ptbase_mfn = __shadow_status(d, ptbase_pfn, PGT_snapshot);
        oos_pdes = 1;
        ASSERT(ptbase_mfn);
    }
 
    errors += check_l2_table(d, ptbase_mfn, smfn, oos_pdes);

    gpl2e = (l2_pgentry_t *) map_domain_mem( ptbase_mfn << PAGE_SHIFT );
    spl2e = (l2_pgentry_t *) map_domain_mem( smfn << PAGE_SHIFT );

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

        if ( l2e_get_value(spl2e[i]) != 0 )  /* FIXME: check flags? */
        {
            errors += check_l1_table(d, gl1pfn, gl1mfn, sl1mfn, i);
        }
    }

    unmap_domain_mem(spl2e);
    unmap_domain_mem(gpl2e);

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

int _check_all_pagetables(struct exec_domain *ed, char *s)
{
    struct domain *d = ed->domain;
    int i;
    struct shadow_status *a;
    unsigned long gmfn;
    int errors = 0;

    shadow_status_noswap = 1;

    sh_check_name = s;
    SH_VVLOG("%s-PT Audit domid=%d", s, d->id);
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
                errors += check_l1_table(d, a->gpfn_and_flags & PGT_mfn_mask,
                                         gmfn, a->smfn, 0);
                break;
            case PGT_l2_shadow:
                errors += check_l2_table(d, gmfn, a->smfn,
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
                printk("unexpected shadow type %p, gpfn=%p, "
                       "gmfn=%p smfn=%p\n",
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
