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
/*
 * Jun Nakajima <jun.nakajima@intel.com>
 * Chengyuan Li <chengyuan.li@intel.com>
 *
 * Extended to support 32-bit PAE and 64-bit guests.
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
#include <asm/shadow_64.h>

extern void free_shadow_pages(struct domain *d);

#if 0 // this code has not been updated for 32pae & 64 bit modes
#if SHADOW_DEBUG
static void mark_shadows_as_reflecting_snapshot(struct domain *d, unsigned long gpfn);
#endif
#endif

#if CONFIG_PAGING_LEVELS == 3
static unsigned long shadow_l3_table(
    struct domain *d, unsigned long gpfn, unsigned long gmfn);
#endif

#if CONFIG_PAGING_LEVELS == 4
static unsigned long shadow_l4_table(
    struct domain *d, unsigned long gpfn, unsigned long gmfn);
#endif

#if CONFIG_PAGING_LEVELS >= 3
static void shadow_map_into_current(struct vcpu *v,
    unsigned long va, unsigned int from, unsigned int to);
static inline void validate_bl2e_change( struct domain *d,
    guest_root_pgentry_t *new_gle_p, pgentry_64_t *shadow_l3, int index);
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
    void *l1, *lp;

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
            if (d->arch.ops->guest_paging_levels == PAGING_L2)
            {
#if CONFIG_PAGING_LEVELS >= 3
                /* For 32-bit VMX guest, 2 shadow L1s to simulate 1 guest L1
                 * So need allocate 2 continues shadow L1 each time.
                 */
                page = alloc_domheap_pages(NULL, SL1_ORDER, 0);
                if (!page)
                    goto no_shadow_page;

                l1 = map_domain_page(page_to_pfn(page));
                memset(l1, 0, PAGE_SIZE);
                unmap_domain_page(l1);

                l1 = map_domain_page(page_to_pfn(page+1));
                memset(l1, 0, PAGE_SIZE);
                unmap_domain_page(l1);
#else
                page = alloc_domheap_page(NULL);
                if (!page)
                    goto no_shadow_page;

                l1 = map_domain_page(page_to_pfn(page));
                memset(l1, 0, PAGE_SIZE);
                unmap_domain_page(l1);
#endif
            }
            else
            {
                page = alloc_domheap_page(NULL);
                if (!page)
                    goto no_shadow_page;

                l1 = map_domain_page(page_to_pfn(page));
                memset(l1, 0, PAGE_SIZE);
                unmap_domain_page(l1);
            }
        }
    }
    else {
#if CONFIG_PAGING_LEVELS == 2
        page = alloc_domheap_page(NULL);
#elif CONFIG_PAGING_LEVELS == 3
        if ( psh_type == PGT_l3_shadow )
            page = alloc_domheap_pages(NULL, 0, ALLOC_DOM_DMA);
        else
            page = alloc_domheap_page(NULL);
#elif CONFIG_PAGING_LEVELS == 4
        if ( (psh_type == PGT_l4_shadow) &&
             (d->arch.ops->guest_paging_levels != PAGING_L4) )
            page = alloc_domheap_pages(NULL, 0, ALLOC_DOM_DMA);
        else
            page = alloc_domheap_page(NULL);
#endif
        if (!page)
            goto no_shadow_page;

        lp = map_domain_page(page_to_pfn(page));
        memset(lp, 0, PAGE_SIZE);
        unmap_domain_page(lp);
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

    case PGT_l3_shadow:
        if ( !shadow_promote(d, gpfn, gmfn, psh_type) )
            goto fail;
        perfc_incr(shadow_l3_pages);
        d->arch.shadow_page_count++;
        if ( PGT_l3_page_table == PGT_root_page_table )
            pin = 1;
        break;

    case PGT_l4_shadow:
        if ( !shadow_promote(d, gpfn, gmfn, psh_type) )
            goto fail;
        perfc_incr(shadow_l4_pages);
        d->arch.shadow_page_count++;
        if ( PGT_l4_page_table == PGT_root_page_table )
            pin = 1;
        break;

#if CONFIG_PAGING_LEVELS >= 4
    case PGT_fl1_shadow:
        perfc_incr(shadow_l1_pages);
        d->arch.shadow_page_count++;
        break;
#else

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
#endif
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
    if (psh_type == PGT_l1_shadow)
    {
        if (d->arch.ops->guest_paging_levels == PAGING_L2)
        {
#if CONFIG_PAGING_LEVELS >=3
            free_domheap_pages(page, SL1_ORDER);
#else
            free_domheap_page(page);
#endif
        }
        else
            free_domheap_page(page);
    }
    else
        free_domheap_page(page);

    return 0;

no_shadow_page:
    ASSERT(page == NULL);
    printk("Couldn't alloc shadow page! dom%d count=%d\n",
           d->domain_id, d->arch.shadow_page_count);
    printk("Shadow table counts: l1=%d l2=%d hl2=%d snapshot=%d\n",
           perfc_value(shadow_l1_pages),
           perfc_value(shadow_l2_pages),
           perfc_value(hl2_table_pages),
           perfc_value(snapshot_pages));
    BUG(); /* XXX FIXME: try a shadow flush to free up some memory. */

    return 0;
}

#if CONFIG_PAGING_LEVELS == 2
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
#endif /* CONFIG_PAGING_LEVELS == 2 */

static void shadow_map_l1_into_current_l2(unsigned long va)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    l1_pgentry_t *spl1e;
    l2_pgentry_t sl2e;
    guest_l1_pgentry_t *gpl1e;
    guest_l2_pgentry_t gl2e = {0};
    unsigned long gl1pfn, gl1mfn, sl1mfn;
    int i, init_table = 0;

    __guest_get_l2e(v, va, &gl2e);
    ASSERT(guest_l2e_get_flags(gl2e) & _PAGE_PRESENT);
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
    {
        l2_pgentry_t old_sl2e;
        __shadow_get_l2e(v, va, &old_sl2e);
        ASSERT(!(l2e_get_flags(old_sl2e) & _PAGE_PRESENT));
    }
#endif

#if CONFIG_PAGING_LEVELS >=3
    if (d->arch.ops->guest_paging_levels == PAGING_L2)
    {
        /* for 32-bit VMX guest on 64-bit or PAE host,
         * need update two L2 entries each time
         */
        if ( !get_shadow_ref(sl1mfn))
            BUG();
        l2pde_general(d, &gl2e, &sl2e, sl1mfn);
        __guest_set_l2e(v, va, &gl2e);
        __shadow_set_l2e(v, va & ~((1<<L2_PAGETABLE_SHIFT_32) - 1), &sl2e);
        if ( !get_shadow_ref(sl1mfn+1))
            BUG();
        sl2e = l2e_empty();
        l2pde_general(d, &gl2e, &sl2e, sl1mfn+1);
        __shadow_set_l2e(v,((va & ~((1<<L2_PAGETABLE_SHIFT_32) - 1)) + (1 << L2_PAGETABLE_SHIFT)) , &sl2e);
    } else
#endif
    {
        if ( !get_shadow_ref(sl1mfn) )
            BUG();
        l2pde_general(d, &gl2e, &sl2e, sl1mfn);
        __guest_set_l2e(v, va, &gl2e);
        __shadow_set_l2e(v, va , &sl2e);
    }

    if ( init_table )
    {
        l1_pgentry_t sl1e;
        int index = guest_l1_table_offset(va);
        int min = 1, max = 0;

        unsigned long tmp_gmfn;
        l2_pgentry_t tmp_sl2e = {0};
        guest_l2_pgentry_t tmp_gl2e = {0};

        __guest_get_l2e(v, va, &tmp_gl2e);
        tmp_gmfn = __gpfn_to_mfn(d, l2e_get_pfn(tmp_gl2e));
        gpl1e = (guest_l1_pgentry_t *) map_domain_page(tmp_gmfn);

        /* If the PGT_l1_shadow has two continual pages */
#if CONFIG_PAGING_LEVELS >=3
        if (d->arch.ops->guest_paging_levels == PAGING_L2)
            __shadow_get_l2e(v,  va & ~((1<<L2_PAGETABLE_SHIFT_32) - 1), &tmp_sl2e);
        else
#endif
        __shadow_get_l2e(v, va, &tmp_sl2e);
        spl1e = (l1_pgentry_t *) map_domain_page(l2e_get_pfn(tmp_sl2e));

        for ( i = 0; i < GUEST_L1_PAGETABLE_ENTRIES; i++ )
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

        unmap_domain_page(gpl1e);
        unmap_domain_page(spl1e);
    }
}

#if CONFIG_PAGING_LEVELS == 2
static void
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
            l2_pgentry_t gpde = {0};
            unsigned long gl1pfn;
            unsigned long sl1mfn;

            __guest_get_l2e(v, va, &gpde);

            if ( l2e_get_flags(gpde) & _PAGE_PRESENT )
            {
                gl1pfn = l2e_get_pfn(gpde);
                sl1mfn = __shadow_status(d, gl1pfn, PGT_l1_shadow);
            }
            else
            {
                // no shadow exists, so there's nothing to do.
                perfc_incrc(shadow_set_l1e_fail);
                return;
            }

            if ( sl1mfn )
            {
                perfc_incrc(shadow_set_l1e_unlinked);
                if ( !get_shadow_ref(sl1mfn) )
                    BUG();
                l2pde_general(d, (guest_l2_pgentry_t *)&gpde, &sl2e, sl1mfn);
                __guest_set_l2e(v, va, &gpde);
                __shadow_set_l2e(v, va, &sl2e);
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
        l1_pgentry_t old_spte;
        __shadow_get_l1e(v, va, &old_spte);

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
    __shadow_set_l1e(v, va, &new_spte);
    shadow_update_min_max(l2e_get_pfn(sl2e), l1_table_offset(va));
}

static void shadow_invlpg_32(struct vcpu *v, unsigned long va)
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
    /*if (__copy_from_user(&gpte, &linear_pg_table[va >> PAGE_SHIFT],
                         sizeof(gpte))) {*/
    if (unlikely(!__guest_get_l1e(v, va, &gpte))) {
        perfc_incrc(shadow_invlpg_faults);
        shadow_unlock(d);
        return;
    }
    l1pte_propagate_from_guest(d, gpte, &spte);
    shadow_set_l1e(va, spte, 1);

    shadow_unlock(d);
}
#endif /* CONFIG_PAGING_LEVELS == 2 */

#if CONFIG_PAGING_LEVELS >= 3
static void shadow_set_l1e_64(
    unsigned long va, pgentry_64_t *sl1e_p,
    int create_l1_shadow)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    pgentry_64_t sle;
    pgentry_64_t sle_up = {0};
    l1_pgentry_t old_spte;
    l1_pgentry_t sl1e = *(l1_pgentry_t *)sl1e_p;
    int i;
    unsigned long orig_va = 0;

    if ( d->arch.ops->guest_paging_levels == PAGING_L2 ) 
    {
        /* This is for 32-bit VMX guest on 64-bit host */
        orig_va = va;
        va = va & (~((1<<L2_PAGETABLE_SHIFT_32)-1));
    }

    for ( i = PAGING_L4; i >= PAGING_L2; i-- )
    {
        if ( !__rw_entry(v, va, &sle, SHADOW_ENTRY | GET_ENTRY | i) )
        {
            sl1e = l1e_empty();
            goto out;
        }
        if ( !(entry_get_flags(sle) & _PAGE_PRESENT) )
        {
            if ( create_l1_shadow )
            {
                perfc_incrc(shadow_set_l3e_force_map);
                shadow_map_into_current(v, va, i-1, i);
                __rw_entry(v, va, &sle, SHADOW_ENTRY | GET_ENTRY | i);
            }
        }
        if ( i < PAGING_L4 )
            shadow_update_min_max(entry_get_pfn(sle_up), table_offset_64(va, i));
        sle_up = sle;
    }

    if ( d->arch.ops->guest_paging_levels == PAGING_L2 )
    {
        va = orig_va;
    }

    if ( shadow_mode_refcounts(d) )
    {
        __shadow_get_l1e(v, va, &old_spte);
        if ( l1e_has_changed(old_spte, sl1e, _PAGE_RW | _PAGE_PRESENT) )
        {
            if ( (l1e_get_flags(sl1e) & _PAGE_PRESENT) &&
                 !shadow_get_page_from_l1e(sl1e, d) )
                sl1e = l1e_empty();
            if ( l1e_get_flags(old_spte) & _PAGE_PRESENT )
                put_page_from_l1e(old_spte, d);
        }
    }

out:
    __shadow_set_l1e(v, va, &sl1e);

    shadow_update_min_max(entry_get_pfn(sle_up), guest_l1_table_offset(va));
}
#endif /* CONFIG_PAGING_LEVELS >= 3 */

static struct out_of_sync_entry *
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

    min *= sizeof(guest_l1_pgentry_t);
    length *= sizeof(guest_l1_pgentry_t);

    original = map_domain_page(gmfn);
    snapshot = map_domain_page(smfn);
    memcpy(snapshot + min, original + min, length);
    unmap_domain_page(original);
    unmap_domain_page(snapshot);

    return smfn;
}

static struct out_of_sync_entry *
__mark_mfn_out_of_sync(struct vcpu *v, unsigned long gpfn,
                             unsigned long mfn)
{
    struct domain *d = v->domain;
    struct pfn_info *page = &frame_table[mfn];
    struct out_of_sync_entry *entry = shadow_alloc_oos_entry(d);

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(pfn_valid(mfn));

#ifndef NDEBUG
    {
        u32 type = page->u.inuse.type_info & PGT_type_mask;
        if ( shadow_mode_refcounts(d) )
        {
            ASSERT(type == PGT_writable_page);
        }
        else
        {
            ASSERT(type && (type < PGT_l4_page_table));
        }
    }
#endif

    FSH_LOG("%s(gpfn=%lx, mfn=%lx) c=%08x t=%08x", __func__,
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

#if 0 // this code has not been updated for 32pae & 64 bit modes
#if SHADOW_DEBUG
    mark_shadows_as_reflecting_snapshot(d, gpfn);
#endif
#endif

    // increment guest's ref count to represent the entry in the
    // full shadow out-of-sync list.
    //
    get_page(page, d);

    return entry;
}

static struct out_of_sync_entry *
mark_mfn_out_of_sync(struct vcpu *v, unsigned long gpfn,
                             unsigned long mfn)
{
    struct out_of_sync_entry *entry =
        __mark_mfn_out_of_sync(v, gpfn, mfn);
    struct domain *d = v->domain;

    entry->snapshot_mfn = shadow_make_snapshot(d, gpfn, mfn);
    // Add to the out-of-sync list
    //
    entry->next = d->arch.out_of_sync;
    d->arch.out_of_sync = entry;

    return entry;

}

static void shadow_mark_va_out_of_sync(
    struct vcpu *v, unsigned long gpfn, unsigned long mfn, unsigned long va)
{
    struct out_of_sync_entry *entry =
        __mark_mfn_out_of_sync(v, gpfn, mfn);
    l2_pgentry_t sl2e;
    struct domain *d = v->domain;

#if CONFIG_PAGING_LEVELS >= 4
    {
        l4_pgentry_t sl4e;
        l3_pgentry_t sl3e;

        __shadow_get_l4e(v, va, &sl4e);
        if ( !(l4e_get_flags(sl4e) & _PAGE_PRESENT)) {
            shadow_map_into_current(v, va, PAGING_L3, PAGING_L4);
        }

        if (!__shadow_get_l3e(v, va, &sl3e)) {
            BUG();
        }

        if ( !(l3e_get_flags(sl3e) & _PAGE_PRESENT)) {
            shadow_map_into_current(v, va, PAGING_L2, PAGING_L3);
        }
    }
#endif

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

    FSH_LOG("%s(va=%lx -> writable_pl1e=%lx)",
            __func__, va, entry->writable_pl1e);
}

/*
 * Returns 1 if the snapshot for @gmfn exists and its @index'th entry matches.
 * Returns 0 otherwise.
 */
static int snapshot_entry_matches(
    struct domain *d, guest_l1_pgentry_t *guest_pt,
    unsigned long gpfn, unsigned index)
{
    unsigned long smfn = __shadow_status(d, gpfn, PGT_snapshot);
    guest_l1_pgentry_t *snapshot, gpte; // could be L1s or L2s or ...
    int entries_match;

    perfc_incrc(snapshot_entry_matches_calls);

    if ( !smfn )
        return 0;

    snapshot = map_domain_page(smfn);

    if (__copy_from_user(&gpte, &guest_pt[index],
                         sizeof(gpte)))
    {
        unmap_domain_page(snapshot);
        return 0;
    }

    // This could probably be smarter, but this is sufficent for
    // our current needs.
    //
    entries_match = !guest_l1e_has_changed(gpte, snapshot[index],
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
static int is_out_of_sync(struct vcpu *v, unsigned long va) /* __shadow_out_of_sync */
{
    struct domain *d = v->domain;
#if CONFIG_PAGING_LEVELS == 4
    unsigned long l2mfn = ((v->arch.flags & TF_kernel_mode)?
                          pagetable_get_pfn(v->arch.guest_table) :
                          pagetable_get_pfn(v->arch.guest_table_user));
#else
    unsigned long l2mfn = pagetable_get_pfn(v->arch.guest_table);
#endif
    unsigned long l2pfn = __mfn_to_gpfn(d, l2mfn);
    guest_l2_pgentry_t l2e;
    unsigned long l1pfn, l1mfn;
    guest_l1_pgentry_t *guest_pt;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(VALID_M2P(l2pfn));

    perfc_incrc(shadow_out_of_sync_calls);

#if CONFIG_PAGING_LEVELS >= 3

#define unmap_and_return(x)                                         \
    if ( guest_pt != (guest_l1_pgentry_t *) v->arch.guest_vtable )  \
        unmap_domain_page(guest_pt);                                \
    return (x);

    if (d->arch.ops->guest_paging_levels >= PAGING_L3) 
    { 
        pgentry_64_t le;
        unsigned long gmfn;
        unsigned long gpfn;
        int i;

        gmfn = l2mfn;
        gpfn = l2pfn;
        guest_pt = (guest_l1_pgentry_t *)v->arch.guest_vtable;

        for ( i = PAGING_L4; i >= PAGING_L3; i-- ) 
        {
            if (d->arch.ops->guest_paging_levels == PAGING_L3 
                && i == PAGING_L4)
                continue;       /* skip the top-level for 3-level */

            if ( page_out_of_sync(&frame_table[gmfn]) &&
                 !snapshot_entry_matches(
                     d, guest_pt, gpfn, table_offset_64(va, i)) )
            {
                unmap_and_return (1);
            }

            le = entry_empty();
            __rw_entry(v, va, &le, GUEST_ENTRY | GET_ENTRY | i);

            if ( !(entry_get_flags(le) & _PAGE_PRESENT) )
            {
                unmap_and_return (0);
            }
            gpfn = entry_get_pfn(le);
            gmfn = __gpfn_to_mfn(d, gpfn);
            if ( !VALID_MFN(gmfn) )
            {
                unmap_and_return (0);
            }
            if ( guest_pt != (guest_l1_pgentry_t *)v->arch.guest_vtable )
                unmap_domain_page(guest_pt);
            guest_pt = (guest_l1_pgentry_t *)map_domain_page(gmfn);
        }

        /* L2 */
        if ( page_out_of_sync(&frame_table[gmfn]) &&
             !snapshot_entry_matches(d, guest_pt, gpfn, l2_table_offset(va)) )
        {
            unmap_and_return (1);
        }

        if ( guest_pt != (guest_l1_pgentry_t *)v->arch.guest_vtable )
            unmap_domain_page(guest_pt);

    } 
    else
#undef unmap_and_return
#endif /* CONFIG_PAGING_LEVELS >= 3 */
    {
        if ( page_out_of_sync(&frame_table[l2mfn]) &&
             !snapshot_entry_matches(d, (guest_l1_pgentry_t *)v->arch.guest_vtable,
                                     l2pfn, guest_l2_table_offset(va)) )
            return 1;
    }

    __guest_get_l2e(v, va, &l2e);
    if ( !(guest_l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (guest_l2e_get_flags(l2e) & _PAGE_PSE))
        return 0;

    l1pfn = l2e_get_pfn(l2e);
    l1mfn = __gpfn_to_mfn(d, l1pfn);

    // If the l1 pfn is invalid, it can't be out of sync...
    if ( !VALID_MFN(l1mfn) )
        return 0;

    guest_pt = (guest_l1_pgentry_t *) map_domain_page(l1mfn);

    if ( page_out_of_sync(&frame_table[l1mfn]) &&
         !snapshot_entry_matches(
             d, guest_pt, l1pfn, guest_l1_table_offset(va)) ) 
    {
        unmap_domain_page(guest_pt);
        return 1;
    }

    unmap_domain_page(guest_pt);
    return 0;
}

#define GPFN_TO_GPTEPAGE(_gpfn) ((_gpfn) / (PAGE_SIZE / sizeof(guest_l1_pgentry_t)))
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
#if CONFIG_PAGING_LEVELS == 4
    is_l1_shadow |=
      ((frame_table[pt_mfn].u.inuse.type_info & PGT_type_mask) ==
                PGT_fl1_shadow);
#endif

    match = l1e_from_pfn(readonly_gmfn, flags);

    if ( shadow_mode_external(d) ) {
        i = (frame_table[readonly_gmfn].u.inuse.type_info & PGT_va_mask)
            >> PGT_va_shift;

        if ( (i >= 0 && i < L1_PAGETABLE_ENTRIES) &&
             !l1e_has_changed(pt[i], match, flags) &&
             fix_entry(d, &pt[i], &found, is_l1_shadow, max_refs_to_find) &&
             !prediction )
            goto out;
    }

    for (i = 0; i < GUEST_L1_PAGETABLE_ENTRIES; i++)
    {
        if ( unlikely(!l1e_has_changed(pt[i], match, flags)) &&
             fix_entry(d, &pt[i], &found, is_l1_shadow, max_refs_to_find) )
            break;
    }

out:
    unmap_domain_page(pt);

    return found;
}

static int remove_all_write_access(
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
        if (--write_refs == 0)
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
            if ( (a->gpfn_and_flags & PGT_type_mask) == PGT_l1_shadow
#if CONFIG_PAGING_LEVELS >= 4
              || (a->gpfn_and_flags & PGT_type_mask) == PGT_fl1_shadow
#endif
              )

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


static int resync_all(struct domain *d, u32 stype)
{
    struct out_of_sync_entry *entry;
    unsigned i;
    unsigned long smfn;
    void *guest, *shadow, *snapshot;
    int need_flush = 0, external = shadow_mode_external(d);
    int unshadow;
    int changed;
    u32 min_max_shadow, min_max_snapshot;
    int min_shadow, max_shadow, min_snapshot, max_snapshot;
    struct vcpu *v;

    ASSERT(shadow_lock_is_acquired(d));

    for ( entry = d->arch.out_of_sync; entry; entry = entry->next)
    {
        int max = -1;

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

        min_max_shadow = pfn_to_page(smfn)->tlbflush_timestamp;
        min_shadow     = SHADOW_MIN(min_max_shadow);
        max_shadow     = SHADOW_MAX(min_max_shadow);

        min_max_snapshot= pfn_to_page(entry->snapshot_mfn)->tlbflush_timestamp;
        min_snapshot    = SHADOW_MIN(min_max_snapshot);
        max_snapshot    = SHADOW_MAX(min_max_snapshot);

        switch ( stype )
        {
        case PGT_l1_shadow:
        {
            guest_l1_pgentry_t *guest1 = guest;
            l1_pgentry_t *shadow1 = shadow;
            guest_l1_pgentry_t *snapshot1 = snapshot;
            int unshadow_l1 = 0;

            ASSERT(shadow_mode_write_l1(d) ||
                   shadow_mode_write_all(d) || shadow_mode_wr_pt_pte(d));

            if ( !shadow_mode_refcounts(d) )
                revalidate_l1(d, (l1_pgentry_t *)guest1, (l1_pgentry_t *)snapshot1);
            if ( !smfn )
                break;

            changed = 0;

            for ( i = min_shadow; i <= max_shadow; i++ )
            {
                if ( (i < min_snapshot) || (i > max_snapshot) ||
                     guest_l1e_has_changed(guest1[i], snapshot1[i], PAGE_FLAG_MASK) )
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
            if ( d->arch.ops->guest_paging_levels >= PAGING_L3 &&
                 unshadow_l1 ) {
                pgentry_64_t l2e;

                __shadow_get_l2e(entry->v, entry->va, &l2e);

                if ( entry_get_flags(l2e) & _PAGE_PRESENT ) {
                    put_shadow_ref(entry_get_pfn(l2e));
                    l2e = entry_empty();
                    __shadow_set_l2e(entry->v, entry->va, &l2e);

                    if (entry->v == current)
                        need_flush = 1;
                }
            }

            break;
        }
#if CONFIG_PAGING_LEVELS == 2
        case PGT_l2_shadow:
        {
            l2_pgentry_t *guest2 = guest;
            l2_pgentry_t *shadow2 = shadow;
            l2_pgentry_t *snapshot2 = snapshot;

            ASSERT(shadow_mode_write_all(d) || shadow_mode_wr_pt_pte(d));
            BUG_ON(!shadow_mode_refcounts(d)); // not yet implemented

            changed = 0;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            {
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
#elif CONFIG_PAGING_LEVELS >= 3
        case PGT_l2_shadow:
        case PGT_l3_shadow:
        {
            pgentry_64_t *guest_pt = guest;
            pgentry_64_t *shadow_pt = shadow;
            pgentry_64_t *snapshot_pt = snapshot;

            changed = 0;
            for ( i = min_shadow; i <= max_shadow; i++ )
            {
                if ( (i < min_snapshot) || (i > max_snapshot) ||
                  entry_has_changed(
                      guest_pt[i], snapshot_pt[i], PAGE_FLAG_MASK) )
                {
                    need_flush |= validate_entry_change(
                        d, &guest_pt[i], &shadow_pt[i],
                        shadow_type_to_level(stype));
                    changed++;
                }
#if CONFIG_PAGING_LEVELS == 3
                if ( stype == PGT_l3_shadow ) 
                {
                    if ( entry_get_value(guest_pt[i]) != 0 ) 
                        max = i;

                    if ( !(entry_get_flags(guest_pt[i]) & _PAGE_PRESENT) &&
                         unlikely(entry_get_value(guest_pt[i]) != 0) &&
                         !unshadow &&
                         (frame_table[smfn].u.inuse.type_info & PGT_pinned) )
                        unshadow = 1;
                }
#endif
            }

            if ( d->arch.ops->guest_paging_levels == PAGING_L3
                 && max == -1 && stype == PGT_l3_shadow )
                unshadow = 1;

            perfc_incrc(resync_l3);
            perfc_incr_histo(shm_l3_updates, changed, PT_UPDATES);
            break;
        }
        case PGT_l4_shadow:
        {
            guest_root_pgentry_t *guest_root = guest;
            l4_pgentry_t *shadow4 = shadow;
            guest_root_pgentry_t *snapshot_root = snapshot;

            changed = 0;
            for ( i = 0; i < GUEST_ROOT_PAGETABLE_ENTRIES; i++ )
            {
                guest_root_pgentry_t new_root_e = guest_root[i];
                if ( !is_guest_l4_slot(i) && !external )
                    continue;
                if ( root_entry_has_changed(
                        new_root_e, snapshot_root[i], PAGE_FLAG_MASK))
                {
                    if ( d->arch.ops->guest_paging_levels == PAGING_L4 ) 
                    {
                        need_flush |= validate_entry_change(
                          d, (pgentry_64_t *)&new_root_e,
                          (pgentry_64_t *)&shadow4[i], shadow_type_to_level(stype));
                    } else {
                        validate_bl2e_change(d, &new_root_e, shadow, i);
                    }
                    changed++;
                    ESH_LOG("%d: shadow4 mfn: %lx, shadow root: %lx\n", i,
                      smfn, pagetable_get_paddr(current->arch.shadow_table));
                }
                if ( guest_root_get_intpte(new_root_e) != 0 ) /* FIXME: check flags? */
                    max = i;

                //  Need a better solution in the long term.
                if ( !(guest_root_get_flags(new_root_e) & _PAGE_PRESENT) &&
                     unlikely(guest_root_get_intpte(new_root_e) != 0) &&
                     !unshadow &&
                     (frame_table[smfn].u.inuse.type_info & PGT_pinned) )
                    unshadow = 1;
            }
            if ( max == -1 )
                unshadow = 1;
            perfc_incrc(resync_l4);
            perfc_incr_histo(shm_l4_updates, changed, PT_UPDATES);
            break;
        }

#endif /* CONFIG_PAGING_LEVELS >= 3 */
        default:
            BUG();
        }

        if ( smfn )
            unmap_domain_page(shadow);
        unmap_domain_page(snapshot);
        unmap_domain_page(guest);

        if ( unlikely(unshadow) )
        {
            for_each_vcpu(d, v)
                if(smfn == pagetable_get_pfn(v->arch.shadow_table))
                    return need_flush;
            perfc_incrc(unshadow_l2_count);
            shadow_unpin(smfn);
#if CONFIG_PAGING_LEVELS == 2
            if ( unlikely(shadow_mode_external(d)) )
            {
                unsigned long hl2mfn;

                if ( (hl2mfn = __shadow_status(d, entry->gpfn, PGT_hl2_shadow)) &&
                     MFN_PINNED(hl2mfn) )
                    shadow_unpin(hl2mfn);
            }
#endif
        }
    }

    return need_flush;
}

static void sync_all(struct domain *d)
{
    struct out_of_sync_entry *entry;
    int need_flush = 0;
    l1_pgentry_t *ppte, opte, npte;
    cpumask_t other_vcpus_mask;

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

        ppte = (l1_pgentry_t *)(
            (char *)map_domain_page(entry->writable_pl1e >> PAGE_SHIFT) +
            (entry->writable_pl1e & ~PAGE_MASK));
        opte = npte = *ppte;
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

    /* Other VCPUs mustn't use the revoked writable mappings. */
    other_vcpus_mask = d->cpumask;
    cpu_clear(smp_processor_id(), other_vcpus_mask);
    flush_tlb_mask(other_vcpus_mask);

    /* Flush ourself later. */
    need_flush = 1;

    /* Second, resync all L1 pages, then L2 pages, etc... */
    need_flush |= resync_all(d, PGT_l1_shadow);

#if CONFIG_PAGING_LEVELS == 2
    if ( d->arch.ops->guest_paging_levels == PAGING_L2 &&
         shadow_mode_translate(d) )  
    {
        need_flush |= resync_all(d, PGT_hl2_shadow);
    }
#endif

#if CONFIG_PAGING_LEVELS >= 3
    if (d->arch.ops->guest_paging_levels == PAGING_L2)
        need_flush |= resync_all(d, PGT_l4_shadow);
    else
        need_flush |= resync_all(d, PGT_l2_shadow);

    if (d->arch.ops->guest_paging_levels >= PAGING_L3) 
    {
        need_flush |= resync_all(d, PGT_l3_shadow);
        need_flush |= resync_all(d, PGT_l4_shadow);
    }
#endif

    if ( need_flush && !unlikely(shadow_mode_external(d)) )
        local_flush_tlb();

    free_out_of_sync_state(d);
}

static inline int l1pte_write_fault(
    struct vcpu *v, guest_l1_pgentry_t *gpte_p, l1_pgentry_t *spte_p,
    unsigned long va)
{
    struct domain *d = v->domain;
    guest_l1_pgentry_t gpte = *gpte_p;
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

    ASSERT(guest_l1e_get_flags(gpte) & _PAGE_RW);
    guest_l1e_add_flags(gpte, _PAGE_DIRTY | _PAGE_ACCESSED);
    spte = l1e_from_pfn(gmfn, guest_l1e_get_flags(gpte) & ~_PAGE_GLOBAL);

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
    struct domain *d, guest_l1_pgentry_t *gpte_p, l1_pgentry_t *spte_p)
{
    guest_l1_pgentry_t gpte = *gpte_p;
    l1_pgentry_t spte = *spte_p;
    unsigned long pfn = l1e_get_pfn(gpte);
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

    if ( unlikely(!VALID_MFN(mfn)) )
    {
        SH_VLOG("l1pte_read_fault: invalid gpfn=%lx", pfn);
        *spte_p = l1e_empty();
        return 0;
    }

    guest_l1e_add_flags(gpte, _PAGE_ACCESSED);
    spte = l1e_from_pfn(mfn, guest_l1e_get_flags(gpte) & ~_PAGE_GLOBAL);

    if ( shadow_mode_log_dirty(d) || !(guest_l1e_get_flags(gpte) & _PAGE_DIRTY) ||
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
#if CONFIG_PAGING_LEVELS == 2
static int shadow_fault_32(unsigned long va, struct cpu_user_regs *regs)
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
    //orig_gpte = gpte = linear_pg_table[l1_linear_offset(va)];
    __guest_get_l1e(v, va, &gpte);
    orig_gpte = gpte;

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
        /*if ( unlikely(__copy_to_user(&linear_pg_table[l1_linear_offset(va)],
                                     &gpte, sizeof(gpte))) )*/
        if ( unlikely(!__guest_set_l1e(v, va, &gpte)))
        {
            printk("%s() failed, crashing domain %d "
                   "due to a read-only L2 page table (gpde=%" PRIpte "), va=%lx\n",
                   __func__,d->domain_id, l2e_get_intpte(gpde), va);
            domain_crash_synchronous();
        }

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
#endif /* CONFIG_PAGING_LEVELS == 2 */

static inline unsigned long va_to_l1mfn(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;
    guest_l2_pgentry_t gl2e = {0};

    __guest_get_l2e(v, va, &gl2e);
    
    if ( unlikely(!(guest_l2e_get_flags(gl2e) & _PAGE_PRESENT)) )
        return INVALID_MFN;

    return __gpfn_to_mfn(d, l2e_get_pfn(gl2e));
}

static int do_update_va_mapping(unsigned long va,
                                l1_pgentry_t val,
                                struct vcpu *v)
{
    struct domain *d = v->domain;
    l1_pgentry_t spte;
    int rc = 0;

    shadow_lock(d);

    // This is actually overkill - we don't need to sync the L1 itself,
    // just everything involved in getting to this L1 (i.e. we need
    // linear_pg_table[l1_linear_offset(va)] to be in sync)...
    //
    __shadow_sync_va(v, va);

    l1pte_propagate_from_guest(d, *(guest_l1_pgentry_t *)&val, &spte);
#if CONFIG_PAGING_LEVELS == 2
    shadow_set_l1e(va, spte, 0);
#elif CONFIG_PAGING_LEVELS >= 3
    shadow_set_l1e_64(va, (pgentry_64_t *) &spte, 0);
#endif
    /*
     * If we're in log-dirty mode then we need to note that we've updated
     * the PTE in the PT-holding page. We need the machine frame number
     * for this.
     */
    __mark_dirty(d, va_to_l1mfn(v, va));

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
 * update_pagetables(), shadow_update_pagetables(), shadow_mode_enable(),
 * shadow_l2_table(), shadow_hl2_table(), and alloc_monitor_pagetable()
 * all play a part in maintaining these mappings.
 */
static void shadow_update_pagetables(struct vcpu *v)
{
    struct domain *d = v->domain;
#if CONFIG_PAGING_LEVELS == 4
    unsigned long gmfn = ((v->arch.flags & TF_kernel_mode)?
                          pagetable_get_pfn(v->arch.guest_table) :
                          pagetable_get_pfn(v->arch.guest_table_user));
#else
    unsigned long gmfn = pagetable_get_pfn(v->arch.guest_table);
#endif

    unsigned long gpfn = __mfn_to_gpfn(d, gmfn);
    unsigned long smfn, old_smfn;

#if CONFIG_PAGING_LEVELS == 2
    unsigned long hl2mfn;
#endif

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
    {
#if CONFIG_PAGING_LEVELS == 2
        smfn = shadow_l2_table(d, gpfn, gmfn);
#elif CONFIG_PAGING_LEVELS == 3
        smfn = shadow_l3_table(d, gpfn, gmfn);
#elif CONFIG_PAGING_LEVELS == 4
        smfn = shadow_l4_table(d, gpfn, gmfn);
#endif
    }else
        shadow_sync_all(d);
    if ( !get_shadow_ref(smfn) )
        BUG();
    old_smfn = pagetable_get_pfn(v->arch.shadow_table);
    v->arch.shadow_table = mk_pagetable(smfn << PAGE_SHIFT);
    if ( old_smfn )
        put_shadow_ref(old_smfn);

    SH_VVLOG("shadow_update_pagetables(gmfn=%lx, smfn=%lx)", gmfn, smfn);

    /*
     * arch.shadow_vtable
     */
    if ( max_mode == SHM_external
#if CONFIG_PAGING_LEVELS >=3
         || max_mode & SHM_enable
#endif
        )
    {
        if ( v->arch.shadow_vtable )
            unmap_domain_page(v->arch.shadow_vtable);
        v->arch.shadow_vtable = map_domain_page(smfn);
    }

#if CONFIG_PAGING_LEVELS == 2
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
#endif /* CONFIG_PAGING_LEVELS == 2 */

#if CONFIG_PAGING_LEVELS == 3
    /* FIXME: PAE code to be written */
#endif
}


/************************************************************************/
/************************************************************************/
/************************************************************************/

#if 0 // this code has not been updated for 32pae & 64 bit modes
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
// int shadow_status_noswap; // declared in shadow32.c

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
    l1_pgentry_t eff_guest_pte;
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
        printk("eff_guest_pfn=%lx eff_guest_mfn=%lx shadow_mfn=%lx t=0x%08lx page_table_page=%d\n",
               eff_guest_pfn, eff_guest_mfn, shadow_mfn,
               frame_table[eff_guest_mfn].u.inuse.type_info,
               page_table_page);
        FAIL("RW coherence");
    }

    if ( (level == 1) &&
         (l1e_get_flags(shadow_pte) & _PAGE_RW ) &&
         !(guest_writable && (l1e_get_flags(eff_guest_pte) & _PAGE_DIRTY)) )
    {
        printk("eff_guest_pfn=%lx eff_guest_mfn=%lx shadow_mfn=%lx t=0x%08lx page_table_page=%d\n",
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

static int check_l2_table(
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

#if CONFIG_PAGING_LEVELS == 2
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
#if CONFIG_PAGING_LEVELS == 4
    pagetable_t pt = ((v->arch.flags & TF_kernel_mode)?
                      v->arch.guest_table : v->arch.guest_table_user);
#else
    pagetable_t pt = v->arch.guest_table;
#endif
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
#if CONFIG_PAGING_LEVELS == 2
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
#endif // this code has not been updated for 32pae & 64 bit modes

#if CONFIG_PAGING_LEVELS == 3
static unsigned long shadow_l3_table(
    struct domain *d, unsigned long gpfn, unsigned long gmfn)
{
    unsigned long smfn;
    l3_pgentry_t *spl3e;

    perfc_incrc(shadow_l3_table_count);

    if ( unlikely(!(smfn = alloc_shadow_page(d, gpfn, gmfn, PGT_l3_shadow))) )
    {
        printk("Couldn't alloc an L4 shadow for pfn=%lx mfn=%lx\n", gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    spl3e = (l3_pgentry_t *)map_domain_page(smfn);

    /* Make the self entry */
    spl3e[PAE_SHADOW_SELF_ENTRY] = l3e_from_pfn(smfn, __PAGE_HYPERVISOR);

    if ( (PGT_base_page_table == PGT_l3_page_table) &&
         !shadow_mode_external(d) ) {
        int i;
        unsigned long g2mfn, s2mfn;
        l2_pgentry_t *spl2e;
        l3_pgentry_t *gpl3e;

        /* Get the top entry */
        gpl3e = (l3_pgentry_t *)map_domain_page(gmfn);

        if ( !(l3e_get_flags(gpl3e[L3_PAGETABLE_ENTRIES - 1]) & _PAGE_PRESENT) )
        {
            BUG();
        }

        g2mfn = l3e_get_pfn(gpl3e[L3_PAGETABLE_ENTRIES - 1]);

        /* NB. g2mfn should be same as g2pfn */
        if (!(s2mfn = __shadow_status(d, g2mfn, PGT_l2_shadow))) {
            if ( unlikely(!(s2mfn =
                    alloc_shadow_page(d, g2mfn, g2mfn, PGT_l2_shadow))) ) {
                printk("Couldn't alloc an L2 shadow for pfn=%lx mfn=%lx\n",
                    g2mfn, g2mfn);
                BUG(); /* XXX Deal gracefully with failure. */
            }
        } 

        if (!get_shadow_ref(s2mfn))
            BUG();
            
        /* Map shadow L2 into shadow L3 */
        spl3e[L3_PAGETABLE_ENTRIES - 1] = l3e_from_pfn(s2mfn, _PAGE_PRESENT);
        shadow_update_min_max(smfn, L3_PAGETABLE_ENTRIES -1);

        /*  
         * Xen private mappings. Do the similar things as
         * create_pae_xen_mappings().
         */
        spl2e = (l2_pgentry_t *)map_domain_page(s2mfn);

        /*
         * When we free L2 pages, we need to tell if the page contains
         * Xen private mappings. Use the va_mask part.
         */
        frame_table[s2mfn].u.inuse.type_info |= 
            (unsigned long) 3 << PGT_score_shift; 

        memset(spl2e, 0, 
               (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)) * sizeof(l2_pgentry_t));

        memcpy(&spl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));       

        for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
            spl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
                l2e_from_page(
                    virt_to_page(page_get_owner(&frame_table[gmfn])->arch.mm_perdomain_pt) + i, 
                    __PAGE_HYPERVISOR);
        for ( i = 0; i < (LINEARPT_MBYTES >> (L2_PAGETABLE_SHIFT - 20)); i++ )
            spl2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
                (l3e_get_flags(gpl3e[i]) & _PAGE_PRESENT) ?
                l2e_from_pfn(l3e_get_pfn(gpl3e[i]), __PAGE_HYPERVISOR) :
                l2e_empty();
       
        unmap_domain_page(spl2e);
        unmap_domain_page(gpl3e);
    }
    unmap_domain_page(spl3e);

    return smfn;
}

static unsigned long gva_to_gpa_pae(unsigned long gva)
{
    BUG();
    return 43;
}
#endif /* CONFIG_PAGING_LEVELS == 3 */

#if CONFIG_PAGING_LEVELS == 4
/****************************************************************************/
/* 64-bit shadow-mode code testing */
/****************************************************************************/
/*
 * init_bl2() is for 32-bit VMX guest on 64-bit host
 * Using 1 shadow L4(l3) and 4 shadow L2s to simulate guest L2
 */
static inline unsigned long init_bl2(l4_pgentry_t *spl4e, unsigned long smfn)
{
    unsigned int count;
    unsigned long sl2mfn;
    struct pfn_info *page;
    void *l2;

    memset(spl4e, 0, PAGE_SIZE);

    /* Map the self entry, L4&L3 share the same page */
    spl4e[PAE_SHADOW_SELF_ENTRY] = l4e_from_pfn(smfn, __PAGE_HYPERVISOR);

    /* Allocate 4 shadow L2s */
    page = alloc_domheap_pages(NULL, SL2_ORDER, 0);
    if (!page)
        domain_crash_synchronous();

    for (count = 0; count < PDP_ENTRIES; count++)
    {
        sl2mfn = page_to_pfn(page+count);
        l2 = map_domain_page(sl2mfn);
        memset(l2, 0, PAGE_SIZE);
        unmap_domain_page(l2);
        spl4e[count] = l4e_from_pfn(sl2mfn, _PAGE_PRESENT);
    }

    unmap_domain_page(spl4e);

    return smfn;
}

static unsigned long shadow_l4_table(
  struct domain *d, unsigned long gpfn, unsigned long gmfn)
{
    unsigned long smfn;
    l4_pgentry_t *spl4e;

    SH_VVLOG("shadow_l4_table(gpfn=%lx, gmfn=%lx)", gpfn, gmfn);

    perfc_incrc(shadow_l4_table_count);

    if ( unlikely(!(smfn = alloc_shadow_page(d, gpfn, gmfn, PGT_l4_shadow))) )
    {
        printk("Couldn't alloc an L4 shadow for pfn=%lx mfn=%lx\n", gpfn, gmfn);
        BUG(); /* XXX Deal gracefully with failure. */
    }

    spl4e = (l4_pgentry_t *)map_domain_page(smfn);

    if (d->arch.ops->guest_paging_levels == PAGING_L2) {
        return init_bl2(spl4e, smfn);
    }

    /* Install hypervisor and 4x linear p.t. mapings. */
    if ( (PGT_base_page_table == PGT_l4_page_table) &&
      !shadow_mode_external(d) )
    {
        /*
         * We could proactively fill in PDEs for pages that are already
         * shadowed *and* where the guest PDE has _PAGE_ACCESSED set
         * (restriction required for coherence of the accessed bit). However,
         * we tried it and it didn't help performance. This is simpler.
         */
        memset(spl4e, 0, L4_PAGETABLE_ENTRIES*sizeof(l4_pgentry_t));

        /* Install hypervisor and 2x linear p.t. mapings. */
        memcpy(&spl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));

        spl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
            l4e_from_paddr(__pa(page_get_owner(&frame_table[gmfn])->arch.mm_perdomain_l3),
                            __PAGE_HYPERVISOR);

        if ( shadow_mode_translate(d) ) // NB: not external
        {
            spl4e[l4_table_offset(RO_MPT_VIRT_START)] =
                l4e_from_paddr(pagetable_get_paddr(d->arch.phys_table),
                                __PAGE_HYPERVISOR);
        }
        else
            spl4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
                l4e_from_pfn(gmfn, __PAGE_HYPERVISOR);

    } else
        memset(spl4e, 0, L4_PAGETABLE_ENTRIES*sizeof(l4_pgentry_t));

    unmap_domain_page(spl4e);

    ESH_LOG("shadow_l4_table(%lx -> %lx)", gmfn, smfn);
    return smfn;
}
#endif /* CONFIG_PAGING_LEVELS == 4 */

#if CONFIG_PAGING_LEVELS >= 3
/*
 * validate_bl2e_change()
 * The code is for 32-bit VMX gues on 64-bit host.
 * To sync guest L2.
 */

static inline void
validate_bl2e_change(
    struct domain *d,
    guest_root_pgentry_t *new_gle_p,
    pgentry_64_t *shadow_l3,
    int index)
{
    int sl3_idx, sl2_idx;
    unsigned long sl2mfn, sl1mfn;
    pgentry_64_t *sl2_p;

    /* Using guest l2 pte index to get shadow l3&l2 index
     * index: 0 ~ 1023, PAGETABLE_ENTRIES: 512
     */
    sl3_idx = index / (PAGETABLE_ENTRIES / 2);
    sl2_idx = (index % (PAGETABLE_ENTRIES / 2)) * 2;

    sl2mfn = entry_get_pfn(shadow_l3[sl3_idx]);
    sl2_p = (pgentry_64_t *)map_domain_page(sl2mfn);

    validate_pde_change(
        d, *(guest_l2_pgentry_t *)new_gle_p, (l2_pgentry_t *)&sl2_p[sl2_idx]);

    /* Mapping the second l1 shadow page */
    if (entry_get_flags(sl2_p[sl2_idx]) & _PAGE_PRESENT) {
       sl1mfn = entry_get_pfn(sl2_p[sl2_idx]);
       sl2_p[sl2_idx + 1] =
            entry_from_pfn(sl1mfn + 1, entry_get_flags(sl2_p[sl2_idx]));
    }
    else
        sl2_p[sl2_idx + 1] = (pgentry_64_t){0};
    unmap_domain_page(sl2_p);

}

/*
 * This shadow_mark_va_out_of_sync() is for 2M page shadow
 */
static void shadow_mark_va_out_of_sync_2mp(
  struct vcpu *v, unsigned long gpfn, unsigned long mfn, unsigned long writable_pl1e)
{
    struct out_of_sync_entry *entry =
      shadow_mark_mfn_out_of_sync(v, gpfn, mfn);

    entry->writable_pl1e = writable_pl1e;
    ESH_LOG("<shadow_mark_va_out_of_sync_2mp> gpfn = %lx\n", gpfn);
    if ( !get_shadow_ref(writable_pl1e >> L1_PAGETABLE_SHIFT) )
        BUG();
}

static int get_shadow_mfn(struct domain *d, unsigned long gpfn, unsigned long *spmfn, u32 flag)
{
    unsigned long gmfn;
    if ( !(*spmfn = __shadow_status(d, gpfn, flag)) )
    {
        /* This is NOT already shadowed so we need to shadow it. */
        SH_VVLOG("<get_shadow_mfn>: not shadowed");

        gmfn = __gpfn_to_mfn(d, gpfn);
        if ( unlikely(!VALID_MFN(gmfn)) )
        {
            // Attempt to use an invalid pfn as an shadow page.
            // XXX this needs to be more graceful!
            BUG();
        }

        if ( unlikely(!(*spmfn =
                  alloc_shadow_page(d, gpfn, gmfn, flag))) )
        {
            printk("<get_shadow_mfn>Couldn't alloc an shadow for pfn=%lx mfn=%lx\n", gpfn, gmfn);
            BUG(); /* XXX Need to deal gracefully with failure. */
        }
        switch(flag) {
            case PGT_l1_shadow:
                perfc_incrc(shadow_l1_table_count);
                break;
            case PGT_l2_shadow:
                perfc_incrc(shadow_l2_table_count);
                break;
            case PGT_l3_shadow:
                perfc_incrc(shadow_l3_table_count);
                break;
            case PGT_hl2_shadow:
                perfc_incrc(shadow_hl2_table_count);
                break;
        }

        return 1;
    } else {
        /* This L1 is shadowed already, but the L2 entry is missing. */
        SH_VVLOG("4b: was shadowed, l2 missing (%lx)", *spmfn);
        return 0;
    }
}

static void shadow_map_into_current(struct vcpu *v,
  unsigned long va, unsigned int from, unsigned int to)
{
    pgentry_64_t gle = {0}, sle;
    unsigned long gpfn, smfn;

    if (from == PAGING_L1 && to == PAGING_L2) {
        shadow_map_l1_into_current_l2(va);
        return;
    }

    __rw_entry(v, va, &gle, GUEST_ENTRY | GET_ENTRY | to);
    ASSERT(entry_get_flags(gle) & _PAGE_PRESENT);
    gpfn = entry_get_pfn(gle);

    get_shadow_mfn(v->domain, gpfn, &smfn, shadow_level_to_type(from));

    if ( !get_shadow_ref(smfn) )
        BUG();
    entry_general(v->domain, &gle, &sle, smfn, to);
    __rw_entry(v, va, &gle, GUEST_ENTRY | SET_ENTRY | to);
    __rw_entry(v, va, &sle, SHADOW_ENTRY | SET_ENTRY | to);
}

/*
 * shadow_set_lxe should be put in shadow.h
 */
static void shadow_set_l2e_64(unsigned long va, l2_pgentry_t sl2e,
  int create_l2_shadow, int put_ref_check)
{
    struct vcpu *v = current;
    l4_pgentry_t sl4e;
    l3_pgentry_t sl3e;

    __shadow_get_l4e(v, va, &sl4e);
    if (!(l4e_get_flags(sl4e) & _PAGE_PRESENT)) {
        if (create_l2_shadow) {
            perfc_incrc(shadow_set_l3e_force_map);
            shadow_map_into_current(v, va, PAGING_L3, PAGING_L4);
            __shadow_get_l4e(v, va, &sl4e);
        } else {
            printk("For non VMX shadow, create_l1_shadow:%d\n", create_l2_shadow);
        }
    }

    __shadow_get_l3e(v, va, &sl3e);
    if (!(l3e_get_flags(sl3e) & _PAGE_PRESENT)) {
         if (create_l2_shadow) {
            perfc_incrc(shadow_set_l2e_force_map);
            shadow_map_into_current(v, va, PAGING_L2, PAGING_L3);
            __shadow_get_l3e(v, va, &sl3e);
        } else {
            printk("For non VMX shadow, create_l1_shadow:%d\n", create_l2_shadow);
        }
         shadow_update_min_max(l4e_get_pfn(sl4e), l3_table_offset(va));

    }

    if ( put_ref_check ) {
        l2_pgentry_t tmp_sl2e;
        if ( __shadow_get_l2e(v, va, &tmp_sl2e) ) {
            if ( l2e_get_flags(tmp_sl2e) & _PAGE_PRESENT )
                if ( l2e_get_pfn(tmp_sl2e) == l2e_get_pfn(sl2e) ) {
                    put_shadow_ref(l2e_get_pfn(sl2e));
                }
        }

    }

    if (! __shadow_set_l2e(v, va, &sl2e))
        BUG();
    shadow_update_min_max(l3e_get_pfn(sl3e), l2_table_offset(va));
}


/* As 32-bit guest don't support 4M page yet,
 * we don't concern double compile for this function
 */
static inline int l2e_rw_fault(
    struct vcpu *v, l2_pgentry_t *gl2e_p, unsigned long va, int rw)
{
    struct domain *d = v->domain;
    l2_pgentry_t gl2e = *gl2e_p;
    l2_pgentry_t tmp_l2e = gl2e;
    unsigned long start_gpfn = l2e_get_pfn(gl2e);
    unsigned long gpfn, mfn;
    unsigned long l1_mfn, gmfn;
    l1_pgentry_t *l1_p;
    l1_pgentry_t sl1e;
    l1_pgentry_t old_sl1e;
    l2_pgentry_t sl2e;
    u64 nx = 0;
    int put_ref_check = 0;
    /* Check if gpfn is 2M aligned */

    /* Update guest l2e */
    if (rw) {
        ASSERT(l2e_get_flags(gl2e) & _PAGE_RW);
        l2e_add_flags(gl2e, _PAGE_DIRTY | _PAGE_ACCESSED);
    } else {
        l2e_add_flags(gl2e, _PAGE_ACCESSED);
    }

    l2e_remove_flags(tmp_l2e, _PAGE_PSE);
    if (l2e_get_flags(gl2e) & _PAGE_NX) {
        l2e_remove_flags(tmp_l2e, _PAGE_NX);
        nx = 1ULL << 63;
    }


    /* Get the shadow l2 first */
    if ( !__shadow_get_l2e(v, va, &sl2e) )
        sl2e = l2e_empty();

    l1_mfn = ___shadow_status(d, start_gpfn | nx, PGT_fl1_shadow);

    /* Check the corresponding l2e */
    if (l1_mfn) {
        /* Why it is PRESENT?*/
        if ((l2e_get_flags(sl2e) & _PAGE_PRESENT) &&
                l2e_get_pfn(sl2e) == l1_mfn) {
            ESH_LOG("sl2e PRSENT bit is set: %lx, l1_mfn = %lx\n", l2e_get_pfn(sl2e), l1_mfn);
        } else {
            put_ref_check = 1;
            if (!get_shadow_ref(l1_mfn))
                BUG();
        }
        l1_p = (l1_pgentry_t *)map_domain_page(l1_mfn);
        sl2e = l2e_from_pfn(l1_mfn, l2e_get_flags(tmp_l2e));
    } else {
        /* Allocate a new page as shadow page table if need */
        gmfn = __gpfn_to_mfn(d, start_gpfn);
        l1_mfn = alloc_shadow_page(d, start_gpfn | nx, gmfn, PGT_fl1_shadow);
        if (unlikely(!l1_mfn)) {
            BUG();
        }

        if (!get_shadow_ref(l1_mfn))
            BUG();
        l1_p = (l1_pgentry_t *)map_domain_page(l1_mfn );
        sl2e = l2e_from_pfn(l1_mfn, l2e_get_flags(tmp_l2e));
        memset(l1_p, 0, PAGE_SIZE);
        ESH_LOG("Alloc a shadow page: %lx\n", l1_mfn);
    }

    ESH_LOG("<%s>: sl2e = %lx\n", __func__, l2e_get_intpte(sl2e));
    /* Map the page to l2*/
    shadow_set_l2e_64(va, sl2e, 1, put_ref_check);

    if (l2e_get_flags(gl2e) & _PAGE_NX)
        l2e_add_flags(tmp_l2e, _PAGE_NX);

    /* Propagate the shadow page table, i.e. setting sl1e */
    for (gpfn = start_gpfn;
      gpfn < (start_gpfn + L1_PAGETABLE_ENTRIES); gpfn++) {

        mfn = __gpfn_to_mfn(d, gpfn);

        if ( unlikely(!VALID_MFN(mfn)) )
        {
            continue;
        }

        sl1e = l1e_from_pfn(mfn, l2e_get_flags(tmp_l2e));

        if (!rw) {
            if ( shadow_mode_log_dirty(d) ||
              !(l2e_get_flags(gl2e) & _PAGE_DIRTY) || mfn_is_page_table(mfn) )
            {
                l1e_remove_flags(sl1e, _PAGE_RW);
            }
        } else {
            /* __mark_dirty(d, gmfn); */
        }
       // printk("<%s> gpfn: %lx, mfn: %lx, sl1e: %lx\n", __func__, gpfn, mfn, l1e_get_intpte(sl1e));
        /* The shadow entrys need setup before shadow_mark_va_out_of_sync()*/
        old_sl1e = l1_p[gpfn - start_gpfn];

        if ( l1e_has_changed(old_sl1e, sl1e, _PAGE_RW | _PAGE_PRESENT) )
        {
            if ( (l1e_get_flags(sl1e) & _PAGE_PRESENT) &&
              !shadow_get_page_from_l1e(sl1e, d) ) {
                ESH_LOG("%lx, mfn: %lx why make me empty, start_pfn: %lx, gpfn: %lx\n", l1e_get_intpte(sl1e),mfn, start_gpfn, gpfn);
                sl1e = l1e_empty();
            }
            if ( l1e_get_flags(old_sl1e) & _PAGE_PRESENT )
                put_page_from_l1e(old_sl1e, d);
        }

        l1_p[gpfn - start_gpfn] = sl1e;

        if (rw) {
            /* shadow_mark_va_out_of_sync() need modificatin for 2M pages*/
            if ( mfn_is_page_table(mfn) )
                shadow_mark_va_out_of_sync_2mp(v, gpfn, mfn,
                  l2e_get_paddr(sl2e) | (sizeof(l1_pgentry_t) * (gpfn - start_gpfn)));
        }
    }

    unmap_domain_page(l1_p);
    return 1;

}

/*
 * Check P, R/W, U/S bits in the guest page table.
 * If the fault belongs to guest return 1,
 * else return 0.
 */
#if defined( GUEST_PGENTRY_32 )
static inline int guest_page_fault(
    struct vcpu *v,
    unsigned long va, unsigned int error_code,
    guest_l2_pgentry_t *gpl2e, guest_l1_pgentry_t *gpl1e)
{
    /* The following check for 32-bit guest on 64-bit host */

    __guest_get_l2e(v, va, gpl2e);

    /* Check the guest L2 page-table entry first*/
    if ( unlikely(!(guest_l2e_get_flags(*gpl2e) & _PAGE_PRESENT)) )
        return 1;

    if ( error_code & ERROR_W ) 
    {
        if ( unlikely(!(guest_l2e_get_flags(*gpl2e) & _PAGE_RW)) )
            return 1;
    }

    if ( error_code & ERROR_U ) 
    {
        if ( unlikely(!(guest_l2e_get_flags(*gpl2e) & _PAGE_USER)) )
            return 1;
    }

    if ( guest_l2e_get_flags(*gpl2e) & _PAGE_PSE )
        return 0;

    __guest_get_l1e(v, va, gpl1e);

    /* Then check the guest L1 page-table entry */
    if ( unlikely(!(guest_l1e_get_flags(*gpl1e) & _PAGE_PRESENT)) )
        return 1;

    if ( error_code & ERROR_W ) 
    {
        if ( unlikely(!(guest_l1e_get_flags(*gpl1e) & _PAGE_RW)) )
            return 1;
    }

    if ( error_code & ERROR_U ) 
    {
        if ( unlikely(!(guest_l1e_get_flags(*gpl1e) & _PAGE_USER)) )
            return 1;
    }

    return 0;
}
#else
static inline int guest_page_fault(
    struct vcpu *v,
    unsigned long va, unsigned int error_code,
    guest_l2_pgentry_t *gpl2e, guest_l1_pgentry_t *gpl1e)
{
    struct domain *d = v->domain;
    pgentry_64_t gle;
    unsigned long gpfn = 0, mfn;
    int i;

    ASSERT( d->arch.ops->guest_paging_levels >= PAGING_L3 );

#if CONFIG_PAGING_LEVELS == 4
    if ( d->arch.ops->guest_paging_levels == PAGING_L4 ) 
    {
        __rw_entry(v, va, &gle, GUEST_ENTRY | GET_ENTRY | PAGING_L4);
        if ( unlikely(!(entry_get_flags(gle) & _PAGE_PRESENT)) )
            return 1;

        if ( error_code & ERROR_W )
        {
            if ( unlikely(!(entry_get_flags(gle) & _PAGE_RW)) )
                return 1;
        }

        if ( error_code & ERROR_U )
        {
            if ( unlikely(!(entry_get_flags(gle) & _PAGE_USER)) )
                return 1;
        }
        gpfn = entry_get_pfn(gle);
    }
#endif

#if CONFIG_PAGING_LEVELS >= 3
    if ( d->arch.ops->guest_paging_levels == PAGING_L3 ) 
    {
        gpfn = pagetable_get_pfn(v->arch.guest_table);
    }
#endif

    for ( i = PAGING_L3; i >= PAGING_L1; i-- ) 
    {
        pgentry_64_t *lva;
        /*
         * If it's not external mode, then mfn should be machine physical.
         */
        mfn = __gpfn_to_mfn(d, gpfn);

        lva = (pgentry_64_t *) map_domain_page(mfn);
        gle = lva[table_offset_64(va, i)];
        unmap_domain_page(lva);

        gpfn = entry_get_pfn(gle);

        if ( unlikely(!(entry_get_flags(gle) & _PAGE_PRESENT)) )
            return 1;

        if ( i < PAGING_L3 ) 
        {
            if ( error_code & ERROR_W ) 
            {
                if ( unlikely(!(entry_get_flags(gle) & _PAGE_RW)) ) 
                {
                    if ( i == PAGING_L1 )
                        if ( gpl1e )
                            gpl1e->l1 = gle.lo;
                    return 1;
                }
            }
            if ( error_code & ERROR_U ) 
            {
                if ( unlikely(!(entry_get_flags(gle) & _PAGE_USER)) )
                    return 1;
            }
        }

        if ( i == PAGING_L2 ) 
        {
            if ( gpl2e )
                gpl2e->l2 = gle.lo;
            if ( likely(entry_get_flags(gle) & _PAGE_PSE) )
                return 0;
        }

        if ( i == PAGING_L1 )
            if ( gpl1e )
                gpl1e->l1 = gle.lo;
    }

    return 0;

}
#endif

static int shadow_fault_64(unsigned long va, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    guest_l2_pgentry_t gl2e;
    guest_l1_pgentry_t gl1e, orig_gl1e;
    l1_pgentry_t sl1e;

    gl1e = guest_l1e_empty(); gl2e = guest_l2e_empty();

    sl1e = l1e_empty();

    perfc_incrc(shadow_fault_calls);

    ESH_LOG("<shadow_fault_64> va=%lx,  rip = %lx, error code = %x\n",
            va, regs->eip, regs->error_code);

    /*
     * Don't let someone else take the guest's table pages out-of-sync.
     */
    shadow_lock(d);

    /*
     * STEP 1. Check to see if this fault might have been caused by an
     *         out-of-sync table page entry, or if we should pass this
     *         fault onto the guest.
     */
    __shadow_sync_va(v, va);

    /*
     * STEP 2. Check if the fault belongs to guest
     */
    if ( guest_page_fault(v, va, regs->error_code, &gl2e, &gl1e) ) 
    {
        if ( unlikely(shadow_mode_log_dirty(d)) && l1e_get_intpte(gl1e) != 0 )
            goto check_writeable;
        
        goto fail;
    }

    if ( unlikely((guest_l2e_get_flags(gl2e) & _PAGE_PSE)) ) 
        goto pse;

    /*
     * Handle 4K pages here
     */
check_writeable:
    orig_gl1e = gl1e;
    
    /* Write fault? */
    if ( regs->error_code & 2 ) 
    {
        int allow_writes = 0;

        if ( unlikely(!(guest_l1e_get_flags(gl1e) & _PAGE_RW)) )
        {
            if ( shadow_mode_page_writable(va, regs, l1e_get_pfn(gl1e)) )
            {
                allow_writes = 1;
                l1e_add_flags(gl1e, _PAGE_RW);
            }
            else
            {
                /* Write fault on a read-only mapping. */
                SH_VVLOG("shadow_fault - EXIT: wr fault on RO page (%" PRIpte ")", 
                         l1e_get_intpte(gl1e));
                perfc_incrc(shadow_fault_bail_ro_mapping);
                goto fail;
            }
        }

        if ( !l1pte_write_fault(v, &gl1e, &sl1e, va) ) 
        {
            SH_VVLOG("shadow_fault - EXIT: l1pte_write_fault failed");
            perfc_incrc(write_fault_bail);
            shadow_unlock(d);
            return 0;
        }
 
        if (allow_writes)
            l1e_remove_flags(gl1e, _PAGE_RW);
    }
    else 
    {
        if ( !l1pte_read_fault(d, &gl1e, &sl1e) )
        {
            SH_VVLOG("shadow_fault - EXIT: l1pte_read_fault failed");
            perfc_incrc(read_fault_bail);
            shadow_unlock(d);
            return 0;
        }
    }

    /*
     * STEP 3. Write the modified shadow PTE and guest PTE back to the tables
     */
    if ( l1e_has_changed(orig_gl1e, gl1e, PAGE_FLAG_MASK) )
    {
        if (unlikely(!__guest_set_l1e(v, va, &gl1e))) 
            domain_crash_synchronous();

        __mark_dirty(d, __gpfn_to_mfn(d, l2e_get_pfn(gl2e)));
    }

    shadow_set_l1e_64(va, (pgentry_64_t *)&sl1e, 1);

    perfc_incrc(shadow_fault_fixed);
    d->arch.shadow_fault_count++;

    shadow_unlock(d);

    return EXCRET_fault_fixed;

pse:
    /*
     * Handle 2M pages here
     */
    if ( unlikely(!shadow_mode_external(d)) )
        BUG();

    /* Write fault? */
    if ( regs->error_code & 2 ) 
    {
        if ( !l2e_rw_fault(v, (l2_pgentry_t *)&gl2e, va, WRITE_FAULT) ) 
        {
            goto fail;
        }
    } 
    else 
    {
        l2e_rw_fault(v, (l2_pgentry_t *)&gl2e, va, READ_FAULT);
    }

    /*
     * STEP 3. Write guest/shadow l2e back
     */

    if ( unlikely(!__guest_set_l2e(v, va, &gl2e)) ) 
    {
        domain_crash_synchronous();
    }

    /*
     * Todo: if necessary, record the page table page as dirty
     */

    perfc_incrc(shadow_fault_fixed);
    d->arch.shadow_fault_count++;

    shadow_unlock(d);

    return EXCRET_fault_fixed;
fail:
    shadow_unlock(d);
    ESH_LOG("Guest fault~~~\n");
    return 0;
}

static void shadow_invlpg_64(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;
    l1_pgentry_t  sl1e, old_sl1e;

    shadow_lock(d);

    __shadow_sync_va(v, va);

    if ( shadow_mode_external(d) && __shadow_get_l1e(v, va, &old_sl1e) )
        if ( l1e_get_flags(old_sl1e) & _PAGE_PRESENT )
            put_page_from_l1e(old_sl1e, d);

    sl1e = l1e_empty();
    __shadow_set_l1e(v, va, &sl1e);

    shadow_unlock(d);
}

#if CONFIG_PAGING_LEVELS == 4
static unsigned long gva_to_gpa_64(unsigned long gva)
{
    struct vcpu *v = current;
    guest_l1_pgentry_t gl1e = {0};
    guest_l2_pgentry_t gl2e = {0};
    unsigned long gpa;

    if (guest_page_fault(v, gva, 0, &gl2e, &gl1e))
        return 0;

    if (guest_l2e_get_flags(gl2e) & _PAGE_PSE)
        gpa = guest_l2e_get_paddr(gl2e) + (gva & ((1 << GUEST_L2_PAGETABLE_SHIFT) - 1));
    else
        gpa = guest_l1e_get_paddr(gl1e) + (gva & ~PAGE_MASK);

    return gpa;
}

#ifndef GUEST_PGENTRY_32
struct shadow_ops MODE_F_HANDLER = {
    .guest_paging_levels        = 4,
    .invlpg                     = shadow_invlpg_64,
    .fault                      = shadow_fault_64,
    .update_pagetables          = shadow_update_pagetables,
    .sync_all                   = sync_all,
    .remove_all_write_access    = remove_all_write_access,
    .do_update_va_mapping       = do_update_va_mapping,
    .mark_mfn_out_of_sync       = mark_mfn_out_of_sync,
    .is_out_of_sync             = is_out_of_sync,
    .gva_to_gpa                 = gva_to_gpa_64,
};
#endif /* GUEST_PGENTRY_32 */
#endif /* CONFIG_PAGING_LEVELS == 4 */

#endif /* CONFIG_PAGING_LEVELS >= 3 */


#if CONFIG_PAGING_LEVELS == 2
struct shadow_ops MODE_A_HANDLER = {
    .guest_paging_levels        = 2,
    .invlpg                     = shadow_invlpg_32,
    .fault                      = shadow_fault_32,
    .update_pagetables          = shadow_update_pagetables,
    .sync_all                   = sync_all,
    .remove_all_write_access    = remove_all_write_access,
    .do_update_va_mapping       = do_update_va_mapping,
    .mark_mfn_out_of_sync       = mark_mfn_out_of_sync,
    .is_out_of_sync             = is_out_of_sync,
    .gva_to_gpa                 = gva_to_gpa_64,
};

#elif CONFIG_PAGING_LEVELS == 3

struct shadow_ops MODE_B_HANDLER = {
    .guest_paging_levels        = 3,
    .invlpg                     = shadow_invlpg_64,
    .fault                      = shadow_fault_64,
    .update_pagetables          = shadow_update_pagetables,
    .sync_all                   = sync_all,
    .remove_all_write_access    = remove_all_write_access,
    .do_update_va_mapping       = do_update_va_mapping,
    .mark_mfn_out_of_sync       = mark_mfn_out_of_sync,
    .is_out_of_sync             = is_out_of_sync,
    .gva_to_gpa                 = gva_to_gpa_pae,
};

#endif


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
