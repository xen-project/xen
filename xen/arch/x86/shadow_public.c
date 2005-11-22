/******************************************************************************
 * arch/x86/shadow_public.c
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

#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>

#endif
#if CONFIG_PAGING_LEVELS == 4
extern struct shadow_ops MODE_F_HANDLER;
extern struct shadow_ops MODE_D_HANDLER;
#endif

extern struct shadow_ops MODE_A_HANDLER;

#define SHADOW_MAX_GUEST32(_encoded) ((L1_PAGETABLE_ENTRIES_32 - 1) - ((_encoded) >> 16))
/****************************************************************************/
/************* export interface functions ***********************************/
/****************************************************************************/


int shadow_set_guest_paging_levels(struct domain *d, int levels)
{
    shadow_lock(d);

    switch(levels) {
#if CONFIG_PAGING_LEVELS >= 4
    case 4:
        if ( d->arch.ops != &MODE_F_HANDLER )
            d->arch.ops = &MODE_F_HANDLER;
        shadow_unlock(d);
        return 1;
#endif
    case 3:
    case 2:
#if CONFIG_PAGING_LEVELS == 2
        if ( d->arch.ops != &MODE_A_HANDLER )
            d->arch.ops = &MODE_A_HANDLER;
#elif CONFIG_PAGING_LEVELS == 3
        if ( d->arch.ops != &MODE_B_HANDLER )
            d->arch.ops = &MODE_B_HANDLER;
#elif CONFIG_PAGING_LEVELS == 4
        if ( d->arch.ops != &MODE_D_HANDLER )
            d->arch.ops = &MODE_D_HANDLER;
#endif
        shadow_unlock(d);
        return 1;
    default:
        shadow_unlock(d);
        return 0;
    }
}

void shadow_invlpg(struct vcpu *v, unsigned long va)
{
    struct domain *d = current->domain;
    d->arch.ops->invlpg(v, va);
}

int shadow_fault(unsigned long va, struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    return d->arch.ops->fault(va, regs);
}

void __update_pagetables(struct vcpu *v)
{
    struct domain *d = v->domain;
    d->arch.ops->update_pagetables(v);
}

void __shadow_sync_all(struct domain *d)
{
    d->arch.ops->sync_all(d);
}
    
int shadow_remove_all_write_access(
    struct domain *d, unsigned long readonly_gpfn, unsigned long readonly_gmfn)
{
    return d->arch.ops->remove_all_write_access(d, readonly_gpfn, readonly_gmfn);
}

int shadow_do_update_va_mapping(unsigned long va,
                                l1_pgentry_t val,
                                struct vcpu *v)
{
    struct domain *d = v->domain;
    return d->arch.ops->do_update_va_mapping(va, val, v);
}

struct out_of_sync_entry *
shadow_mark_mfn_out_of_sync(struct vcpu *v, unsigned long gpfn,
                            unsigned long mfn)
{
    struct domain *d = v->domain;
    return d->arch.ops->mark_mfn_out_of_sync(v, gpfn, mfn);
}

/*
 * Returns 1 if va's shadow mapping is out-of-sync.
 * Returns 0 otherwise.
 */
int __shadow_out_of_sync(struct vcpu *v, unsigned long va)
{
    struct domain *d = v->domain;
    return d->arch.ops->is_out_of_sync(v, va);
}

unsigned long gva_to_gpa(unsigned long gva)
{
    struct domain *d = current->domain;
    return d->arch.ops->gva_to_gpa(gva);
}
/****************************************************************************/
/****************************************************************************/
#if CONFIG_PAGING_LEVELS >= 3

static void inline
free_shadow_fl1_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *pl1e = map_domain_page(smfn);
    int i;

    for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
        put_page_from_l1e(pl1e[i], d);
}

/*
 * Free l2, l3, l4 shadow tables
 */

void free_fake_shadow_l2(struct domain *d,unsigned long smfn);

static void inline
free_shadow_tables(struct domain *d, unsigned long smfn, u32 level)
{
    pgentry_64_t *ple = map_domain_page(smfn);
    int i, external = shadow_mode_external(d);

#if CONFIG_PAGING_LEVELS >=3
    if ( d->arch.ops->guest_paging_levels == PAGING_L2 )
    {
        struct pfn_info *page = &frame_table[smfn];
        for ( i = 0; i < PDP_ENTRIES; i++ )
        {
            if ( entry_get_flags(ple[i]) & _PAGE_PRESENT )
                free_fake_shadow_l2(d,entry_get_pfn(ple[i]));
        }

        page = &frame_table[entry_get_pfn(ple[0])];
        free_domheap_pages(page, SL2_ORDER);
        unmap_domain_page(ple);
    }
    else
#endif
    {
        /*
         * No Xen mappings in external pages
         */
        if ( external )
        {
            for ( i = 0; i < PAGETABLE_ENTRIES; i++ )
                if ( entry_get_flags(ple[i]) & _PAGE_PRESENT )
                    put_shadow_ref(entry_get_pfn(ple[i]));
        } 
        else
        {
            for ( i = 0; i < PAGETABLE_ENTRIES; i++ )
            {
                /* 
                 * List the skip/break conditions to avoid freeing
                 * Xen private mappings.
                 */
#if CONFIG_PAGING_LEVELS == 2
                if ( level == PAGING_L2 && !is_guest_l2_slot(0, i) )
                    continue;
#endif
#if CONFIG_PAGING_LEVELS == 3
                if ( level == PAGING_L3 && i == L3_PAGETABLE_ENTRIES )
                    break;
                if ( level == PAGING_L2 )
                {
                    struct pfn_info *page = &frame_table[smfn]; 
                    if ( is_xen_l2_slot(page->u.inuse.type_info, i) )
                        continue;
                }
#endif
#if CONFIG_PAGING_LEVELS == 4
                if ( level == PAGING_L4 && !is_guest_l4_slot(i))
                    continue;
#endif
                if ( entry_get_flags(ple[i]) & _PAGE_PRESENT )
                    put_shadow_ref(entry_get_pfn(ple[i]));
            }
        }
        unmap_domain_page(ple);
    }
}
#endif

#if CONFIG_PAGING_LEVELS == 4
/*
 * Convert PAE 3-level page-table to 4-level page-table
 */
static pagetable_t page_table_convert(struct domain *d)
{
    struct pfn_info *l4page, *l3page;
    l4_pgentry_t *l4;
    l3_pgentry_t *l3, *pae_l3;
    int i;
    
    l4page = alloc_domheap_page(NULL);
    if (l4page == NULL)
        domain_crash(d);
    l4 = map_domain_page(page_to_pfn(l4page));
    memset(l4, 0, PAGE_SIZE);

    l3page = alloc_domheap_page(NULL);
    if (l3page == NULL)
        domain_crash(d);
    l3 =  map_domain_page(page_to_pfn(l3page));
    memset(l3, 0, PAGE_SIZE);

    l4[0] = l4e_from_page(l3page, __PAGE_HYPERVISOR);
    pae_l3 = map_domain_page(pagetable_get_pfn(d->arch.phys_table));

    for (i = 0; i < PDP_ENTRIES; i++) {
        l3[i] = pae_l3[i];
        l3e_add_flags(l3[i], 0x67);
    }

    unmap_domain_page(l4);
    unmap_domain_page(l3);

    return mk_pagetable(page_to_phys(l4page));
}

static void alloc_monitor_pagetable(struct vcpu *v)
{
    unsigned long mmfn;
    l4_pgentry_t *mpl4e;
    struct pfn_info *mmfn_info;
    struct domain *d = v->domain;
    pagetable_t phys_table;

    ASSERT(!pagetable_get_paddr(v->arch.monitor_table)); /* we should only get called once */

    mmfn_info = alloc_domheap_page(NULL);
    ASSERT( mmfn_info );

    mmfn = (unsigned long) (mmfn_info - frame_table);
    mpl4e = (l4_pgentry_t *) map_domain_page(mmfn);
    memcpy(mpl4e, &idle_pg_table[0], PAGE_SIZE);
    mpl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(d->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    /* map the phys_to_machine map into the per domain Read-Only MPT space */
    phys_table = page_table_convert(d);

    mpl4e[l4_table_offset(RO_MPT_VIRT_START)] =
        l4e_from_paddr(pagetable_get_paddr(phys_table),
                       __PAGE_HYPERVISOR);
    v->arch.monitor_table = mk_pagetable(mmfn << PAGE_SHIFT);
    v->arch.monitor_vtable = (l2_pgentry_t *) mpl4e;
}

void free_monitor_pagetable(struct vcpu *v)
{
    unsigned long mfn;

    /*
     * free monitor_table.
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

#elif CONFIG_PAGING_LEVELS == 3

static void alloc_monitor_pagetable(struct vcpu *v)
{
    BUG(); /* PAE not implemented yet */
}

void free_monitor_pagetable(struct vcpu *v)
{
    BUG(); /* PAE not implemented yet */
}

#elif CONFIG_PAGING_LEVELS == 2

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

    memcpy(&mpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

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
#endif 

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

void
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

static void inline
free_shadow_l1_table(struct domain *d, unsigned long smfn)
{
    l1_pgentry_t *pl1e = map_domain_page(smfn);
    int i;
    struct pfn_info *spage = pfn_to_page(smfn);
    u32 min_max = spage->tlbflush_timestamp;
    int min = SHADOW_MIN(min_max);
    int max;
    
    if (d->arch.ops->guest_paging_levels == PAGING_L2)
        max = SHADOW_MAX_GUEST32(min_max);
    else
        max = SHADOW_MAX(min_max);

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

#if CONFIG_PAGING_LEVELS == 2
    if ( shadow_mode_external(d) )
        limit = L2_PAGETABLE_ENTRIES;
    else
        limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
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

void free_fake_shadow_l2(struct domain *d, unsigned long smfn)
{
    pgentry_64_t *ple = map_domain_page(smfn);
    int i;

    for ( i = 0; i < PAGETABLE_ENTRIES; i = i + 2 )
    {
        if ( entry_get_flags(ple[i]) & _PAGE_PRESENT )
            put_shadow_ref(entry_get_pfn(ple[i]));
    }

    unmap_domain_page(ple);
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
#if CONFIG_PAGING_LEVELS >=4
    if ( type == PGT_fl1_shadow ) 
    {
        unsigned long mfn;
        mfn = __shadow_status(d, gpfn, PGT_fl1_shadow);
        if ( !mfn )
            gpfn |= (1UL << 63);
    }
#endif

    delete_shadow_status(d, gpfn, gmfn, type);

    switch ( type )
    {
    case PGT_l1_shadow:
        perfc_decr(shadow_l1_pages);
        shadow_demote(d, gpfn, gmfn);
        free_shadow_l1_table(d, smfn);
        d->arch.shadow_page_count--;
        break;
#if CONFIG_PAGING_LEVELS == 2
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
#endif
#if CONFIG_PAGING_LEVELS >= 3
    case PGT_l2_shadow:
    case PGT_l3_shadow:
    case PGT_l4_shadow:
        shadow_demote(d, gpfn, gmfn);
        free_shadow_tables(d, smfn, shadow_type_to_level(type));
        d->arch.shadow_page_count--;
        break;

    case PGT_fl1_shadow:
        free_shadow_fl1_table(d, smfn);
        d->arch.shadow_page_count--;
        break;
#endif
    case PGT_snapshot:
        perfc_decr(apshot_pages);
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
            delete_shadow_status(d, gpfn_list[count], 0, PGT_writable_pred);
        }

        xfree(gpfn_list);
    }
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

void free_shadow_pages(struct domain *d)
{
    int                   i;
    struct shadow_status *x;
    struct vcpu          *v;
    struct list_head *list_ent, *tmp;

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

#if CONFIG_PAGING_LEVELS == 2
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
#endif
    // Now, the only refs to shadow pages that are left are from the shadow
    // pages themselves.  We just unpin the pinned pages, and the rest
    // should automatically disappear.
    //
    // NB: Beware: each explicitly or implicit call to free_shadow_page
    // can/will result in the hash bucket getting rewritten out from
    // under us...  First, collect the list of pinned pages, then
    // free them.
    //
    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        u32 count;
        unsigned long *mfn_list;

        /* Skip empty buckets. */
        if ( d->arch.shadow_ht[i].gpfn_and_flags == 0 )
            continue;

        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next )
            if ( MFN_PINNED(x->smfn) )
                count++;
        if ( !count )
            continue;

        mfn_list = xmalloc_array(unsigned long, count);
        count = 0;
        for ( x = &d->arch.shadow_ht[i]; x != NULL; x = x->next )
            if ( MFN_PINNED(x->smfn) )
                mfn_list[count++] = x->smfn;

        while ( count )
        {
            shadow_unpin(mfn_list[--count]);
        }
        xfree(mfn_list);
    }

    /* Now free the pre-zero'ed pages from the domain. */
    list_for_each_safe(list_ent, tmp, &d->arch.free_shadow_frames)
    {
        struct pfn_info *page = list_entry(list_ent, struct pfn_info, list);

        list_del(list_ent);
        perfc_decr(free_l1_pages);

        if (d->arch.ops->guest_paging_levels == PAGING_L2)
        {
#if CONFIG_PAGING_LEVELS >=4
            free_domheap_pages(page, SL1_ORDER);
#else
            free_domheap_page(page);
#endif
        }
        else
            free_domheap_page(page);
    }

    shadow_audit(d, 0);

    SH_LOG("Free shadow table.");
}

void __shadow_mode_disable(struct domain *d)
{
    struct vcpu *v;
#ifndef NDEBUG
    int i;
#endif

    if ( unlikely(!shadow_mode_enabled(d)) )
        return;

    free_shadow_pages(d);
    free_writable_pte_predictions(d);

#ifndef NDEBUG
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

    for_each_vcpu(d, v)
        update_pagetables(v);
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

#if defined(CONFIG_PAGING_LEVELS)
    if(!shadow_set_guest_paging_levels(d,
                                       CONFIG_PAGING_LEVELS)) {
        printk("Unsupported guest paging levels\n");
        domain_crash_synchronous(); /* need to take a clean path */
    }
#endif

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
        if ( !(mode & SHM_external) && d->arch.ops->guest_paging_levels == 2)
            v->arch.shadow_vtable = __shadow_linear_l2_table;
        else
            v->arch.shadow_vtable = NULL;
        
#if CONFIG_PAGING_LEVELS == 2
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
#endif
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
        if ( shadow_mode_enabled(d) )
        {
            __shadow_sync_all(d);
            __shadow_mode_disable(d);
        }
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

void shadow_mode_init(void)
{
}

int _shadow_mode_refcounts(struct domain *d)
{
    return shadow_mode_refcounts(d);
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

int
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
        SH_VVLOG("shadow_l1_normal_pt_update pa=%p, gpde=%" PRIpte,
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
    unsigned long pa, l3_pgentry_t l3e,
    struct domain_mmap_cache *cache)
{
    unsigned long sl3mfn;
    pgentry_64_t *spl3e;

    shadow_lock(d);

    sl3mfn = __shadow_status(current->domain, pa >> PAGE_SHIFT, PGT_l3_shadow);
    if ( sl3mfn )
    {
        SH_VVLOG("shadow_l3_normal_pt_update pa=%p, l3e=%" PRIpte,
                 (void *)pa, l3e_get_intpte(l3e));
        spl3e = (pgentry_64_t *) map_domain_page_with_cache(sl3mfn, cache);
        validate_entry_change(d, (pgentry_64_t *) &l3e,
                              &spl3e[(pa & ~PAGE_MASK) / sizeof(l3_pgentry_t)], 
                              shadow_type_to_level(PGT_l3_shadow));
        unmap_domain_page_with_cache(spl3e, cache);
    }

    shadow_unlock(d);
}
#endif

#if CONFIG_PAGING_LEVELS >= 4
void shadow_l4_normal_pt_update(
    struct domain *d,
    unsigned long pa, l4_pgentry_t l4e,
    struct domain_mmap_cache *cache)
{
    unsigned long sl4mfn;
    pgentry_64_t *spl4e;

    shadow_lock(d);

    sl4mfn = __shadow_status(current->domain, pa >> PAGE_SHIFT, PGT_l4_shadow);
    if ( sl4mfn )
    {
        SH_VVLOG("shadow_l4_normal_pt_update pa=%p, l4e=%" PRIpte,
                 (void *)pa, l4e_get_intpte(l4e));
        spl4e = (pgentry_64_t *)map_domain_page_with_cache(sl4mfn, cache);
        validate_entry_change(d, (pgentry_64_t *)&l4e,
                              &spl4e[(pa & ~PAGE_MASK) / sizeof(l4_pgentry_t)], 
                              shadow_type_to_level(PGT_l4_shadow));
        unmap_domain_page_with_cache(spl4e, cache);
    }

    shadow_unlock(d);
}
#endif

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

void
remove_shadow(struct domain *d, unsigned long gpfn, u32 stype)
{
    unsigned long smfn;

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

unsigned long
gpfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
    unsigned long va, tabpfn;
    l1_pgentry_t *l1, l1e;
    l2_pgentry_t *l2, l2e;

    ASSERT(shadow_mode_translate(d));

    perfc_incrc(gpfn_to_mfn_foreign);

    va = gpfn << PAGE_SHIFT;
    tabpfn = pagetable_get_pfn(d->arch.phys_table);
    l2 = map_domain_page(tabpfn);
    l2e = l2[l2_table_offset(va)];
    unmap_domain_page(l2);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
    {
        printk("gpfn_to_mfn_foreign(d->id=%d, gpfn=%lx) => 0 l2e=%" PRIpte "\n",
               d->domain_id, gpfn, l2e_get_intpte(l2e));
        return INVALID_MFN;
    }
    l1 = map_domain_page(l2e_get_pfn(l2e));
    l1e = l1[l1_table_offset(va)];
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

static u32 __shadow_remove_all_access(struct domain *d, unsigned long forbidden_gmfn)
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

void shadow_drop_references(
    struct domain *d, struct pfn_info *page)
{
    if ( likely(!shadow_mode_refcounts(d)) ||
         ((page->u.inuse.type_info & PGT_count_mask) == 0) )
        return;

    /* XXX This needs more thought... */
    printk("%s: needing to call __shadow_remove_all_access for mfn=%lx\n",
           __func__, page_to_pfn(page));
    printk("Before: mfn=%lx c=%08x t=%" PRtype_info "\n", page_to_pfn(page),
           page->count_info, page->u.inuse.type_info);

    shadow_lock(d);
    __shadow_remove_all_access(d, page_to_pfn(page));
    shadow_unlock(d);

    printk("After:  mfn=%lx c=%08x t=%" PRtype_info "\n", page_to_pfn(page),
           page->count_info, page->u.inuse.type_info);
}

/* XXX Needs more thought. Neither pretty nor fast: a place holder. */
void shadow_sync_and_drop_references(
    struct domain *d, struct pfn_info *page)
{
    if ( likely(!shadow_mode_refcounts(d)) )
        return;

    shadow_lock(d);

    if ( page_out_of_sync(page) )
        __shadow_sync_mfn(d, page_to_pfn(page));

    __shadow_remove_all_access(d, page_to_pfn(page));

    shadow_unlock(d);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
