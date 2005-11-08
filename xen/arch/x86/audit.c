/******************************************************************************
 * arch/x86/audit.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>

/* XXX SMP bug -- these should not be statics... */
static int ttot=0, ctot=0, io_mappings=0, lowmem_mappings=0;
static int l1, l2, oos_count, page_count;

#define FILE_AND_LINE 0

#if FILE_AND_LINE
#define adjust(_p, _a) _adjust((_p), (_a), __FILE__, __LINE__)
#define ADJUST_EXTRA_ARGS ,const char *file, int line
#define APRINTK(_f, _a...) printk(_f " %s:%d\n", ## _a, file, line)
#else
#define adjust _adjust
#define ADJUST_EXTRA_ARGS
#define APRINTK(_f, _a...) printk(_f "\n", ##_a)
#endif

int audit_adjust_pgtables(struct domain *d, int dir, int noisy)
{
    int errors = 0;
    int shadow_refcounts = !!shadow_mode_refcounts(d);
    int shadow_enabled = !!shadow_mode_enabled(d);
    int l2limit;

    void _adjust(struct pfn_info *page, int adjtype ADJUST_EXTRA_ARGS)
    {
        if ( adjtype )
        {
            // adjust the type count
            //
            int tcount = page->u.inuse.type_info & PGT_count_mask;
            tcount += dir;
            ttot++;

            if ( page_get_owner(page) == NULL )
            {
                APRINTK("adjust(mfn=%lx, dir=%d, adjtype=%d) owner=NULL",
                        page_to_pfn(page), dir, adjtype);
                errors++;
            }

            if ( tcount < 0 )
            {
                APRINTK("Audit %d: type count went below zero "
                        "mfn=%lx t=%" PRtype_info " ot=%x",
                        d->domain_id, page_to_pfn(page),
                        page->u.inuse.type_info,
                        page->tlbflush_timestamp);
                errors++;
            }
            else if ( (tcount & ~PGT_count_mask) != 0 )
            {
                APRINTK("Audit %d: type count overflowed "
                        "mfn=%lx t=%" PRtype_info " ot=%x",
                        d->domain_id, page_to_pfn(page),
                        page->u.inuse.type_info,
                        page->tlbflush_timestamp);
                errors++;
            }
            else
                page->u.inuse.type_info += dir;
        }

        // adjust the general count
        //
        int count = page->count_info & PGC_count_mask;
        count += dir;
        ctot++;

        if ( count < 0 )
        {
            APRINTK("Audit %d: general count went below zero "
                    "mfn=%lx t=%" PRtype_info " ot=%x",
                    d->domain_id, page_to_pfn(page),
                    page->u.inuse.type_info,
                    page->tlbflush_timestamp);
            errors++;
        }
        else if ( (count & ~PGT_count_mask) != 0 )
        {
            APRINTK("Audit %d: general count overflowed "
                    "mfn=%lx t=%" PRtype_info " ot=%x",
                    d->domain_id, page_to_pfn(page),
                    page->u.inuse.type_info,
                    page->tlbflush_timestamp);
            errors++;
        }
        else
            page->count_info += dir;
    }

    void adjust_l2_page(unsigned long mfn, int shadow)
    {
        unsigned long *pt = map_domain_page(mfn);
        int i;

        for ( i = 0; i < l2limit; i++ )
        {
            if ( pt[i] & _PAGE_PRESENT )
            {
                unsigned long l1mfn = pt[i] >> PAGE_SHIFT;
                struct pfn_info *l1page = pfn_to_page(l1mfn);

                if ( noisy )
                {
                    if ( shadow )
                    {
                        if ( page_get_owner(l1page) != NULL )
                        {
                            printk("L2: Bizarre shadow L1 page mfn=%lx "
                                   "belonging to a domain %p (id=%d)\n",
                                   l1mfn,
                                   page_get_owner(l1page),
                                   page_get_owner(l1page)->domain_id);
                            errors++;
                            continue;
                        }

                        u32 page_type = l1page->u.inuse.type_info & PGT_type_mask;

                        if ( page_type != PGT_l1_shadow )
                        {
                            printk("Audit %d: [Shadow L2 mfn=%lx i=%x] "
                                   "Expected Shadow L1 t=%" PRtype_info 
				   " mfn=%lx\n",
                                   d->domain_id, mfn, i,
                                   l1page->u.inuse.type_info, l1mfn);
                            errors++;
                        }
                    }
                    else
                    {
                        if ( page_get_owner(l1page) != d )
                        {
                            printk("L2: Skip bizarre L1 page mfn=%lx "
                                   "belonging to other dom %p (id=%d)\n",
                                   l1mfn,
                                   page_get_owner(l1page),
                                   (page_get_owner(l1page)
                                    ? page_get_owner(l1page)->domain_id
                                    : -1));
                            errors++;
                            continue;
                        }

                        u32 page_type = l1page->u.inuse.type_info & PGT_type_mask;

                        if ( page_type == PGT_l2_page_table )
                        {
                            printk("Audit %d: [%x] Found %s Linear PT "
                                   "t=%" PRtype_info " mfn=%lx\n",
                                   d->domain_id, i, (l1mfn==mfn) ? "Self" : "Other",
                                   l1page->u.inuse.type_info, l1mfn);
                        }
                        else if ( page_type != PGT_l1_page_table )
                        {
                            printk("Audit %d: [L2 mfn=%lx i=%x] "
                                   "Expected L1 t=%" PRtype_info " mfn=%lx\n",
                                   d->domain_id, mfn, i,
                                   l1page->u.inuse.type_info, l1mfn);
                            errors++;
                        }
                    }
                }

                adjust(l1page, !shadow);
            }
        }

        if ( shadow_mode_translate(d) && !shadow_mode_external(d) )
        {
            unsigned long hl2mfn =
                pt[l2_table_offset(LINEAR_PT_VIRT_START)] >> PAGE_SHIFT;
            struct pfn_info *hl2page = pfn_to_page(hl2mfn);
            adjust(hl2page, 0);
        }

        unmap_domain_page(pt);
    }

    void adjust_hl2_page(unsigned long hl2mfn)
    {
        unsigned long *pt = map_domain_page(hl2mfn);
        int i;

        for ( i = 0; i < l2limit; i++ )
        {
            if ( pt[i] & _PAGE_PRESENT )
            {
                unsigned long gmfn = pt[i] >> PAGE_SHIFT;
                struct pfn_info *gpage = pfn_to_page(gmfn);

                if ( gmfn < 0x100 )
                {
                    lowmem_mappings++;
                    continue;
                }

                if ( gmfn > max_page )
                {
                    io_mappings++;
                    continue;
                }

                if ( noisy )
                {
                    if ( page_get_owner(gpage) != d )
                    {
                        printk("Audit %d: [hl2mfn=%lx,i=%x] Skip foreign page "
                               "dom=%p (id=%d) mfn=%lx c=%08x t=%"
			       PRtype_info "\n",
                               d->domain_id, hl2mfn, i,
                               page_get_owner(gpage),
                               page_get_owner(gpage)->domain_id,
                               gmfn,
                               gpage->count_info,
                               gpage->u.inuse.type_info);
                        continue;
                    }
                }
                adjust(gpage, 0);
            }
        }

        unmap_domain_page(pt);
    }

    void adjust_l1_page(unsigned long l1mfn)
    {
        unsigned long *pt = map_domain_page(l1mfn);
        int i;

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            if ( pt[i] & _PAGE_PRESENT )
            {
                unsigned long gmfn = pt[i] >> PAGE_SHIFT;
                struct pfn_info *gpage = pfn_to_page(gmfn);

                if ( gmfn < 0x100 )
                {
                    lowmem_mappings++;
                    continue;
                }

                if ( gmfn > max_page )
                {
                    io_mappings++;
                    continue;
                }

                if ( noisy )
                {
                    if ( pt[i] & _PAGE_RW )
                    {
                        // If it's not a writable page, complain.
                        //
                        if ( !((gpage->u.inuse.type_info & PGT_type_mask) ==
                               PGT_writable_page) )
                        {
                            printk("Audit %d: [l1mfn=%lx, i=%x] Illegal RW "
                                   "t=%" PRtype_info " mfn=%lx\n",
                                   d->domain_id, l1mfn, i,
                                   gpage->u.inuse.type_info, gmfn);
                            errors++;
                        }

                        if ( shadow_refcounts &&
                             page_is_page_table(gpage) &&
                             ! page_out_of_sync(gpage) )
                        {
                            printk("Audit %d: [l1mfn=%lx, i=%x] Illegal RW of "
                                   "page table gmfn=%lx\n",
                                   d->domain_id, l1mfn, i, gmfn);
                            errors++;
                        }
                    }		   

                    if ( page_get_owner(gpage) != d )
                    {
                        printk("Audit %d: [l1mfn=%lx,i=%x] Skip foreign page "
                               "dom=%p (id=%d) mfn=%lx c=%08x t=%" 
			       PRtype_info "\n",
                               d->domain_id, l1mfn, i,
                               page_get_owner(gpage),
                               page_get_owner(gpage)->domain_id,
                               gmfn,
                               gpage->count_info,
                               gpage->u.inuse.type_info);
                        continue;
                    }
                }

                adjust(gpage, (pt[i] & _PAGE_RW) ? 1 : 0);
            }
        }

        unmap_domain_page(pt);
    }

    void adjust_shadow_tables()
    {
        struct shadow_status *a;
        unsigned long smfn, gmfn;
        struct pfn_info *page;
        int i;

        for ( i = 0; i < shadow_ht_buckets; i++ )
        {
            a = &d->arch.shadow_ht[i];
            while ( a && a->gpfn_and_flags )
            {
                gmfn = __gpfn_to_mfn(d, a->gpfn_and_flags & PGT_mfn_mask);
                smfn = a->smfn;
                page = &frame_table[smfn];

                switch ( a->gpfn_and_flags & PGT_type_mask ) {
                case PGT_writable_pred:
                    break;
                case PGT_snapshot:
                    adjust(pfn_to_page(gmfn), 0);
                    break;
                case PGT_l1_shadow:
                    adjust(pfn_to_page(gmfn), 0);
                    if ( shadow_refcounts )
                        adjust_l1_page(smfn);
                    if ( page->u.inuse.type_info & PGT_pinned )
                        adjust(page, 0);
                    break;
                case PGT_hl2_shadow:
                    adjust(pfn_to_page(gmfn), 0);
                    if ( shadow_refcounts )
                        adjust_hl2_page(smfn);
                    if ( page->u.inuse.type_info & PGT_pinned )
                        adjust(page, 0);
                    break;
                case PGT_l2_shadow:
                    adjust(pfn_to_page(gmfn), 0);
                    adjust_l2_page(smfn, 1);
                    if ( page->u.inuse.type_info & PGT_pinned )
                        adjust(page, 0);
                    break;
                default:
                    BUG();
                    break;
                }

                a = a->next;
            }
        }
    }

    void adjust_oos_list()
    {
        struct out_of_sync_entry *oos;

        if ( (oos = d->arch.out_of_sync) )
            ASSERT(shadow_enabled);

        while ( oos )
        {
            adjust(pfn_to_page(oos->gmfn), 0);

            // Only use entries that have low bits clear...
            //
            if ( !(oos->writable_pl1e & (sizeof(l1_pgentry_t)-1)) )
                adjust(pfn_to_page(oos->writable_pl1e >> PAGE_SHIFT), 0);

            if ( oos->snapshot_mfn != SHADOW_SNAPSHOT_ELSEWHERE )
                adjust(pfn_to_page(oos->snapshot_mfn), 0);

            oos = oos->next;
            oos_count++;
        }
    }

    void adjust_for_pgtbase()
    {
        struct vcpu *v;

        for_each_vcpu(d, v)
        {
            if ( pagetable_get_paddr(v->arch.guest_table) )
                adjust(&frame_table[pagetable_get_pfn(v->arch.guest_table)], !shadow_mode_refcounts(d));
            if ( pagetable_get_paddr(v->arch.shadow_table) )
                adjust(&frame_table[pagetable_get_pfn(v->arch.shadow_table)], 0);
            if ( v->arch.monitor_shadow_ref )
                adjust(&frame_table[v->arch.monitor_shadow_ref], 0);
        }
    }

    void adjust_guest_pages()
    {
        struct list_head *list_ent = d->page_list.next;
        struct pfn_info *page;
        unsigned long mfn, snapshot_mfn;

        while ( list_ent != &d->page_list )
        {
            u32 page_type;

            page = list_entry(list_ent, struct pfn_info, list);
            snapshot_mfn = mfn = page_to_pfn(page);
            page_type = page->u.inuse.type_info & PGT_type_mask;

            BUG_ON(page_get_owner(page) != d);

            page_count++;

            if ( shadow_enabled && !shadow_refcounts &&
                 page_out_of_sync(page) )
            {
                unsigned long gpfn = __mfn_to_gpfn(d, mfn);
                ASSERT( VALID_M2P(gpfn) );
                snapshot_mfn = __shadow_status(d, gpfn, PGT_snapshot);
                ASSERT( snapshot_mfn );
            }

            switch ( page_type )
            {
            case PGT_l2_page_table:
                l2++;

                if ( noisy )
                {
                    if ( shadow_refcounts )
                    {
                        printk("Audit %d: found an L2 guest page "
                               "mfn=%lx t=%" PRtype_info " c=%08x while in shadow mode\n",
                               d->domain_id, mfn, page->u.inuse.type_info,
                               page->count_info);
                        errors++;
                    }

                    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
                    {
                        if ( (page->u.inuse.type_info & PGT_validated) !=
                             PGT_validated )
                        {
                            printk("Audit %d: L2 mfn=%lx not validated %"
				   PRtype_info "\n",
                                   d->domain_id, mfn, page->u.inuse.type_info);
                            errors++;
                        }

                        if ( (page->u.inuse.type_info & PGT_pinned) != PGT_pinned )
                        {
                            printk("Audit %d: L2 mfn=%lx not pinned t=%"
				   PRtype_info "\n",
                                   d->domain_id, mfn, page->u.inuse.type_info);
                            errors++;
                        }
                    }
                }

                if ( page->u.inuse.type_info & PGT_pinned )
                    adjust(page, 1);

                if ( page->u.inuse.type_info & PGT_validated )
                    adjust_l2_page(snapshot_mfn, 0);

                break;

            case PGT_l1_page_table:
                l1++;

                if ( noisy )
                {
                    if ( shadow_refcounts )
                    {
                        printk("found an L1 guest page mfn=%lx t=%" 
			       PRtype_info " c=%08x "
                               "while in shadow mode\n",
                               mfn, page->u.inuse.type_info, page->count_info);
                        errors++;
                    }

                    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
                    {
                        if ( (page->u.inuse.type_info & PGT_validated) !=
                             PGT_validated )
                        {
                            printk("Audit %d: L1 not validated mfn=%lx t=%"
				   PRtype_info "\n",
                                   d->domain_id, mfn, page->u.inuse.type_info);
                            errors++;
                        }
                    }
                }
                
                if ( page->u.inuse.type_info & PGT_pinned )
                    adjust(page, 1);

                if ( page->u.inuse.type_info & PGT_validated )
                    adjust_l1_page(snapshot_mfn);

                break;

            case PGT_gdt_page:
                ASSERT( !page_out_of_sync(page) );
                adjust(page, 1);
                break;

            case PGT_ldt_page:
                ASSERT( !page_out_of_sync(page) );
                adjust(page, 1);
                break;

            case PGT_writable_page:
                if ( shadow_refcounts )
                {
                    // In shadow mode, writable pages can get pinned by
                    // paravirtualized guests that think they are pinning
                    // their L1s and/or L2s.
                    //
                    if ( page->u.inuse.type_info & PGT_pinned )
                        adjust(page, 1);
                }
            }

            list_ent = page->list.next;
        }
    }

#ifdef __i386__
    if ( shadow_mode_external(d) )
        l2limit = L2_PAGETABLE_ENTRIES;
    else
        l2limit = DOMAIN_ENTRIES_PER_L2_PAGETABLE;
#else
    l2limit = 0; /* XXX x86/64 XXX */
#endif

    adjust_for_pgtbase();

    adjust_guest_pages();

    if ( shadow_enabled )
    {
        adjust_oos_list();
        adjust_shadow_tables();
    }

    adjust(virt_to_page(d->shared_info), 1);

    return errors;
}


#ifndef NDEBUG

void audit_pagelist(struct domain *d)
{
    struct list_head *list_ent;
    int xenpages, totpages;

    list_ent = d->xenpage_list.next;
    for ( xenpages = 0; (list_ent != &d->xenpage_list); xenpages++ )
    {
        list_ent = list_ent->next;
    }
    list_ent = d->page_list.next;
    for ( totpages = 0; (list_ent != &d->page_list); totpages++ )
    {
        list_ent = list_ent->next;
    }

    if ( xenpages != d->xenheap_pages ||
         totpages != d->tot_pages )
    {
        printk("ARGH! dom %d: xen=%d %d, pages=%d %d\n", d->domain_id,
               xenpages, d->xenheap_pages, 
               totpages, d->tot_pages );
    }
}

void _audit_domain(struct domain *d, int flags)
{
    int shadow_refcounts = !!shadow_mode_refcounts(d);

    void scan_for_pfn_in_mfn(struct domain *d, unsigned long xmfn,
                             unsigned long mfn)
    {
        struct pfn_info *page = &frame_table[mfn];
        unsigned long *pt = map_domain_page(mfn);
        int i;

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            if ( (pt[i] & _PAGE_PRESENT) && ((pt[i] >> PAGE_SHIFT) == xmfn) )
                printk("     found dom=%d mfn=%lx t=%" PRtype_info " c=%08x "
                       "pt[i=%x]=%lx\n",
                       d->domain_id, mfn, page->u.inuse.type_info,
                       page->count_info, i, pt[i]);
        }

        unmap_domain_page(pt);           
    }

    void scan_for_pfn_in_grant_table(struct domain *d, unsigned xmfn)
    {
        int i;
        active_grant_entry_t *act = d->grant_table->active;

        spin_lock(&d->grant_table->lock);

        for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
        {
            if ( act[i].pin && (act[i].frame == xmfn) )
            {
                printk("     found active grant table entry i=%d dom=%d pin=%d\n",
                       i, act[i].domid, act[i].pin);
            }
        }

        spin_unlock(&d->grant_table->lock);
    }

    void scan_for_pfn(struct domain *d, unsigned long xmfn)
    {
        scan_for_pfn_in_grant_table(d, xmfn);

        if ( !shadow_mode_enabled(d) )
        {
            struct list_head *list_ent = d->page_list.next;
            struct pfn_info *page;

            while ( list_ent != &d->page_list )
            {
                page = list_entry(list_ent, struct pfn_info, list);

                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                case PGT_l2_page_table:
                    scan_for_pfn_in_mfn(d, xmfn, page_to_pfn(page));
                    break;
                default:
                    break;
                }

                list_ent = page->list.next;
            }
        }
        else
        {
            struct shadow_status *a;
            int i;
            
            for ( i = 0; i < shadow_ht_buckets; i++ )
            {
                a = &d->arch.shadow_ht[i];
                while ( a && a->gpfn_and_flags )
                {
                    switch ( a->gpfn_and_flags & PGT_type_mask )
                    {
                    case PGT_l1_shadow:
                    case PGT_l2_shadow:
                    case PGT_hl2_shadow:
                        scan_for_pfn_in_mfn(d, xmfn, a->smfn);
                        break;
                    case PGT_snapshot:
                    case PGT_writable_pred:
                        break;
                    default:
                        BUG();
                        break;
                    }
                    a = a->next;
                }
            }
        }
    }

    void scan_for_pfn_remote(unsigned long xmfn)
    {
        struct domain *e;
        for_each_domain ( e )
            scan_for_pfn( e, xmfn );
    } 

    unsigned long mfn;
    struct list_head *list_ent;
    struct pfn_info *page;
    int errors = 0;

    if ( (d != current->domain) && shadow_mode_translate(d) )
    {
        printk("skipping audit domain of translated domain %d "
               "from other context\n",
               d->domain_id);
        return;
    }

    if ( d != current->domain )
        domain_pause(d);

    // Maybe we should just be using BIGLOCK?
    //
    if ( !(flags & AUDIT_SHADOW_ALREADY_LOCKED) )
        shadow_lock(d);

    spin_lock(&d->page_alloc_lock);

    audit_pagelist(d);

    /* PHASE 0 */

    list_ent = d->page_list.next;
    while ( list_ent != &d->page_list )
    {
        u32 page_type;

        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);
        page_type = page->u.inuse.type_info & PGT_type_mask;

        BUG_ON(page_get_owner(page) != d);

        if ( (page->u.inuse.type_info & PGT_count_mask) >
             (page->count_info & PGC_count_mask) )
        {
            printk("taf(%" PRtype_info ") > caf(%08x) mfn=%lx\n",
                   page->u.inuse.type_info, page->count_info, mfn);
            errors++;
        }

        if ( shadow_mode_refcounts(d) &&
             (page_type == PGT_writable_page) &&
             !(page->u.inuse.type_info & PGT_validated) )
        {
            printk("shadow mode writable page not validated mfn=%lx " 
		   "t=%" PRtype_info  " c=%08x\n",
                   mfn, page->u.inuse.type_info, page->count_info);
            errors++;
        }
 
#if 0   /* SYSV shared memory pages plus writeable files. */
        if ( page_type == PGT_writable_page && 
             (page->u.inuse.type_info & PGT_count_mask) > 1 )
        {
            printk("writeable page with type count >1: "
                   "mfn=%lx t=%" PRtype_info " c=%08x\n",
                  mfn,
                  page->u.inuse.type_info,
                  page->count_info );
            errors++;
            scan_for_pfn_remote(mfn);
        }
#endif

        if ( page_type == PGT_none && 
             (page->u.inuse.type_info & PGT_count_mask) > 0 )
        {
            printk("normal page with type count >0: mfn=%lx t=%" PRtype_info " c=%08x\n",
                  mfn,
                  page->u.inuse.type_info,
                  page->count_info );
            errors++;
        }

        if ( page_out_of_sync(page) )
        {
            if ( !page_is_page_table(page) )
            {
                printk("out of sync page mfn=%lx is not a page table\n", mfn);
                errors++;
            }
            unsigned long pfn = __mfn_to_gpfn(d, mfn);
            if ( !__shadow_status(d, pfn, PGT_snapshot) )
            {
                printk("out of sync page mfn=%lx doesn't have a snapshot\n",
                       mfn);
                errors++;
            }
            if ( shadow_refcounts
                 ? (page_type != PGT_writable_page)
                 : !(page_type && (page_type <= PGT_l4_page_table)) )
            {
                printk("out of sync page mfn=%lx has strange type "
                       "t=%" PRtype_info  " c=%08x\n",
                       mfn, page->u.inuse.type_info, page->count_info);
                errors++;
            }
        }

        /* Use tlbflush_timestamp to store original type_info. */
        page->tlbflush_timestamp = page->u.inuse.type_info;

        list_ent = page->list.next;
    }

    /* PHASE 1 */
    io_mappings = lowmem_mappings = 0;

    errors += audit_adjust_pgtables(d, -1, 1);

    if ( !(flags & AUDIT_QUIET) &&
         ((io_mappings > 0) || (lowmem_mappings > 0)) )
        printk("Audit %d: Found %d lowmem mappings and %d io mappings\n",
               d->domain_id, lowmem_mappings, io_mappings);

    /* PHASE 2 */

    list_ent = d->page_list.next;
    while ( list_ent != &d->page_list )
    {
        page = list_entry(list_ent, struct pfn_info, list);
        mfn = page_to_pfn(page);

        switch ( page->u.inuse.type_info & PGT_type_mask)
        {
        case PGT_l1_page_table:
        case PGT_l2_page_table:
        case PGT_l3_page_table:
        case PGT_l4_page_table:
            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                printk("Audit %d: type count!=0 t=%" PRtype_info " ot=%x c=%x mfn=%lx\n",
                       d->domain_id, page->u.inuse.type_info, 
                       page->tlbflush_timestamp,
                       page->count_info, mfn);
                errors++;
                scan_for_pfn_remote(mfn);
            }
            break;
        case PGT_none:
        case PGT_writable_page:
        case PGT_gdt_page:
        case PGT_ldt_page:
            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                printk("Audit %d: type count!=0 t=%" PRtype_info " ot=%x c=%x mfn=%lx\n",
                       d->domain_id, page->u.inuse.type_info, 
                       page->tlbflush_timestamp,
                       page->count_info, mfn);
                //errors++;
            }
            break;
        default:
            BUG(); // XXX fix me...
        }
        
        if ( (page->count_info & PGC_count_mask) != 1 )
        {
            printk("Audit %d: gen count!=1 (c=%x) t=%" PRtype_info " ot=%x mfn=%lx\n",
                   d->domain_id,
                   page->count_info,
                   page->u.inuse.type_info, 
                   page->tlbflush_timestamp, mfn );
            //errors++;
            scan_for_pfn_remote(mfn);
        }

        list_ent = page->list.next;
    }

    if ( shadow_mode_enabled(d) )
    {
        struct shadow_status *a;
        struct pfn_info *page;
        u32 page_type;
        int i;

        for ( i = 0; i < shadow_ht_buckets; i++ )
        {
            a = &d->arch.shadow_ht[i];
            while ( a && a->gpfn_and_flags )
            {
                page = pfn_to_page(a->smfn);
                page_type = a->gpfn_and_flags & PGT_type_mask;

                switch ( page_type ) {
                case PGT_l1_shadow:
                case PGT_l2_shadow:
                case PGT_hl2_shadow:
                case PGT_snapshot:
                    if ( ((page->u.inuse.type_info & PGT_type_mask) != page_type ) ||
                         (page->count_info != 0) )
                    {
                        printk("Audit %d: shadow page counts wrong "
                               "mfn=%lx t=%" PRtype_info " c=%08x\n",
                               d->domain_id, page_to_pfn(page),
                               page->u.inuse.type_info,
                               page->count_info);
                        printk("a->gpfn_and_flags=%p\n",
                               (void *)a->gpfn_and_flags);
                        errors++;
                    }
                    break;
                case PGT_writable_pred:
                    // XXX - nothing to check?
                    break;

                default:
                    BUG();
                    break;
                }

                a = a->next;
            }
        }
    }

    /* PHASE 3 */
    ctot = ttot = page_count = l1 = l2 = oos_count = 0;

    audit_adjust_pgtables(d, 1, 0);

#if 0
    // This covers our sins of trashing the tlbflush_timestamps...
    //
    local_flush_tlb();
#endif

    spin_unlock(&d->page_alloc_lock);

    if ( !(flags & AUDIT_QUIET) )
        printk("Audit dom%d Done. "
               "pages=%d oos=%d l1=%d l2=%d ctot=%d ttot=%d\n",
               d->domain_id, page_count, oos_count, l1, l2, ctot, ttot);

    if ( !(flags & AUDIT_SHADOW_ALREADY_LOCKED) )
        shadow_unlock(d);

    if ( d != current->domain )
        domain_unpause(d);

    if ( errors && !(flags & AUDIT_ERRORS_OK) )
        BUG();
}

void audit_domains(void)
{
    struct domain *d;
    for_each_domain ( d )
        audit_domain(d);
}

void audit_domains_key(unsigned char key)
{
    audit_domains();
}
#endif
