/******************************************************************************
 * memory.c
 * 
 * Copyright (c) 2002 K A Fraser
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
 * A description of the page table API:
 * 
 * Domains trap to process_page_updates with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val.
 * 
 * Reference counting of pages:
 * ----------------------------
 * Each page has two refcounts: tot_count and type_count.
 * 
 * TOT_COUNT is the obvious reference count. It counts all uses of a
 * physical page frame by a domain, including uses as a page directory,
 * a page table, or simple mappings via a PTE. This count prevents a
 * domain from releasing a frame back to the hypervisor's free pool when
 * it is still referencing it!
 * 
 * TYPE_COUNT is more subtle. A frame can be put to one of three
 * mutually-exclusive uses: it might be used as a page directory, or a
 * page table, or it may be mapped writeable by the domain [of course, a
 * frame may not be used in any of these three ways!].
 * So, type_count is a count of the number of times a frame is being 
 * referred to in its current incarnation. Therefore, a page can only
 * change its type when its type count is zero.
 * 
 * Pinning the page type:
 * ----------------------
 * The type of a page can be pinned/unpinned with the commands
 * PGEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
 * pinning is not reference counted, so it can't be nested).
 * This is useful to prevent a page's type count falling to zero, at which
 * point safety checks would need to be carried out next time the count
 * is increased again.
 * 
 * A further note on writeable page mappings:
 * ------------------------------------------
 * For simplicity, the count of writeable mappings for a page may not
 * correspond to reality. The 'writeable count' is incremented for every
 * PTE which maps the page with the _PAGE_RW flag set. However, for
 * write access to be possible the page directory entry must also have
 * its _PAGE_RW bit set. We do not check this as it complicates the 
 * reference counting considerably [consider the case of multiple
 * directory entries referencing a single page table, some with the RW
 * bit set, others not -- it starts getting a bit messy].
 * In normal use, this simplification shouldn't be a problem.
 * However, the logic can be added if required.
 * 
 * One more note on read-only page mappings:
 * -----------------------------------------
 * We want domains to be able to map pages for read-only access. The
 * main reason is that page tables and directories should be readable
 * by a domain, but it would not be safe for them to be writeable.
 * However, domains have free access to rings 1 & 2 of the Intel
 * privilege model. In terms of page protection, these are considered
 * to be part of 'supervisor mode'. The WP bit in CR0 controls whether
 * read-only restrictions are respected in supervisor mode -- if the 
 * bit is clear then any mapped page is writeable.
 * 
 * We get round this by always setting the WP bit and disallowing 
 * updates to it. This is very unlikely to cause a problem for guest
 * OS's, which will generally use the WP bit to simplify copy-on-write
 * implementation (in that case, OS wants a fault when it writes to
 * an application-supplied buffer).
 */


/*
 * THE FOLLOWING ARE ISSUES IF GUEST OPERATING SYSTEMS BECOME SMP-CAPABLE.
 * -----------------------------------------------------------------------
 * 
 * *********
 * UPDATE 15/7/02: Interface has changed --updates now specify physical
 * address of page-table entry, rather than specifying a virtual address,
 * so hypervisor no longer "walks" the page tables. Therefore the 
 * solution below cannot work. Another possibility is to add a new entry
 * to our "struct page" which says to which top-level page table each
 * lower-level page table or writeable mapping belongs. If it belongs to more
 * than one, we'd probably just flush on all processors running the domain.
 * *********
 * 
 * The problem involves creating new page tables which might be mapped 
 * writeable in the TLB of another processor. As an example, a domain might be 
 * running in two contexts (ie. on two processors) simultaneously, using the 
 * same top-level page table in both contexts. Now, if context 1 sends an 
 * update request [make page P read-only, add a reference to page P as a page 
 * table], that will succeed if there was only one writeable mapping of P. 
 * However, that mapping may persist in the TLB of context 2.
 * 
 * Solution: when installing a new page table, we must flush foreign TLBs as
 * necessary. Naive solution is to flush on any processor running our domain.
 * Cleverer solution is to flush on any processor running same top-level page
 * table, but this will sometimes fail (consider two different top-level page
 * tables which have a shared lower-level page table).
 * 
 * A better solution: when squashing a write reference, check how many times
 * that lowest-level table entry is referenced by ORing refcounts of tables
 * down the page-table hierarchy. If results is != 1, we require flushing all
 * instances of current domain if a new table is installed (because the
 * lowest-level entry may be referenced by many top-level page tables).
 * However, common case will be that result == 1, so we only need to flush
 * processors with the same top-level page table. Make choice at
 * table-installation time based on a `flush_level' flag, which is
 * FLUSH_NONE, FLUSH_PAGETABLE, FLUSH_DOMAIN. A flush reduces this
 * to FLUSH_NONE, while squashed write mappings can only promote up
 * to more aggressive flush types.
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/mm.h>
#include <xeno/sched.h>
#include <xeno/errno.h>
#include <xeno/perfc.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>

#if 0
#define MEM_LOG(_f, _a...) printk("DOM%d: (file=memory.c, line=%d) " _f "\n", current->domain, __LINE__, ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

/* Domain 0 is allowed to submit requests on behalf of others. */
#define DOMAIN_OKAY(_f) \
    ((((_f) & PG_domain_mask) == current->domain) || (current->domain == 0))

/* 'get' checks parameter for validity before inc'ing refcnt. */
static int get_l2_table(unsigned long page_nr);
static int get_l1_table(unsigned long page_nr);
static int get_page(unsigned long page_nr, int writeable);
static int inc_page_refcnt(unsigned long page_nr, unsigned int type);
/* 'put' does no checking because if refcnt not zero, entity must be valid. */
static void put_l2_table(unsigned long page_nr);
static void put_l1_table(unsigned long page_nr);
static void put_page(unsigned long page_nr, int writeable);
static int dec_page_refcnt(unsigned long page_nr, unsigned int type);

static int mod_l2_entry(l2_pgentry_t *, l2_pgentry_t);
static int mod_l1_entry(l1_pgentry_t *, l1_pgentry_t);

/* frame table size and its size in pages */
frame_table_t * frame_table;
unsigned long frame_table_size;
unsigned long max_page;

struct list_head free_list;
spinlock_t free_list_lock = SPIN_LOCK_UNLOCKED;
unsigned int free_pfns;

/* Used to defer flushing of memory structures. */
static struct {
    int flush_tlb;
    int refresh_ldt;
} deferred_op[NR_CPUS] __cacheline_aligned;

/*
 * init_frametable:
 * Initialise per-frame memory information. This goes directly after
 * MAX_MONITOR_ADDRESS in physical memory.
 */
void __init init_frametable(unsigned long nr_pages)
{
    struct pfn_info *pf;
    unsigned long page_index;
    unsigned long flags;

    memset(deferred_op, 0, sizeof(deferred_op));

    max_page = nr_pages;
    frame_table_size = nr_pages * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
    frame_table = (frame_table_t *)FRAMETABLE_VIRT_START;
    memset(frame_table, 0, frame_table_size);

    free_pfns = 0;

    /* Put all domain-allocatable memory on a free list. */
    spin_lock_irqsave(&free_list_lock, flags);
    INIT_LIST_HEAD(&free_list);
    for( page_index = (__pa(frame_table) + frame_table_size) >> PAGE_SHIFT; 
         page_index < nr_pages;
         page_index++ )      
    {
        pf = list_entry(&frame_table[page_index].list, struct pfn_info, list);
        list_add_tail(&pf->list, &free_list);
        free_pfns++;
    }
    spin_unlock_irqrestore(&free_list_lock, flags);
}


static void __invalidate_shadow_ldt(void)
{
    int i, cpu = smp_processor_id();
    unsigned long pfn;
    struct pfn_info *page;
    
    current->mm.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1_pgentry_to_pagenr(current->mm.perdomain_pt[i]);
        if ( pfn == 0 ) continue;
        current->mm.perdomain_pt[i] = mk_l1_pgentry(0);
        page = frame_table + pfn;
        ASSERT((page->flags & PG_type_mask) == PGT_ldt_page);
        ASSERT((page->flags & PG_domain_mask) == current->domain);
        ASSERT((page->type_count != 0) && (page->tot_count != 0));
        put_page_type(page);
        put_page_tot(page);                
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    deferred_op[cpu].flush_tlb   = 1;
    deferred_op[cpu].refresh_ldt = 1;
}


static inline void invalidate_shadow_ldt(void)
{
    if ( current->mm.shadow_ldt_mapcnt != 0 )
        __invalidate_shadow_ldt();
}


/* Map shadow page at offset @off. Returns 0 on success. */
int map_ldt_shadow_page(unsigned int off)
{
    struct task_struct *p = current;
    unsigned long addr = p->mm.ldt_base + (off << PAGE_SHIFT);
    unsigned long l1e, *ldt_page;
    struct pfn_info *page;
    int i, ret = -1;

    spin_lock(&p->page_lock);

    __get_user(l1e, (unsigned long *)(linear_pg_table+(addr>>PAGE_SHIFT)));
    if ( unlikely(!(l1e & _PAGE_PRESENT)) )
        goto out;

    page = frame_table + (l1e >> PAGE_SHIFT);
    if ( unlikely((page->flags & PG_type_mask) != PGT_ldt_page) )
    {
        if ( unlikely(page->type_count != 0) )
            goto out;

        /* Check all potential LDT entries in the page. */
        ldt_page = (unsigned long *)addr;
        for ( i = 0; i < 512; i++ )
            if ( unlikely(!check_descriptor(ldt_page[i*2], ldt_page[i*2+1])) )
                goto out;

        if ( unlikely(page->flags & PG_need_flush) )
        {
            perfc_incrc(need_flush_tlb_flush);
            __write_cr3_counted(pagetable_val(p->mm.pagetable));
            page->flags &= ~PG_need_flush;
        }

        page->flags &= ~PG_type_mask;
        page->flags |= PGT_ldt_page;
    }

    /* Success! */
    get_page_type(page);
    get_page_tot(page);
    p->mm.perdomain_pt[l1_table_offset(off)+16] = mk_l1_pgentry(l1e|_PAGE_RW);
    p->mm.shadow_ldt_mapcnt++;

    ret = 0;

 out:
    spin_unlock(&p->page_lock);
    return ret;
}


/* Return original refcnt, or -1 on error. */
static int inc_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;
    unsigned long flags;

    if ( unlikely(page_nr >= max_page) )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return -1;
    }
    page = frame_table + page_nr;
    flags = page->flags;
    if ( unlikely(!DOMAIN_OKAY(flags)) )
    {
        MEM_LOG("Bad page domain (%ld)", flags & PG_domain_mask);
        return -1;
    }
    if ( (flags & PG_type_mask) != type )
    {
        if ( page_type_count(page) != 0 )
        {
            MEM_LOG("Page %08lx bad type/count (%08lx!=%08x) cnt=%ld",
                    page_nr << PAGE_SHIFT,
                    flags & PG_type_mask, type, page_type_count(page));
            return -1;
        }

        if ( unlikely(flags & PG_need_flush) )
        {
            deferred_op[smp_processor_id()].flush_tlb = 1;
            page->flags &= ~PG_need_flush;
            perfc_incrc(need_flush_tlb_flush);
        }

        page->flags &= ~PG_type_mask;
        page->flags |= type;
    }

    get_page_tot(page);
    return get_page_type(page);
}


/* Return new refcnt, or -1 on error. */
static int dec_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;

    if ( unlikely(page_nr >= max_page) )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return -1;
    }
    page = frame_table + page_nr;
    if ( unlikely(!DOMAIN_OKAY(page->flags)) || 
         unlikely(((page->flags & PG_type_mask) != type)) ) 
    {
        MEM_LOG("Bad page type/domain (dom=%ld) (type %ld != expected %d)",
                page->flags & PG_domain_mask, page->flags & PG_type_mask,
                type);
        return -1;
    }
    ASSERT(page_type_count(page) != 0);
    put_page_tot(page);
    return put_page_type(page);
}


/* We allow a L2 table to map itself, to achieve a linear pagetable. */
/* NB. There's no need for a put_twisted_l2_table() function!! */
static int get_twisted_l2_table(unsigned long entry_pfn, l2_pgentry_t l2e)
{
    unsigned long l2v = l2_pgentry_val(l2e);

    /* Clearly the mapping must be read-only :-) */
    if ( (l2v & _PAGE_RW) )
    {
        MEM_LOG("Attempt to install twisted L2 entry with write permissions");
        return -1;
    }

    /* This is a sufficient final check. */
    if ( (l2v >> PAGE_SHIFT) != entry_pfn )
    {
        MEM_LOG("L2 tables may not map _other_ L2 tables!\n");
        return -1;
    }
    
    /* We don't bump the reference counts. */
    return 0;
}


static int get_l2_table(unsigned long page_nr)
{
    l2_pgentry_t *p_l2_entry, l2_entry;
    int i, ret=0;
   
    ret = inc_page_refcnt(page_nr, PGT_l2_page_table);
    if ( likely(ret != 0) ) return (ret < 0) ? ret : 0;
    
    /* NEW level-2 page table! Deal with every PDE in the table. */
    p_l2_entry = map_domain_mem(page_nr << PAGE_SHIFT);
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        l2_entry = *p_l2_entry++;
        if ( !(l2_pgentry_val(l2_entry) & _PAGE_PRESENT) ) continue;
        if ( (l2_pgentry_val(l2_entry) & (_PAGE_GLOBAL|_PAGE_PSE)) )
        {
            MEM_LOG("Bad L2 page type settings %04lx",
                    l2_pgentry_val(l2_entry) & (_PAGE_GLOBAL|_PAGE_PSE));
            ret = -1;
            goto out;
        }
        /* Assume we're mapping an L1 table, falling back to twisted L2. */
        ret = get_l1_table(l2_pgentry_to_pagenr(l2_entry));
        if ( ret ) ret = get_twisted_l2_table(page_nr, l2_entry);
        if ( ret ) goto out;
    }
    
    /* Now we simply slap in our high mapping. */
    memcpy(p_l2_entry, 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    p_l2_entry[(PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT) -
              DOMAIN_ENTRIES_PER_L2_PAGETABLE] =
        mk_l2_pgentry(__pa(current->mm.perdomain_pt) | __PAGE_HYPERVISOR);
    p_l2_entry[(LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT) -
              DOMAIN_ENTRIES_PER_L2_PAGETABLE] =
        mk_l2_pgentry((page_nr << PAGE_SHIFT) | __PAGE_HYPERVISOR);

 out:
    unmap_domain_mem(p_l2_entry);
    return ret;
}


static int get_l1_table(unsigned long page_nr)
{
    l1_pgentry_t *p_l1_entry, l1_entry;
    int i, ret;

    /* Update ref count for page pointed at by PDE. */
    ret = inc_page_refcnt(page_nr, PGT_l1_page_table);
    if ( likely(ret != 0) ) return (ret < 0) ? ret : 0;

    /* NEW level-1 page table! Deal with every PTE in the table. */
    p_l1_entry = map_domain_mem(page_nr << PAGE_SHIFT);
    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
    {
        l1_entry = *p_l1_entry++;
        if ( !(l1_pgentry_val(l1_entry) & _PAGE_PRESENT) ) continue;
        if ( (l1_pgentry_val(l1_entry) &
              (_PAGE_GLOBAL|_PAGE_PAT)) )
        {
            MEM_LOG("Bad L1 page type settings %04lx",
                    l1_pgentry_val(l1_entry) &
                    (_PAGE_GLOBAL|_PAGE_PAT));
            ret = -1;
            goto out;
        }
        ret = get_page(l1_pgentry_to_pagenr(l1_entry),
                       l1_pgentry_val(l1_entry) & _PAGE_RW);
        if ( ret ) goto out;
    }

 out:
    /* Make sure we unmap the right page! */
    unmap_domain_mem(p_l1_entry-1);
    return ret;
}


static int get_page(unsigned long page_nr, int writeable)
{
    struct pfn_info *page;
    unsigned long flags;

    /* Update ref count for page pointed at by PTE. */
    if ( unlikely(page_nr >= max_page) )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return(-1);
    }
    page = frame_table + page_nr;
    flags = page->flags;
    if ( unlikely(!DOMAIN_OKAY(flags)) )
    {
        MEM_LOG("Bad page domain (%ld)", flags & PG_domain_mask);
        return(-1);
    }

    if ( writeable )
    {
        if ( (flags & PG_type_mask) != PGT_writeable_page )
        {
            if ( page_type_count(page) != 0 )
            {
                MEM_LOG("Bad page type/count (%08lx!=%08x) cnt=%ld",
                        flags & PG_type_mask, PGT_writeable_page,
                        page_type_count(page));
                return(-1);
            }
            page->flags &= ~PG_type_mask;
            page->flags |= PGT_writeable_page;
        }
        page->flags |= PG_need_flush;
        get_page_type(page);
    }

    get_page_tot(page);
    
    return(0);
}


static void put_l2_table(unsigned long page_nr)
{
    l2_pgentry_t *p_l2_entry, l2_entry;
    int i;

    if ( likely(dec_page_refcnt(page_nr, PGT_l2_page_table)) ) return;

    /* We had last reference to level-2 page table. Free the PDEs. */
    p_l2_entry = map_domain_mem(page_nr << PAGE_SHIFT);
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        l2_entry = *p_l2_entry++;
        if ( (l2_pgentry_val(l2_entry) & _PAGE_PRESENT) )
            put_l1_table(l2_pgentry_to_pagenr(l2_entry));
    }

    unmap_domain_mem(p_l2_entry);
}


static void put_l1_table(unsigned long page_nr)
{
    l1_pgentry_t *p_l1_entry, l1_entry;
    int i;

    if ( likely(dec_page_refcnt(page_nr, PGT_l1_page_table)) ) return;

    /* We had last reference to level-1 page table. Free the PTEs. */
    p_l1_entry = map_domain_mem(page_nr << PAGE_SHIFT);
    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
    {
        l1_entry = *p_l1_entry++;
        if ( (l1_pgentry_val(l1_entry) & _PAGE_PRESENT) ) 
        {
            put_page(l1_pgentry_to_pagenr(l1_entry), 
                     l1_pgentry_val(l1_entry) & _PAGE_RW);
        }
    }

    /* Make sure we unmap the right page! */
    unmap_domain_mem(p_l1_entry-1);
}


static void put_page(unsigned long page_nr, int writeable)
{
    struct pfn_info *page;
    ASSERT(page_nr < max_page);
    page = frame_table + page_nr;
    ASSERT(DOMAIN_OKAY(page->flags));
    ASSERT((!writeable) || 
           ((page_type_count(page) != 0) && 
            ((page->flags & PG_type_mask) == PGT_writeable_page) &&
            ((page->flags & PG_need_flush) == PG_need_flush)));
    if ( writeable )
    {
        put_page_type(page);
    }
    else if ( unlikely(((page->flags & PG_type_mask) == PGT_ldt_page) &&
                       (page_type_count(page) != 0)) )
    {
        /* We expect this is rare so we just blow the entire shadow LDT. */
        invalidate_shadow_ldt();
    }
    put_page_tot(page);
}


static int mod_l2_entry(l2_pgentry_t *p_l2_entry, l2_pgentry_t new_l2_entry)
{
    l2_pgentry_t old_l2_entry = *p_l2_entry;

    if ( unlikely((((unsigned long)p_l2_entry & (PAGE_SIZE-1)) >> 2) >=
                  DOMAIN_ENTRIES_PER_L2_PAGETABLE) )
    {
        MEM_LOG("Illegal L2 update attempt in hypervisor area %p",
                p_l2_entry);
        goto fail;
    }

    if ( (l2_pgentry_val(new_l2_entry) & _PAGE_PRESENT) )
    {
        if ( unlikely((l2_pgentry_val(new_l2_entry) & 
                       (_PAGE_GLOBAL|_PAGE_PSE))) )
        {
            MEM_LOG("Bad L2 entry val %04lx",
                    l2_pgentry_val(new_l2_entry) & 
                    (_PAGE_GLOBAL|_PAGE_PSE));
            goto fail;
        }
        /* Differ in mapping (bits 12-31) or presence (bit 0)? */
        if ( ((l2_pgentry_val(old_l2_entry) ^ 
               l2_pgentry_val(new_l2_entry)) & 0xfffff001) != 0 )
        {
            if ( (l2_pgentry_val(old_l2_entry) & _PAGE_PRESENT) ) 
                put_l1_table(l2_pgentry_to_pagenr(old_l2_entry));
            
            /* Assume we're mapping an L1 table, falling back to twisted L2. */
            if ( unlikely(get_l1_table(l2_pgentry_to_pagenr(new_l2_entry))) )
            {
                /* NB. No need to sanity-check the VA: done already. */
                unsigned long l1e = l1_pgentry_val(
                    linear_pg_table[(unsigned long)p_l2_entry >> PAGE_SHIFT]);
                if ( get_twisted_l2_table(l1e >> PAGE_SHIFT, new_l2_entry) )
                    goto fail;
            }
        } 
    }
    else if ( (l2_pgentry_val(old_l2_entry) & _PAGE_PRESENT) )
    {
        put_l1_table(l2_pgentry_to_pagenr(old_l2_entry));
    }
    
    *p_l2_entry = new_l2_entry;
    return 0;

 fail:
    return -1;
}


static int mod_l1_entry(l1_pgentry_t *p_l1_entry, l1_pgentry_t new_l1_entry)
{
    l1_pgentry_t old_l1_entry = *p_l1_entry;

    if ( (l1_pgentry_val(new_l1_entry) & _PAGE_PRESENT) )
    {
        if ( unlikely((l1_pgentry_val(new_l1_entry) &
                       (_PAGE_GLOBAL|_PAGE_PAT))) ) 
        {
            MEM_LOG("Bad L1 entry val %04lx",
                    l1_pgentry_val(new_l1_entry) & 
                    (_PAGE_GLOBAL|_PAGE_PAT));
            goto fail;
        }
        /*
         * Differ in mapping (bits 12-31), writeable (bit 1), or
         * presence (bit 0)?
         */
        if ( ((l1_pgentry_val(old_l1_entry) ^
               l1_pgentry_val(new_l1_entry)) & 0xfffff003) != 0 )
        {
            if ( (l1_pgentry_val(old_l1_entry) & _PAGE_PRESENT) ) 
                put_page(l1_pgentry_to_pagenr(old_l1_entry),
                         l1_pgentry_val(old_l1_entry) & _PAGE_RW);

            if ( get_page(l1_pgentry_to_pagenr(new_l1_entry),
                          l1_pgentry_val(new_l1_entry) & _PAGE_RW) )
                goto fail;
        } 
    }
    else if ( (l1_pgentry_val(old_l1_entry) & _PAGE_PRESENT) )
    {
        put_page(l1_pgentry_to_pagenr(old_l1_entry),
                 l1_pgentry_val(old_l1_entry) & _PAGE_RW);
    }

    *p_l1_entry = new_l1_entry;
    return 0;

 fail:
    return -1;
}


static int do_extended_command(unsigned long ptr, unsigned long val)
{
    int err = 0, cpu = smp_processor_id();
    unsigned int cmd = val & PGEXT_CMD_MASK;
    unsigned long pfn = ptr >> PAGE_SHIFT;
    struct pfn_info *page = frame_table + pfn;

    /* 'ptr' must be in range except where it isn't a machine address. */
    if ( (pfn >= max_page) && (cmd != PGEXT_SET_LDT) )
        return 1;

    switch ( cmd )
    {
    case PGEXT_PIN_L1_TABLE:
        err = get_l1_table(pfn);
        goto mark_as_pinned;
    case PGEXT_PIN_L2_TABLE:
        err = get_l2_table(pfn);
    mark_as_pinned:
        if ( unlikely(err) )
        {
            MEM_LOG("Error while pinning pfn %08lx", pfn);
            break;
        }
        put_page_type(page);
        put_page_tot(page);
        if ( likely(!(page->type_count & REFCNT_PIN_BIT)) )
        {
            page->type_count |= REFCNT_PIN_BIT;
            page->tot_count  |= REFCNT_PIN_BIT;
        }
        else
        {
            MEM_LOG("Pfn %08lx already pinned", pfn);
            err = 1;
        }
        break;

    case PGEXT_UNPIN_TABLE:
        if ( !DOMAIN_OKAY(page->flags) )
        {
            err = 1;
            MEM_LOG("Page %08lx bad domain (dom=%ld)",
                    ptr, page->flags & PG_domain_mask);
        }
        else if ( (page->type_count & REFCNT_PIN_BIT) )
        {
            page->type_count &= ~REFCNT_PIN_BIT;
            page->tot_count  &= ~REFCNT_PIN_BIT;
            get_page_type(page);
            get_page_tot(page);
            ((page->flags & PG_type_mask) == PGT_l1_page_table) ?
                put_l1_table(pfn) : put_l2_table(pfn);
        }
        else
        {
            err = 1;
            MEM_LOG("Pfn %08lx not pinned", pfn);
        }
        break;

    case PGEXT_NEW_BASEPTR:
        err = get_l2_table(pfn);
        if ( !err )
        {
            put_l2_table(pagetable_val(current->mm.pagetable) >> PAGE_SHIFT);
            current->mm.pagetable = mk_pagetable(pfn << PAGE_SHIFT);
            invalidate_shadow_ldt();
            deferred_op[cpu].flush_tlb = 1;
        }
        else
        {
            MEM_LOG("Error while installing new baseptr %08lx %d", ptr, err);
        }
        break;
        
    case PGEXT_TLB_FLUSH:
        deferred_op[cpu].flush_tlb = 1;
        break;
    
    case PGEXT_INVLPG:
        __flush_tlb_one(val & ~PGEXT_CMD_MASK);
        break;

    case PGEXT_SET_LDT:
    {
        unsigned long ents = val >> PGEXT_CMD_SHIFT;
        if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
             (ents > 8192) ||
             ((ptr+ents*LDT_ENTRY_SIZE) < ptr) ||
             ((ptr+ents*LDT_ENTRY_SIZE) > PAGE_OFFSET) )
        {
            err = 1;
            MEM_LOG("Bad args to SET_LDT: ptr=%08lx, ents=%08lx", ptr, ents);
        }
        else if ( (current->mm.ldt_ents != ents) || 
                  (current->mm.ldt_base != ptr) )
        {
            if ( current->mm.ldt_ents != 0 )
                invalidate_shadow_ldt();
            current->mm.ldt_base = ptr;
            current->mm.ldt_ents = ents;
            load_LDT(current);
            deferred_op[cpu].refresh_ldt = (ents != 0);
        }
        break;
    }

    default:
        MEM_LOG("Invalid extended pt command 0x%08lx", val & PGEXT_CMD_MASK);
        err = 1;
        break;
    }

    return err;
}


int do_process_page_updates(page_update_request_t *ureqs, int count)
{
    page_update_request_t req;
    unsigned long flags, pfn, l1e;
    struct pfn_info *page;
    int err = 0, i, cpu = smp_processor_id();
    unsigned int cmd;
    unsigned long cr0 = 0;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(copy_from_user(&req, ureqs, sizeof(req)) != 0) )
        {
            if ( cr0 != 0 ) write_cr0(cr0);
            kill_domain_with_errmsg("Cannot read page update request");
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);
        pfn = req.ptr >> PAGE_SHIFT;

        err = 1;

        spin_lock_irq(&current->page_lock);

        /* Get the page-frame number that a non-extended command references. */
        if ( (cmd == PGREQ_NORMAL_UPDATE) || (cmd == PGREQ_UNCHECKED_UPDATE) )
        {
            if ( cr0 == 0 )
            {
                cr0 = read_cr0();
                write_cr0(cr0 & ~X86_CR0_WP);
            }
            /* Need to use 'get_user' since the VA's PGD may be absent. */
            __get_user(l1e, (unsigned long *)(linear_pg_table+pfn));
            /* Now check that the VA's PTE isn't absent. */
            if ( unlikely(!(l1e & _PAGE_PRESENT)) )
            {
                MEM_LOG("L1E n.p. at VA %08lx (%08lx)", req.ptr&~3, l1e);
                goto unlock;
            }
            /* Finally, get the underlying machine address. */
            pfn = l1e >> PAGE_SHIFT;
        }

        /* Least significant bits of 'ptr' demux the operation type. */
        switch ( cmd )
        {
            /*
             * PGREQ_NORMAL_UPDATE: Normal update to any level of page table.
             */
        case PGREQ_NORMAL_UPDATE:
            page  = frame_table + pfn;
            flags = page->flags;

            if ( likely(DOMAIN_OKAY(flags)) )
            {
                switch ( (flags & PG_type_mask) )
                {
                case PGT_l1_page_table: 
                    err = mod_l1_entry((l1_pgentry_t *)req.ptr, 
                                       mk_l1_pgentry(req.val)); 
                    break;
                case PGT_l2_page_table: 
                    err = mod_l2_entry((l2_pgentry_t *)req.ptr, 
                                       mk_l2_pgentry(req.val)); 
                    break;                    
                default:
                    if ( page->type_count == 0 )
                    {
                        *(unsigned long *)req.ptr = req.val;
                        err = 0;
                    }
                    else
                        MEM_LOG("Update to bad page %08lx", req.ptr);
                    break;
                }
            }
            else
            {
                MEM_LOG("Bad domain normal update (dom %d, pfn %ld)",
                        current->domain, pfn);
            }
            break;

        case PGREQ_UNCHECKED_UPDATE:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            if ( likely(IS_PRIV(current)) )
            {
                *(unsigned long *)req.ptr = req.val;
                err = 0;
            }
            else
            {
                MEM_LOG("Bad unchecked update attempt");
            }
            break;
            
        case PGREQ_MPT_UPDATE:
            page = frame_table + pfn;
            if ( unlikely(pfn >= max_page) )
            {
                MEM_LOG("Page out of range (%08lx > %08lx)", pfn, max_page);
            }
            else if ( likely(DOMAIN_OKAY(page->flags)) )
            {
                machine_to_phys_mapping[pfn] = req.val;
                err = 0;
            }
            else
            {
                MEM_LOG("Bad domain MPT update (dom %d, pfn %ld)",
                        current->domain, pfn);
            }            
            break;

            /*
             * PGREQ_EXTENDED_COMMAND: Extended command is specified
             * in the least-siginificant bits of the 'value' field.
             */
        case PGREQ_EXTENDED_COMMAND:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            err = do_extended_command(req.ptr, req.val);
            break;

        default:
            MEM_LOG("Invalid page update command %08lx", req.ptr);
            break;
        }

    unlock:
        spin_unlock_irq(&current->page_lock);

        if ( unlikely(err) )
        {
            if ( cr0 != 0 ) write_cr0(cr0);
            kill_domain_with_errmsg("Illegal page update request");
        }

        ureqs++;
    }

    if ( deferred_op[cpu].flush_tlb )
    {
        deferred_op[cpu].flush_tlb = 0;
        __write_cr3_counted(pagetable_val(current->mm.pagetable));
    }

    if ( deferred_op[cpu].refresh_ldt )
    {
        deferred_op[cpu].refresh_ldt = 0;
        (void)map_ldt_shadow_page(0);
    }

    if ( cr0 != 0 )
        write_cr0(cr0);

    return 0;
}


int do_update_va_mapping(unsigned long page_nr, 
                         unsigned long val, 
                         unsigned long flags)
{
    unsigned long _x, cr0 = 0;
    struct task_struct *p = current;
    int err = -EINVAL;

    if ( unlikely(page_nr >= (HYPERVISOR_VIRT_START >> PAGE_SHIFT)) )
        goto out;

    spin_lock_irq(&p->page_lock);

    /* Check that the VA's page-directory entry is present.. */
    if ( unlikely((err = __get_user(_x, (unsigned long *)
                                    (&linear_pg_table[page_nr]))) != 0) )
        goto unlock_and_out;

    /* If the VA's page-directory entry is read-only, we frob the WP bit. */
    if ( unlikely(__put_user(_x, (unsigned long *)
                             (&linear_pg_table[page_nr]))) )
    {
        cr0 = read_cr0();
        write_cr0(cr0 & ~X86_CR0_WP);        
    }

    if ( unlikely((err = mod_l1_entry(&linear_pg_table[page_nr], 
                                      mk_l1_pgentry(val))) != 0) )
    {
        spin_unlock_irq(&p->page_lock);
        kill_domain_with_errmsg("Illegal VA-mapping update request");
    }

    if ( unlikely(flags & UVMF_INVLPG) )
        __flush_tlb_one(page_nr << PAGE_SHIFT);

    if ( unlikely(flags & UVMF_FLUSH_TLB) )
        __write_cr3_counted(pagetable_val(p->mm.pagetable));

    if ( unlikely(cr0 != 0) )
        write_cr0(cr0);

 unlock_and_out:
    spin_unlock_irq(&p->page_lock);
 out:
    return err;
}
