/******************************************************************************
 * memory.c
 * 
 * Copyright (c) 2002-2004 K A Fraser
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
 * Domains trap to do_mmu_update with a list of update requests.
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
 * it still holds a reference to it.
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
 * MMUEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/interrupt.h>
#include <xen/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <asm/ldt.h>

#ifndef NDEBUG
#define MEM_LOG(_f, _a...)                             \
  printk("DOM%llu: (file=memory.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

static int alloc_l2_table(struct pfn_info *page);
static int alloc_l1_table(struct pfn_info *page);
static int get_page_from_pagenr(unsigned long page_nr, int check_level);
static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         unsigned int type,
                                         int check_level);
#define CHECK_STRICT 0 /* Subject domain must own the page                  */
#define CHECK_ANYDOM 1 /* Any domain may own the page (if subject is priv.) */

static void free_l2_table(struct pfn_info *page);
static void free_l1_table(struct pfn_info *page);

static int mod_l2_entry(l2_pgentry_t *, l2_pgentry_t, unsigned long);
static int mod_l1_entry(l1_pgentry_t *, l1_pgentry_t);

/* Frame table and its size in pages. */
struct pfn_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;

struct list_head free_list;
spinlock_t free_list_lock;
unsigned int free_pfns;

/* Used to defer flushing of memory structures. */
static struct {
#define DOP_FLUSH_TLB   (1<<0) /* Flush the TLB.                 */
#define DOP_RELOAD_LDT  (1<<1) /* Reload the LDT shadow mapping. */
    unsigned long       deferred_ops;
    unsigned long       cr0;
    domid_t             subject_id;
    struct task_struct *subject_p;
} percpu_info[NR_CPUS] __cacheline_aligned;


/*
 * init_frametable:
 * Initialise per-frame memory information. This goes directly after
 * MAX_MONITOR_ADDRESS in physical memory.
 */
void __init init_frametable(unsigned long nr_pages)
{
    memset(percpu_info, 0, sizeof(percpu_info));

    max_page = nr_pages;
    frame_table_size = nr_pages * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
    frame_table = (struct pfn_info *)FRAMETABLE_VIRT_START;
    memset(frame_table, 0, frame_table_size);

    spin_lock_init(&free_list_lock);
    INIT_LIST_HEAD(&free_list);    
    free_pfns = 0;

}

void add_to_domain_alloc_list(unsigned long ps, unsigned long pe)
{
    struct pfn_info *pf;
    unsigned long i;
    unsigned long flags;

    spin_lock_irqsave(&free_list_lock, flags);
    for ( i = ps >> PAGE_SHIFT; i < (pe >> PAGE_SHIFT); i++ )
    {
        pf = list_entry(&frame_table[i].list, struct pfn_info, list);
        list_add_tail(&pf->list, &free_list);
        free_pfns++;
    }
    spin_unlock_irqrestore(&free_list_lock, flags);
}

static void __invalidate_shadow_ldt(struct task_struct *p)
{
    int i;
    unsigned long pfn;
    struct pfn_info *page;
    
    p->mm.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1_pgentry_to_pagenr(p->mm.perdomain_pt[i]);
        if ( pfn == 0 ) continue;
        p->mm.perdomain_pt[i] = mk_l1_pgentry(0);
        page = frame_table + pfn;
        ASSERT_PAGE_IS_TYPE(page, PGT_ldt_page);
        ASSERT_PAGE_IS_DOMAIN(page, p);
        put_page_and_type(page);
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    percpu_info[p->processor].deferred_ops |= DOP_FLUSH_TLB | DOP_RELOAD_LDT;
}


static inline void invalidate_shadow_ldt(void)
{
    struct task_struct *p = current;
    if ( p->mm.shadow_ldt_mapcnt != 0 )
        __invalidate_shadow_ldt(p);
}


int alloc_segdesc_page(struct pfn_info *page)
{
    unsigned long *descs = map_domain_mem((page-frame_table) << PAGE_SHIFT);
    int i;

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(descs[i*2], descs[i*2+1])) )
            goto fail;

    unmap_domain_mem(descs);
    return 1;

 fail:
    unmap_domain_mem(descs);
    return 0;
}


/* Map shadow page at offset @off. */
int map_ldt_shadow_page(unsigned int off)
{
    struct task_struct *p = current;
    unsigned long l1e;

    if ( unlikely(in_interrupt()) )
        BUG();

    __get_user(l1e, (unsigned long *)&linear_pg_table[(p->mm.ldt_base >> 
                                                       PAGE_SHIFT) + off]);

    if ( unlikely(!(l1e & _PAGE_PRESENT)) ||
         unlikely(!get_page_and_type(&frame_table[l1e >> PAGE_SHIFT], 
                                     p, PGT_ldt_page)) )
        return 0;

    p->mm.perdomain_pt[off + 16] = mk_l1_pgentry(l1e | _PAGE_RW);
    p->mm.shadow_ldt_mapcnt++;

    return 1;
}


static int get_page_from_pagenr(unsigned long page_nr, int check_level)
{
    struct task_struct *p = current;
    struct pfn_info *page = &frame_table[page_nr];
    unsigned long y, x, nx;

    if ( unlikely(!pfn_is_ram(page_nr)) )
    {
        MEM_LOG("Pfn %08lx is not RAM", page_nr);
        return 0;
    }

    /* Find the correct subject domain. */
    if ( unlikely(percpu_info[p->processor].subject_p != NULL) )
        p = percpu_info[p->processor].subject_p;

    /* Demote ANYDOM to STRICT if subject domain is not privileged. */
    if ( check_level == CHECK_ANYDOM && !IS_PRIV(p) )
        check_level = CHECK_STRICT;

    switch ( check_level )
    {
    case CHECK_STRICT:
        if ( unlikely(!get_page(page, p)) )
        {
            MEM_LOG("Could not get page ref for pfn %08lx\n", page_nr);
            return 0;
        }
        break;
    case CHECK_ANYDOM:
        y = page->count_and_flags;
        do {
            x  = y;
            nx = x + 1;
            if ( unlikely((x & PGC_count_mask) == 0) ||
                 unlikely((nx & PGC_count_mask) == 0) )
            {
                MEM_LOG("Could not get page ref for pfn %08lx\n", page_nr);
                return 0;
            }
        }
        while ( unlikely((y = cmpxchg(&page->count_and_flags, x, nx)) != x) );
        break;
    }

    return 1;
}


static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         unsigned int type,
                                         int check_level)
{
    struct pfn_info *page = &frame_table[page_nr];

    if ( unlikely(!get_page_from_pagenr(page_nr, check_level)) )
        return 0;

    if ( unlikely(!get_page_type(page, type)) )
    {
        MEM_LOG("Bad page type for pfn %08lx (%08lx)", 
                page_nr, page->type_and_flags);
        put_page(page);
        return 0;
    }

    return 1;
}


/*
 * We allow an L2 tables to map each other (a.k.a. linear page tables). It
 * needs some special care with reference counst and access permissions:
 *  1. The mapping entry must be read-only, or the guest may get write access
 *     to its own PTEs.
 *  2. We must only bump the reference counts for an *already validated*
 *     L2 table, or we can end up in a deadlock in get_page_type() by waiting
 *     on a validation that is required to complete that validation.
 *  3. We only need to increment the reference counts for the mapped page
 *     frame if it is mapped by a different L2 table. This is sufficient and
 *     also necessary to allow validation of an L2 table mapping itself.
 */
static int get_linear_pagetable(l2_pgentry_t l2e, unsigned long pfn)
{
    unsigned long x, y;
    struct pfn_info *page;

    if ( (l2_pgentry_val(l2e) & _PAGE_RW) )
    {
        MEM_LOG("Attempt to create linear p.t. with write perms");
        return 0;
    }

    if ( (l2_pgentry_val(l2e) >> PAGE_SHIFT) != pfn )
    {
        /* Make sure the mapped frame belongs to the correct domain. */
        if ( unlikely(!get_page_from_pagenr(l2_pgentry_to_pagenr(l2e), 
                                            CHECK_STRICT)) )
            return 0;

        /*
         * Make sure that the mapped frame is an already-validated L2 table. 
         * If so, atomically increment the count (checking for overflow).
         */
        page = &frame_table[l2_pgentry_to_pagenr(l2e)];
        y = page->type_and_flags;
        do {
            x = y;
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||
                 unlikely((x & (PGT_type_mask|PGT_validated)) != 
                          (PGT_l2_page_table|PGT_validated)) )
            {
                put_page(page);
                return 0;
            }
        }
        while ( (y = cmpxchg(&page->type_and_flags, x, x + 1)) != x );
    }

    return 1;
}


static int get_page_from_l1e(l1_pgentry_t l1e)
{
    unsigned long l1v = l1_pgentry_val(l1e);
    unsigned long pfn = l1_pgentry_to_pagenr(l1e);

    if ( !(l1v & _PAGE_PRESENT) )
        return 1;

    if ( unlikely(l1v & (_PAGE_GLOBAL|_PAGE_PAT)) )
    {
        MEM_LOG("Bad L1 type settings %04lx", l1v & (_PAGE_GLOBAL|_PAGE_PAT));
        return 0;
    }

    if ( unlikely(!pfn_is_ram(pfn)) )
    {
        if ( IS_PRIV(current) )
            return 1;
        MEM_LOG("Non-privileged attempt to map I/O space %08lx", pfn);
        return 0;
    }

    if ( l1v & _PAGE_RW )
    {
        if ( unlikely(!get_page_and_type_from_pagenr(
            pfn, PGT_writeable_page, CHECK_ANYDOM)) )
            return 0;
        set_bit(_PGC_tlb_flush_on_type_change, 
                &frame_table[pfn].count_and_flags);
        return 1;
    }

    return get_page_from_pagenr(pfn, CHECK_ANYDOM);
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
static int get_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( !(l2_pgentry_val(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2_pgentry_val(l2e) & (_PAGE_GLOBAL|_PAGE_PSE))) )
    {
        MEM_LOG("Bad L2 page type settings %04lx",
                l2_pgentry_val(l2e) & (_PAGE_GLOBAL|_PAGE_PSE));
        return 0;
    }

    if ( unlikely(!get_page_and_type_from_pagenr(
        l2_pgentry_to_pagenr(l2e), PGT_l1_page_table, CHECK_STRICT)) )
        return get_linear_pagetable(l2e, pfn);

    return 1;
}


static void put_page_from_l1e(l1_pgentry_t l1e)
{
    struct pfn_info *page = &frame_table[l1_pgentry_to_pagenr(l1e)];
    unsigned long    l1v  = l1_pgentry_val(l1e);

    if ( !(l1v & _PAGE_PRESENT) || !pfn_is_ram(l1v >> PAGE_SHIFT) )
        return;

    if ( l1v & _PAGE_RW )
    {
        put_page_and_type(page);
    }
    else
    {
        /* We expect this is rare so we blow the entire shadow LDT. */
        if ( unlikely(((page->type_and_flags & PGT_type_mask) == 
                       PGT_ldt_page)) &&
             unlikely(((page->type_and_flags & PGT_count_mask) != 0)) )
            invalidate_shadow_ldt();
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static void put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( (l2_pgentry_val(l2e) & _PAGE_PRESENT) && 
         ((l2_pgentry_val(l2e) >> PAGE_SHIFT) != pfn) )
        put_page_and_type(&frame_table[l2_pgentry_to_pagenr(l2e)]);
}


static int alloc_l2_table(struct pfn_info *page)
{
    unsigned long page_nr = page - frame_table;
    l2_pgentry_t *pl2e;
    int i;
   
    pl2e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        if ( unlikely(!get_page_from_l2e(pl2e[i], page_nr)) )
            goto fail;
    
    /* Now we add our private high mappings. */
    memcpy(&pl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    pl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((page_nr << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    pl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(page->u.domain->mm.perdomain_pt) | 
                      __PAGE_HYPERVISOR);

    unmap_domain_mem(pl2e);
    return 1;

 fail:
    while ( i-- > 0 )
        put_page_from_l2e(pl2e[i], page_nr);

    unmap_domain_mem(pl2e);
    return 0;
}


static int alloc_l1_table(struct pfn_info *page)
{
    unsigned long page_nr = page - frame_table;
    l1_pgentry_t *pl1e;
    int i;

    pl1e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        if ( unlikely(!get_page_from_l1e(pl1e[i])) )
            goto fail;

    unmap_domain_mem(pl1e);
    return 1;

 fail:
    while ( i-- > 0 )
        put_page_from_l1e(pl1e[i]);

    unmap_domain_mem(pl1e);
    return 0;
}


static void free_l2_table(struct pfn_info *page)
{
    unsigned long page_nr = page - frame_table;
    l2_pgentry_t *pl2e;
    int i;

    pl2e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        put_page_from_l2e(pl2e[i], page_nr);

    unmap_domain_mem(pl2e);
}


static void free_l1_table(struct pfn_info *page)
{
    unsigned long page_nr = page - frame_table;
    l1_pgentry_t *pl1e;
    int i;

    pl1e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        put_page_from_l1e(pl1e[i]);

    unmap_domain_mem(pl1e);
}


static inline int update_l2e(l2_pgentry_t *pl2e, 
                             l2_pgentry_t  ol2e, 
                             l2_pgentry_t  nl2e)
{
    unsigned long o = cmpxchg((unsigned long *)pl2e, 
                              l2_pgentry_val(ol2e), 
                              l2_pgentry_val(nl2e));
    if ( o != l2_pgentry_val(ol2e) )
        MEM_LOG("Failed to update %08lx -> %08lx: saw %08lx\n",
                l2_pgentry_val(ol2e), l2_pgentry_val(nl2e), o);
    return (o == l2_pgentry_val(ol2e));
}


/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, 
                        l2_pgentry_t nl2e, 
                        unsigned long pfn)
{
    l2_pgentry_t ol2e;
    unsigned long _ol2e;

    if ( unlikely((((unsigned long)pl2e & (PAGE_SIZE-1)) >> 2) >=
                  DOMAIN_ENTRIES_PER_L2_PAGETABLE) )
    {
        MEM_LOG("Illegal L2 update attempt in hypervisor area %p", pl2e);
        return 0;
    }

    if ( unlikely(__get_user(_ol2e, (unsigned long *)pl2e) != 0) )
        return 0;
    ol2e = mk_l2_pgentry(_ol2e);

    if ( l2_pgentry_val(nl2e) & _PAGE_PRESENT )
    {
        /* Differ in mapping (bits 12-31) or presence (bit 0)? */
        if ( ((l2_pgentry_val(ol2e) ^ l2_pgentry_val(nl2e)) & ~0xffe) == 0 )
            return update_l2e(pl2e, ol2e, nl2e);

        if ( unlikely(!get_page_from_l2e(nl2e, pfn)) )
            return 0;
        
        if ( unlikely(!update_l2e(pl2e, ol2e, nl2e)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
        
        put_page_from_l2e(ol2e, pfn);
        return 1;
    }

    if ( unlikely(!update_l2e(pl2e, ol2e, nl2e)) )
        return 0;

    put_page_from_l2e(ol2e, pfn);
    return 1;
}


static inline int update_l1e(l1_pgentry_t *pl1e, 
                             l1_pgentry_t  ol1e, 
                             l1_pgentry_t  nl1e)
{
    unsigned long o = l1_pgentry_val(ol1e);
    unsigned long n = l1_pgentry_val(nl1e);

    if ( unlikely(cmpxchg_user(pl1e, o, n) != 0) ||
         unlikely(o != l1_pgentry_val(ol1e)) )
    {
        MEM_LOG("Failed to update %08lx -> %08lx: saw %08lx\n",
                l1_pgentry_val(ol1e), l1_pgentry_val(nl1e), o);
        return 0;
    }

    return 1;
}


/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e)
{
    l1_pgentry_t ol1e;
    unsigned long _ol1e;

    if ( unlikely(__get_user(_ol1e, (unsigned long *)pl1e) != 0) )
    {
        MEM_LOG("Bad get_user\n");
        return 0;
    }
    
    ol1e = mk_l1_pgentry(_ol1e);

    if ( l1_pgentry_val(nl1e) & _PAGE_PRESENT )
    {
        /* Differ in mapping (bits 12-31), r/w (bit 1), or presence (bit 0)? */
        if ( ((l1_pgentry_val(ol1e) ^ l1_pgentry_val(nl1e)) & ~0xffc) == 0 )
            return update_l1e(pl1e, ol1e, nl1e);

        if ( unlikely(!get_page_from_l1e(nl1e)) )
            return 0;
        
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        {
            put_page_from_l1e(nl1e);
            return 0;
        }
        
        put_page_from_l1e(ol1e);
        return 1;
    }

    if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        return 0;
    
    put_page_from_l1e(ol1e);
    return 1;
}


int alloc_page_type(struct pfn_info *page, unsigned int type)
{
    if ( unlikely(test_and_clear_bit(_PGC_tlb_flush_on_type_change, 
                                     &page->count_and_flags)) )
    {
        struct task_struct *p = page->u.domain;
        mb(); /* Check zombie status before using domain ptr. */
        /*
         * NB. 'p' may no longer be valid by time we dereference it, so
         * p->processor might be garbage. We clamp it, just in case.
         */
        if ( likely(!test_bit(_PGC_zombie, &page->count_and_flags)) )
        {
            unsigned int cpu = p->processor;
            if ( likely(cpu <= smp_num_cpus) &&
                 unlikely(NEED_FLUSH(tlbflush_time[cpu],
                                     page->tlbflush_timestamp)) )
            {
                perfc_incr(need_flush_tlb_flush);
                flush_tlb_cpu(cpu);
            }
        }
    }

    switch ( type )
    {
    case PGT_l1_page_table:
        return alloc_l1_table(page);
    case PGT_l2_page_table:
        return alloc_l2_table(page);
    case PGT_gdt_page:
    case PGT_ldt_page:
        return alloc_segdesc_page(page);
    default:
        BUG();
    }

    return 0;
}


void free_page_type(struct pfn_info *page, unsigned int type)
{
    switch ( type )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        if ( unlikely(current->mm.shadow_mode) && 
             (get_shadow_status(&current->mm, 
                                page-frame_table) & PSH_shadowed) )
        {
            /*
             * Using 'current->mm' is safe and correct because page-table pages 
             * are not shared across domains. Updates to such pages' types are 
             * thus only done within the context of the owning domain. The one 
             * exception is when destroying a domain; however, this is not a 
             * problem as the currently-executing domain will not have this 
             * MFN shadowed, and at domain end-of-day we explicitly unshadow 
             * everything so that nothing will get left lying around.
             */
            unshadow_table( page-frame_table, type );
            put_shadow_status(&current->mm);
        }
        break;

    case PGT_l2_page_table:
        free_l2_table(page);
        if ( unlikely(current->mm.shadow_mode) && 
             (get_shadow_status(&current->mm, 
                                page-frame_table) & PSH_shadowed) )
        {
            unshadow_table( page-frame_table, type );
            put_shadow_status(&current->mm);
        }
        break;

    default:
        BUG();
    }
}


static int do_extended_command(unsigned long ptr, unsigned long val)
{
    int okay = 1, cpu = smp_processor_id();
    unsigned int cmd = val & MMUEXT_CMD_MASK;
    unsigned long pfn = ptr >> PAGE_SHIFT;
    unsigned long old_base_pfn;
    struct pfn_info *page = &frame_table[pfn];

    switch ( cmd )
    {
    case MMUEXT_PIN_L1_TABLE:
    case MMUEXT_PIN_L2_TABLE:
        okay = get_page_and_type_from_pagenr(
            pfn, (cmd == MMUEXT_PIN_L2_TABLE) ? PGT_l2_page_table : 
            PGT_l1_page_table,
            CHECK_STRICT);
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while pinning pfn %08lx", pfn);
            put_page(page);
            break;
        }

        if ( unlikely(test_and_set_bit(_PGC_guest_pinned, 
                                       &page->count_and_flags)) )
        {
            MEM_LOG("Pfn %08lx already pinned", pfn);
            put_page_and_type(page);
            okay = 0;
            break;
        }

        break;

    case MMUEXT_UNPIN_TABLE:
        if ( unlikely(!(okay = get_page_from_pagenr(pfn, CHECK_STRICT))) )
        {
            MEM_LOG("Page %08lx bad domain (dom=%p)",
                    ptr, page->u.domain);
        }
        else if ( likely(test_and_clear_bit(_PGC_guest_pinned, 
                                            &page->count_and_flags)) )
        {
            put_page_and_type(page);
            put_page(page);
        }
        else
        {
            okay = 0;
            put_page(page);
            MEM_LOG("Pfn %08lx not pinned", pfn);
        }
        break;

    case MMUEXT_NEW_BASEPTR:
        okay = get_page_and_type_from_pagenr(pfn, PGT_l2_page_table, 
                                             CHECK_STRICT);
        if ( likely(okay) )
        {
            invalidate_shadow_ldt();

            percpu_info[cpu].deferred_ops &= ~DOP_FLUSH_TLB;
            old_base_pfn = pagetable_val(current->mm.pagetable) >> PAGE_SHIFT;
            current->mm.pagetable = mk_pagetable(pfn << PAGE_SHIFT);

            shadow_mk_pagetable(&current->mm);

            write_ptbase(&current->mm);

            put_page_and_type(&frame_table[old_base_pfn]);    
        }
        else
        {
            MEM_LOG("Error while installing new baseptr %08lx", ptr);
        }
        break;
        
    case MMUEXT_TLB_FLUSH:
        percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;
        break;
    
    case MMUEXT_INVLPG:
        __flush_tlb_one(val & ~MMUEXT_CMD_MASK);
        break;

    case MMUEXT_SET_LDT:
    {
        unsigned long ents = val >> MMUEXT_CMD_SHIFT;
        if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
             (ents > 8192) ||
             ((ptr+ents*LDT_ENTRY_SIZE) < ptr) ||
             ((ptr+ents*LDT_ENTRY_SIZE) > PAGE_OFFSET) )
        {
            okay = 0;
            MEM_LOG("Bad args to SET_LDT: ptr=%08lx, ents=%08lx", ptr, ents);
        }
        else if ( (current->mm.ldt_ents != ents) || 
                  (current->mm.ldt_base != ptr) )
        {
            invalidate_shadow_ldt();
            current->mm.ldt_base = ptr;
            current->mm.ldt_ents = ents;
            load_LDT(current);
            percpu_info[cpu].deferred_ops &= ~DOP_RELOAD_LDT;
            if ( ents != 0 )
                percpu_info[cpu].deferred_ops |= DOP_RELOAD_LDT;
        }
        break;
    }

    case MMUEXT_SET_SUBJECTDOM_L:
        percpu_info[cpu].subject_id = (domid_t)((ptr&~0xFFFF)|(val>>16));
        break;

    case MMUEXT_SET_SUBJECTDOM_H:
        percpu_info[cpu].subject_id |= (domid_t)((ptr&~0xFFFF)|(val>>16))<<32;
        if ( !IS_PRIV(current) )
        {
            MEM_LOG("Dom %llu has no privilege to set subject domain",
                    current->domain);
            okay = 0;
        }
        else
        {
            if ( percpu_info[cpu].subject_p != NULL )
                put_task_struct(percpu_info[cpu].subject_p);
            percpu_info[cpu].subject_p = find_domain_by_id(
                percpu_info[cpu].subject_id);
            if ( percpu_info[cpu].subject_p == NULL )
            {
                MEM_LOG("Unknown domain '%llu'", percpu_info[cpu].subject_id);
                okay = 0;
            }
        }
        break;

    default:
        MEM_LOG("Invalid extended pt command 0x%08lx", val & MMUEXT_CMD_MASK);
        okay = 0;
        break;
    }

    return okay;
}


int do_mmu_update(mmu_update_t *ureqs, int count)
{
    mmu_update_t req;
    unsigned long va = 0, deferred_ops, pfn, prev_pfn = 0;
    struct pfn_info *page;
    int rc = 0, okay = 1, i, cpu = smp_processor_id();
    unsigned int cmd;
    unsigned long prev_spfn = 0;
    l1_pgentry_t *prev_spl1e = 0;

    perfc_incrc(calls_to_mmu_update); 
    perfc_addc(num_page_updates, count);

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(copy_from_user(&req, ureqs, sizeof(req)) != 0) )
        {
            MEM_LOG("Bad copy_from_user");
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);
        pfn = req.ptr >> PAGE_SHIFT;

        okay = 0;

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             */
        case MMU_NORMAL_PT_UPDATE:
            if ( unlikely(!get_page_from_pagenr(pfn, CHECK_STRICT)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            if ( likely(prev_pfn == pfn) )
            {
                va = (va & PAGE_MASK) | (req.ptr & ~PAGE_MASK);
            }
            else
            {
                if ( prev_pfn != 0 )
                    unmap_domain_mem((void *)va);
                va = (unsigned long)map_domain_mem(req.ptr);
                prev_pfn = pfn;
            }

            page = &frame_table[pfn];
            switch ( (page->type_and_flags & PGT_type_mask) )
            {
            case PGT_l1_page_table: 
                if ( likely(get_page_type(page, PGT_l1_page_table)) )
                {
                    okay = mod_l1_entry((l1_pgentry_t *)va, 
                                        mk_l1_pgentry(req.val)); 

                    if ( okay && unlikely(current->mm.shadow_mode) &&
                         (get_shadow_status(&current->mm, page-frame_table) &
                          PSH_shadowed) )
                    {
                        shadow_l1_normal_pt_update( req.ptr, req.val, 
                                                    &prev_spfn, &prev_spl1e );
                        put_shadow_status(&current->mm);
                    }

                    put_page_type(page);
                }
                break;
            case PGT_l2_page_table:
                if ( likely(get_page_type(page, PGT_l2_page_table)) )
                {
                    okay = mod_l2_entry((l2_pgentry_t *)va, 
                                        mk_l2_pgentry(req.val),
                                        pfn); 

                    if ( okay && unlikely(current->mm.shadow_mode) &&
                         (get_shadow_status(&current->mm, page-frame_table) & 
                          PSH_shadowed) )
                    {
                        shadow_l2_normal_pt_update( req.ptr, req.val );
                        put_shadow_status(&current->mm);
                    }

                    put_page_type(page);
                }
                break;
            default:
                if ( likely(get_page_type(page, PGT_writeable_page)) )
                {
                    *(unsigned long *)va = req.val;
                    okay = 1;
                    put_page_type(page);
                }
                break;
            }

            put_page(page);

            break;

        case MMU_MACHPHYS_UPDATE:
            if ( unlikely(!get_page_from_pagenr(pfn, CHECK_STRICT)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            machine_to_phys_mapping[pfn] = req.val;
            okay = 1;
            put_page(&frame_table[pfn]);
            break;

            /*
             * MMU_EXTENDED_COMMAND: Extended command is specified
             * in the least-siginificant bits of the 'value' field.
             */
        case MMU_EXTENDED_COMMAND:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            okay = do_extended_command(req.ptr, req.val);
            break;

        default:
            MEM_LOG("Invalid page update command %08lx", req.ptr);
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        ureqs++;
    }

    if ( prev_pfn != 0 )
        unmap_domain_mem((void *)va);

    if( prev_spl1e != 0 ) 
        unmap_domain_mem((void *)prev_spl1e);

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( deferred_ops & DOP_FLUSH_TLB )
    {
        write_ptbase(&current->mm);
    }

    if ( deferred_ops & DOP_RELOAD_LDT )
        (void)map_ldt_shadow_page(0);

    if ( unlikely(percpu_info[cpu].subject_p != NULL) )
    {
        put_task_struct(percpu_info[cpu].subject_p);
        percpu_info[cpu].subject_p = NULL;
    }

    return rc;
}


int do_update_va_mapping(unsigned long page_nr, 
                         unsigned long val, 
                         unsigned long flags)
{
    struct task_struct *p = current;
    int err = 0;
    unsigned int cpu = p->processor;
    unsigned long deferred_ops;

    perfc_incrc(calls_to_update_va);

    if ( unlikely(page_nr >= (HYPERVISOR_VIRT_START >> PAGE_SHIFT)) )
        return -EINVAL;

    /*
     * XXX When we make this support 4MB superpages we should also deal with 
     * the case of updating L2 entries.
     */

    if ( unlikely(!mod_l1_entry(&linear_pg_table[page_nr], 
                                mk_l1_pgentry(val))) )
        err = -EINVAL;

    if ( unlikely(p->mm.shadow_mode) )
    {
        unsigned long sval;

        l1pte_no_fault( &current->mm, &val, &sval );

        if ( unlikely(__put_user(sval, ((unsigned long *)(
            &shadow_linear_pg_table[page_nr])))) )
        {
            /*
             * Since L2's are guranteed RW, failure indicates the page was not 
             * shadowed, so ignore.
             */
            perfc_incrc(shadow_update_va_fail);
        }

        /*
         * If we're in log-dirty mode then we need to note that we've updated
         * the PTE in the PT-holding page. We need the machine frame number
         * for this.
         */
        if ( p->mm.shadow_mode == SHM_logdirty )
            mark_dirty( &current->mm, va_to_l1mfn(page_nr<<PAGE_SHIFT) );  
  
        check_pagetable( p, p->mm.pagetable, "va" ); /* debug */
    }

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( unlikely(deferred_ops & DOP_FLUSH_TLB) || 
         unlikely(flags & UVMF_FLUSH_TLB) )
    {
        write_ptbase(&p->mm);
    }
    else if ( unlikely(flags & UVMF_INVLPG) )
        __flush_tlb_one(page_nr << PAGE_SHIFT);

    if ( unlikely(deferred_ops & DOP_RELOAD_LDT) )
        (void)map_ldt_shadow_page(0);
    
    return err;
}


#ifndef NDEBUG
/*
 * below are various memory debugging functions: 
 * __audit_page():    prints out all the ptes a pages is listed in
 * audit_page():      in addition maintains a history of audited pages
 * reaudit_pages():   re-audit previously audited pages
 * audit_all_pages(): check the ref-count for all leaf pages
 *                    also checks for zombie pages
 * 
 * reaudit_page() and audit_all_pages() are designed to be
 * keyhandler functions so that they can be easily invoked from the console.
 */


/*
 * prints out all the pt's a page is listed in
 */
void __audit_page(unsigned long pfn) {
    unsigned long     i, j;
    struct pfn_info  *page;
    unsigned long     page_addr;
    l1_pgentry_t     *pl1e, l1e;
    
    page = &frame_table[pfn];
    page_addr = pfn << PAGE_SHIFT;

    printk("audit page: pfn=%lx info: cf=%lx tf=%lx ts=%lx dom=%lx\n", pfn,
           page->count_and_flags, page->type_and_flags,
           page->tlbflush_timestamp, (unsigned long)page->u.domain);

    /* walk the frame table */
    for ( i = 0; i < max_page; i++ )
    {
        if ( (frame_table[i].count_and_flags & PGC_count_mask) == 0 )
            continue;
        if ( (frame_table[i].count_and_flags & PGC_zombie) != 0 )
            continue;

        /* check if entry is a page table (L1 page table) and in use */
        if ( ((frame_table[i].type_and_flags & PGT_type_mask) ==
              PGT_l1_page_table) &&
             ((frame_table[i].type_and_flags & PGT_count_mask) != 0) )
        {
            pl1e = map_domain_mem(i << PAGE_SHIFT);

            /* scan page table for page to audit */
            for ( j=0; j < ENTRIES_PER_L1_PAGETABLE; j++  )
            {
                l1e = pl1e[j];
                if ( l1_pgentry_empty(l1e) )
                    continue;
                if ( l1_pgentry_to_pagenr(l1e) == pfn )
                {
                    printk("  pte_pfn=%06lx cf=%08lx tf=%08lx dom=%08lx\n", 
                           i, frame_table[i].count_and_flags,
                           frame_table[i].type_and_flags,
                           (unsigned long)frame_table[i].u.domain);
                    printk("    pte_idx=%03lx *pte_idx=%08lx\n", 
                           j, l1_pgentry_val(l1e));
                }
            }
            unmap_domain_mem(pl1e);
        }
    }

}

/*
 * audit a page and keep a history of audited pfns
 */
#define LASTPAGES_SIZE 128
static long last_pages[LASTPAGES_SIZE];
static int  last_pages_idx = 0;
void audit_page(unsigned long pfn)
{
    unsigned long     i;

    cli();
    __audit_page(pfn);
    sti();
    /* add pfn to last_pages cache if is not already present */
    for ( i = 0; i < LASTPAGES_SIZE; i++ )
        if ( last_pages[i] == pfn )
            return;

    /* new entry */
    last_pages[last_pages_idx++] = pfn;
    if ( last_pages_idx >= LASTPAGES_SIZE ) 
        last_pages_idx = 0;

}

/*
 * re-audit previously audited pages
 */
void reaudit_pages(u_char key, void *dev_id, struct pt_regs *regs)
{
    int i;

    printk("Dumping audited pages\n");

    for ( i = 0; i < LASTPAGES_SIZE; i++ )
        if ( last_pages[i] != 0 )
            __audit_page(last_pages[i]);
}

/*
 * do various checks on all pages.
 * Currently:
 * - check for zombie pages
 * - check for pages with corrupt ref-count
 * Interrupts are diabled completely. use with care.
 */
void audit_all_pages(u_char key, void *dev_id, struct pt_regs *regs)
{
    unsigned long     i, j, k;
    unsigned long     ref_count;
    l1_pgentry_t     *pl1e, l1e;

    printk("audit_all_pages\n");

    cli();
    
    /* walk the frame table */
    for ( i = 0; i < max_page; i++ )
    {
        /* check for zombies */
        if ( ((frame_table[i].count_and_flags & PGC_count_mask) != 0) &&
             ((frame_table[i].count_and_flags & PGC_zombie) != 0) )
        { 
            printk("zombie: pfn=%08lx cf=%08lx tf=%08lx dom=%08lx\n", 
                   i, frame_table[i].count_and_flags,
                   frame_table[i].type_and_flags,
                   (unsigned long)frame_table[i].u.domain);
        }

        /* check ref count for leaf pages */
        if ( ((frame_table[i].type_and_flags & PGT_type_mask) ==
              PGT_writeable_page) )
        {
            ref_count = 0;

            /* find page tables */
            for ( j = 0; j < max_page; j++ )
            {
                if ( ((frame_table[j].type_and_flags & PGT_type_mask) ==
                      PGT_l1_page_table) &&
                     ((frame_table[j].type_and_flags & PGT_count_mask) != 0) )
                {
                    pl1e = map_domain_mem(j << PAGE_SHIFT);

                    /* scan page table for page to audit */
                    for ( k=0; k < ENTRIES_PER_L1_PAGETABLE; k++  )
                    {
                        l1e = pl1e[k];
                        if ( l1_pgentry_empty(l1e) )
                            continue;
                        if ( l1_pgentry_to_pagenr(l1e) == i )
                        {
                            ref_count++;
                            /* page is in pagetable */
                        }
                    }
                    unmap_domain_mem(pl1e);
                }

            }

            /* check for PGC_ALLOCATED */
            if ( (frame_table[i].count_and_flags & PGC_allocated) != 0 )
                ref_count++;

            if ( (frame_table[i].count_and_flags & PGC_count_mask) 
                 != ref_count )
            {
                printk("refcount error: pfn=%06lx cf=%08lx refcount=%lx\n",
                       i, frame_table[i].count_and_flags, ref_count);
                __audit_page(i);
                printk("\n");
            }
        } /* ref count error */
    }
    sti();
    
}

#endif /* NDEBUG */
