/******************************************************************************
 * memory.c
 * 
 * Copyright (c) 2002 K A Fraser
 * 
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
 * [THAT IS, THEY'RE NOT A PROBLEM NOW, AND MAY NOT EVER BE.]
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
 * ** 1 **
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
 * 
 * ** 2 **
 * Same problem occurs when removing a page table, at level 1 say, then
 * making it writeable. Need a TLB flush between otherwise another processor
 * might write an illegal mapping into the old table, while yet another
 * processor can use the illegal mapping because of a stale level-2 TLB
 * entry. So, removal of a table reference sets 'flush_level' appropriately,
 * and a flush occurs on next addition of a fresh write mapping.
 * 
 * BETTER SOLUTION FOR BOTH 1 AND 2:
 * When type_refcnt goes to zero, leave old type in place (don't set to
 * PGT_none). Then, only flush if making a page table of a page with
 * (cnt=0,type=PGT_writeable), or when adding a write mapping for a page
 * with (cnt=0, type=PGT_pagexxx). A TLB flush will cause all pages
 * with refcnt==0 to be reset to PGT_none. Need an array for the purpose,
 * added to when a type_refcnt goes to zero, and emptied on a TLB flush.
 * Either have per-domain table, or force TLB flush at end of each
 * call to 'process_page_updates'.
 * Most OSes will always keep a writeable reference hanging around, and
 * page table structure is fairly static, so this mechanism should be
 * fairly cheap.
 * 
 * MAYBE EVEN BETTER? [somewhat dubious: not for first cut of the code]:
 * If we need to force an intermediate flush, those other processors
 * spin until we complete, then do a single TLB flush. They can spin on
 * the lock protecting 'process_page_updates', and continue when that
 * is freed. Saves cost of setting up and servicing an IPI: later
 * communication is synchronous. Processors trying to install the domain
 * or domain&pagetable would also enter the spin.
 * 
 * ** 3 **
 * Indeed, this problem generalises to reusing page tables at different
 * levels of the hierarchy (conceptually, the guest OS can use the
 * hypervisor to introduce illegal table entries by proxy). Consider
 * unlinking a level-1 page table and reintroducing at level 2 with no
 * TLB flush. Hypervisor can add a reference to some other level-1 table
 * with the RW bit set. This is fine in the level-2 context, but some
 * other processor may still be using that table in level-1 context
 * (due to a stale TLB entry). At level 1 it may look like the
 * processor has write access to the other level-1 page table! Therefore
 * can add illegal values there with impunity :-(
 * 
 * Fortunately, the solution above generalises to this extended problem.
 */

/*
 * UPDATE 12.11.02.: We no longer have struct page and mem_map. These
 * have been replaced by struct pfn_info and frame_table respectively.
 * 
 * system_free_list is a list_head linking all system owned free pages.
 * it is initialized in init_frametable.
 *
 * Boris Dragovic.
 */
 
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/mm.h>
#include <xeno/sched.h>
#include <xeno/errno.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>

#if 1
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

static int mod_l2_entry(unsigned long, l2_pgentry_t);
static int mod_l1_entry(unsigned long, l1_pgentry_t);

/* frame table size and its size in pages */
frame_table_t * frame_table;
unsigned long frame_table_size;
unsigned long max_page;

struct list_head free_list;
unsigned int free_pfns;

static int tlb_flush[NR_CPUS];

/*
 * init_frametable:
 * Initialise per-frame memory information. This goes directly after
 * MAX_MONITOR_ADDRESS in physical memory.
 */
void __init init_frametable(unsigned long nr_pages)
{
    struct pfn_info *pf;
    unsigned long page_index;

    memset(tlb_flush, 0, sizeof(tlb_flush));

    max_page = nr_pages;
    frame_table_size = nr_pages * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
    frame_table = (frame_table_t *)FRAMETABLE_VIRT_START;
    memset(frame_table, 0, frame_table_size);

    free_pfns = 0;

    /* Put all domain-allocatable memory on a free list. */
    INIT_LIST_HEAD(&free_list);
    for( page_index = (__pa(frame_table) + frame_table_size) >> PAGE_SHIFT; 
         page_index < nr_pages;
         page_index++ )      
    {
        pf = list_entry(&frame_table[page_index].list, struct pfn_info, list);
        list_add_tail(&pf->list, &free_list);
        free_pfns++;
    }
}


/* Return original refcnt, or -1 on error. */
static int inc_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;
    unsigned long flags;

    if ( page_nr >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return -1;
    }
    page = frame_table + page_nr;
    flags = page->flags;
    if ( !DOMAIN_OKAY(flags) )
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

        page->flags |= type;
    }

    get_page_tot(page);
    return get_page_type(page);
}

/* Return new refcnt, or -1 on error. */
static int dec_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;
    int ret;

    if ( page_nr >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return -1;
    }
    page = frame_table + page_nr;
    if ( !DOMAIN_OKAY(page->flags) || 
         ((page->flags & PG_type_mask) != type) ) 
    {
        MEM_LOG("Bad page type/domain (dom=%ld) (type %ld != expected %d)",
                page->flags & PG_domain_mask, page->flags & PG_type_mask,
                type);
        return -1;
    }
    ASSERT(page_type_count(page) != 0);
    if ( (ret = put_page_type(page)) == 0 ) page->flags &= ~PG_type_mask;
    put_page_tot(page);
    return ret;
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
    if ( ret != 0 ) return (ret < 0) ? ret : 0;
    
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
           idle_pg_table[smp_processor_id()] + DOMAIN_ENTRIES_PER_L2_PAGETABLE,
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    p_l2_entry[(PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT) -
              DOMAIN_ENTRIES_PER_L2_PAGETABLE] =
        mk_l2_pgentry(__pa(current->mm.perdomain_pt) | __PAGE_HYPERVISOR);

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
    if ( ret != 0 ) return (ret < 0) ? ret : 0;

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
    if ( page_nr >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return(-1);
    }
    page = frame_table + page_nr;
    flags = page->flags;
    if ( !DOMAIN_OKAY(flags) )
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
            page->flags |= PGT_writeable_page;
        }
        get_page_type(page);
    }

    get_page_tot(page);
    
    return(0);
}

static void put_l2_table(unsigned long page_nr)
{
    l2_pgentry_t *p_l2_entry, l2_entry;
    int i;

    if ( dec_page_refcnt(page_nr, PGT_l2_page_table) ) return;

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

    if ( dec_page_refcnt(page_nr, PGT_l1_page_table) ) return;

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
            ((page->flags & PG_type_mask) == PGT_writeable_page)));
    if ( writeable && (put_page_type(page) == 0) )
    {
        tlb_flush[smp_processor_id()] = 1;
        page->flags &= ~PG_type_mask;
    }
    put_page_tot(page);
}


static int mod_l2_entry(unsigned long pa, l2_pgentry_t new_l2_entry)
{
    l2_pgentry_t *p_l2_entry, old_l2_entry;

    p_l2_entry = map_domain_mem(pa);
    old_l2_entry = *p_l2_entry;

    if ( (((unsigned long)p_l2_entry & (PAGE_SIZE-1)) >> 2) >=
         DOMAIN_ENTRIES_PER_L2_PAGETABLE )
    {
        MEM_LOG("Illegal L2 update attempt in hypervisor area %p",
                p_l2_entry);
        goto fail;
    }

    if ( (l2_pgentry_val(new_l2_entry) & _PAGE_PRESENT) )
    {
        if ( (l2_pgentry_val(new_l2_entry) & (_PAGE_GLOBAL|_PAGE_PSE)) )
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
            {
                put_l1_table(l2_pgentry_to_pagenr(old_l2_entry));
            }
            
            /* Assume we're mapping an L1 table, falling back to twisted L2. */
            if ( get_l1_table(l2_pgentry_to_pagenr(new_l2_entry)) &&
                 get_twisted_l2_table(pa >> PAGE_SHIFT, new_l2_entry) )
                goto fail;
        } 
    }
    else if ( (l2_pgentry_val(old_l2_entry) & _PAGE_PRESENT) )
    {
        put_l1_table(l2_pgentry_to_pagenr(old_l2_entry));
    }
    
    *p_l2_entry = new_l2_entry;
    unmap_domain_mem(p_l2_entry);
    return 0;

 fail:
    unmap_domain_mem(p_l2_entry);
    return -1;
}


static int mod_l1_entry(unsigned long pa, l1_pgentry_t new_l1_entry)
{
    l1_pgentry_t *p_l1_entry, old_l1_entry;

    p_l1_entry = map_domain_mem(pa);
    old_l1_entry = *p_l1_entry;

    if ( (l1_pgentry_val(new_l1_entry) & _PAGE_PRESENT) )
    {
        if ( (l1_pgentry_val(new_l1_entry) &
              (_PAGE_GLOBAL|_PAGE_PAT)) ) 
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
            {
                put_page(l1_pgentry_to_pagenr(old_l1_entry),
                         l1_pgentry_val(old_l1_entry) & _PAGE_RW);
            }
            
            if ( get_page(l1_pgentry_to_pagenr(new_l1_entry),
                          l1_pgentry_val(new_l1_entry) & _PAGE_RW) ){
                goto fail;
            }
        } 
    }
    else if ( (l1_pgentry_val(old_l1_entry) & _PAGE_PRESENT) )
    {
        put_page(l1_pgentry_to_pagenr(old_l1_entry),
                 l1_pgentry_val(old_l1_entry) & _PAGE_RW);
    }

    *p_l1_entry = new_l1_entry;
    unmap_domain_mem(p_l1_entry);
    return 0;

 fail:
    unmap_domain_mem(p_l1_entry);
    return -1;
}


static int do_extended_command(unsigned long ptr, unsigned long val)
{
    int err = 0;
    unsigned long pfn = ptr >> PAGE_SHIFT;
    struct pfn_info *page = frame_table + pfn;

    switch ( (val & PGEXT_CMD_MASK) )
    {
    case PGEXT_PIN_L1_TABLE:
        err = get_l1_table(pfn);
        goto mark_as_pinned;
    case PGEXT_PIN_L2_TABLE:
        err = get_l2_table(pfn);
    mark_as_pinned:
        if ( err )
        {
            MEM_LOG("Error while pinning pfn %08lx", pfn);
            break;
        }
        put_page_type(page);
        put_page_tot(page);
        if ( !(page->type_count & REFCNT_PIN_BIT) )
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
        }
        else
        {
            MEM_LOG("Error while installing new baseptr %08lx %d", ptr, err);
        }
        /* fall through */
        
    case PGEXT_TLB_FLUSH:
        tlb_flush[smp_processor_id()] = 1;
        break;
    
    case PGEXT_INVLPG:
        __flush_tlb_one(val & ~PGEXT_CMD_MASK);
        break;

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
    unsigned long flags, pfn;
    struct pfn_info *page;
    int err = 0, i;

    for ( i = 0; i < count; i++ )
    {
        if ( copy_from_user(&req, ureqs, sizeof(req)) )
        {
            kill_domain_with_errmsg("Cannot read page update request");
        } 

        pfn = req.ptr >> PAGE_SHIFT;
        if ( pfn >= max_page )
        {
            MEM_LOG("Page out of range (%08lx > %08lx)", pfn, max_page);
            kill_domain_with_errmsg("Page update request out of range");
        }

        err = 1;

        /* Least significant bits of 'ptr' demux the operation type. */
        switch ( req.ptr & (sizeof(l1_pgentry_t)-1) )
        {
            /*
             * PGREQ_NORMAL: Normal update to any level of page table.
             */
        case PGREQ_NORMAL:
            page = frame_table + pfn;
            flags = page->flags;
            
            if ( DOMAIN_OKAY(flags) )
            {
                switch ( (flags & PG_type_mask) )
                {
                case PGT_l1_page_table: 
                    err = mod_l1_entry(req.ptr, mk_l1_pgentry(req.val)); 
                    break;
                case PGT_l2_page_table: 
                    err = mod_l2_entry(req.ptr, mk_l2_pgentry(req.val)); 
                    break;
                default:
                    MEM_LOG("Update to non-pt page %08lx", req.ptr);
                    break;
                }
            }
            else
            {
                MEM_LOG("Bad domain normal update (dom %d, pfn %ld)",
                        current->domain, pfn);
            }
            break;

        case PGREQ_MPT_UPDATE:
            page = frame_table + pfn;
            if ( DOMAIN_OKAY(page->flags) )
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

        case PGREQ_UNCHECKED_UPDATE:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            if ( current->domain == 0 )
            {
                unsigned long *ptr = map_domain_mem(req.ptr);
                *ptr = req.val;
                unmap_domain_mem(ptr);
                err = 0;
            }
            else
            {
                MEM_LOG("Bad unchecked update attempt");
            }
            break;
            
        default:
            MEM_LOG("Invalid page update command %08lx", req.ptr);
            break;
        }

        if ( err )
        {
            kill_domain_with_errmsg("Illegal page update request");
        }

        ureqs++;
    }

    if ( tlb_flush[smp_processor_id()] )
    {
        tlb_flush[smp_processor_id()] = 0;
        __asm__ __volatile__ (
            "movl %%eax,%%cr3" : : 
            "a" (pagetable_val(current->mm.pagetable)));

    }

    return(0);
}
