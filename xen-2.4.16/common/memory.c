/******************************************************************************
 * memory.c
 * 
 * Copyright (c) 2002 K A Fraser
 * 
 * A description of the page table API:
 * 
 * Domains trap to process_page_updates with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val. The exceptions are when ptr is PGREQ_ADD_BASEPTR, or
 * PGREQ_REMOVE_BASEPTR.
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

#if 1
#define MEM_LOG(_f, _a...) printk("DOM%d: (file=memory.c, line=%d) " _f "\n", current->domain, __LINE__, ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

/* 'get' checks parameter for validity before inc'ing refcnt. */
static int get_l2_table(unsigned long page_nr);
static int get_l1_table(unsigned long page_nr);
static int get_page(unsigned long page_nr, int writeable);
static int inc_page_refcnt(unsigned long page_nr, unsigned int type);
/* 'put' does no checking because if refcnt not zero, entity must be valid. */
static int  put_l2_table(unsigned long page_nr);
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
unsigned int free_pfns;


/*
 * init_frametable:
 * Initialise per-frame memory information. The return value
 * is the amount of memory available for use by the rest of Xen.
 * The very highest frames are reserved for the per-frame info.
 * This function should be called before initialising the
 * page allocator!
 */
unsigned long __init init_frametable(unsigned long nr_pages)
{
    struct pfn_info *pf;
    unsigned long page_index;

    max_page = nr_pages;
    frame_table_size = nr_pages * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
    free_pfns = nr_pages - (MAX_MONITOR_ADDRESS >> PAGE_SHIFT);

    frame_table = phys_to_virt(MAX_MONITOR_ADDRESS - frame_table_size);
    memset(frame_table, 0, frame_table_size);

    /* Put all domain-allocatable memory on a free list. */
    INIT_LIST_HEAD(&free_list);
    for( page_index = MAX_MONITOR_ADDRESS >> PAGE_SHIFT; 
         page_index < nr_pages; 
         page_index++ )      
    {
        pf = list_entry(&frame_table[page_index].list, struct pfn_info, list);
        list_add_tail(&pf->list, &free_list);
    }

    /* Return the remaing Xen-allocatable memory. */
    return(MAX_MONITOR_ADDRESS - frame_table_size);
}


/* Return original refcnt, or -1 on error. */
static int inc_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;
    unsigned long flags;

    if ( page_nr >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return(-1);
    }
    page = frame_table + page_nr;
    flags = page->flags;
    if ( (flags & PG_domain_mask) != current->domain )
    {
        MEM_LOG("Bad page domain (%ld)", flags & PG_domain_mask);
        return(-1);
    }
    if ( (flags & PG_type_mask) != type )
    {
        if ( page_type_count(page) != 0 )
        {
            MEM_LOG("Page %08lx bad type/count (%08lx!=%08x) cnt=%ld",
                    page_nr << PAGE_SHIFT,
                    flags & PG_type_mask, type, page_type_count(page));
            return(-1);
        }
        page->flags |= type;
    }

    get_page_tot(page);
    return(get_page_type(page));
}

/* Return new refcnt, or -1 on error. */
static int dec_page_refcnt(unsigned long page_nr, unsigned int type)
{
    struct pfn_info *page;
    int ret;

    if ( page_nr >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", page_nr, max_page);
        return(-1);
    }
    page = frame_table + page_nr;
    if ( (page->flags & (PG_type_mask | PG_domain_mask)) != 
         (type | current->domain) ) 
    {
        MEM_LOG("Bad page type/domain (dom=%ld) (type %ld != expected %d)",
                page->flags & PG_domain_mask, page->flags & PG_type_mask,
                type);
        return(-1);
    }
    ASSERT(page_type_count(page) != 0);
    if ( (ret = put_page_type(page)) == 0 ) page->flags &= ~PG_type_mask;
    put_page_tot(page);
    return(ret);
}


static int get_l2_table(unsigned long page_nr)
{
    l2_pgentry_t *p_l2_entry, l2_entry;
    int i, ret=0;
    
    ret = inc_page_refcnt(page_nr, PGT_l2_page_table);
    if ( ret != 0 ) return((ret < 0) ? ret : 0);
    
    /* NEW level-2 page table! Deal with every PDE in the table. */
    p_l2_entry = (l2_pgentry_t *)__va(page_nr << PAGE_SHIFT);
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        l2_entry = *p_l2_entry++;
        if ( !(l2_pgentry_val(l2_entry) & _PAGE_PRESENT) ) continue;
        if ( (l2_pgentry_val(l2_entry) & (_PAGE_GLOBAL|_PAGE_PSE)) )
        {
            MEM_LOG("Bad L2 page type settings %04lx",
                    l2_pgentry_val(l2_entry) & (_PAGE_GLOBAL|_PAGE_PSE));
            return(-1);
        }
        ret = get_l1_table(l2_pgentry_to_pagenr(l2_entry));
        if ( ret ) return(ret);
    }

    /* Now we simply slap in our high mapping. */
    memcpy(p_l2_entry, idle0_pg_table + DOMAIN_ENTRIES_PER_L2_PAGETABLE,
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

    return(ret);
}

static int get_l1_table(unsigned long page_nr)
{
    l1_pgentry_t *p_l1_entry, l1_entry;
    int i, ret;

    /* Update ref count for page pointed at by PDE. */
    ret = inc_page_refcnt(page_nr, PGT_l1_page_table);
    if ( ret != 0 ) return((ret < 0) ? ret : 0);

    /* NEW level-1 page table! Deal with every PTE in the table. */
    p_l1_entry = (l1_pgentry_t *)__va(page_nr << PAGE_SHIFT);
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
            return(-1);
        }
        ret = get_page(l1_pgentry_to_pagenr(l1_entry),
                       l1_pgentry_val(l1_entry) & _PAGE_RW);
        if ( ret ) return(ret);
    }

    return(ret);
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
    if ( (flags & PG_domain_mask) != current->domain )
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

static int put_l2_table(unsigned long page_nr)
{
    l2_pgentry_t *p_l2_entry, l2_entry;
    int i, ret;

    ret = dec_page_refcnt(page_nr, PGT_l2_page_table);
    if ( ret != 0 ) return((ret < 0) ? ret : 0);

    /* We had last reference to level-2 page table. Free the PDEs. */
    p_l2_entry = (l2_pgentry_t *)__va(page_nr << PAGE_SHIFT);
    for ( i = 0; i < HYPERVISOR_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        l2_entry = *p_l2_entry++;
        if ( (l2_pgentry_val(l2_entry) & _PAGE_PRESENT) ) 
            put_l1_table(l2_pgentry_to_pagenr(l2_entry));
    }

    return(0);
}

static void put_l1_table(unsigned long page_nr)
{
    l1_pgentry_t *p_l1_entry, l1_entry;
    int i;

    if ( dec_page_refcnt(page_nr, PGT_l1_page_table) != 0 ) return;

    /* We had last reference to level-1 page table. Free the PTEs. */
    p_l1_entry = (l1_pgentry_t *)__va(page_nr << PAGE_SHIFT);
    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
    {
        l1_entry = *p_l1_entry++;
        if ( (l1_pgentry_val(l1_entry) & _PAGE_PRESENT) ) 
        {
            put_page(l1_pgentry_to_pagenr(l1_entry), 
                     l1_pgentry_val(l1_entry) & _PAGE_RW);
        }
    }
}

static void put_page(unsigned long page_nr, int writeable)
{
    struct pfn_info *page;
    ASSERT(page_nr < max_page);
    page = frame_table + page_nr;
    ASSERT((page->flags & PG_domain_mask) == current->domain);
    ASSERT((((page->flags & PG_type_mask) == PGT_writeable_page) &&
            (page_type_count(page) != 0)) ||
           (((page->flags & PG_type_mask) == PGT_none) &&
            (page_type_count(page) == 0)));
    ASSERT((!writeable) || (page_type_count(page) != 0));
    if ( writeable && (put_page_type(page) == 0) )
        page->flags &= ~PG_type_mask;
    put_page_tot(page);
}


static int mod_l2_entry(l2_pgentry_t *p_l2_entry, l2_pgentry_t new_l2_entry)
{
    l2_pgentry_t old_l2_entry = *p_l2_entry;

    if ( (((unsigned long)p_l2_entry & (PAGE_SIZE-1)) >> 2) >=
         DOMAIN_ENTRIES_PER_L2_PAGETABLE )
    {
        MEM_LOG("Illegal L2 update attempt in hypervisor area %p\n",
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
            
            if ( get_l1_table(l2_pgentry_to_pagenr(new_l2_entry)) )
                goto fail;
        } 
    }
    else if ( (l2_pgentry_val(old_l2_entry) & _PAGE_PRESENT) )
    {
        put_l1_table(l2_pgentry_to_pagenr(old_l2_entry));
    }
    
    *p_l2_entry++ = new_l2_entry;
    
    return(0);
 fail:
    return(-1);
}


static int mod_l1_entry(l1_pgentry_t *p_l1_entry, l1_pgentry_t new_l1_entry)
{
    l1_pgentry_t old_l1_entry = *p_l1_entry;

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
                          l1_pgentry_val(new_l1_entry) & _PAGE_RW) )
                goto fail;
        } 
    }
    else if ( (l1_pgentry_val(old_l1_entry) & _PAGE_PRESENT) )
    {
        put_page(l1_pgentry_to_pagenr(old_l1_entry),
                 l1_pgentry_val(old_l1_entry) & _PAGE_RW);
    }

    *p_l1_entry++ = new_l1_entry;

    return(0);
 fail:
    return(-1);
}


/* Apply updates to page table @pagetable_id within the current domain. */
int do_process_page_updates(page_update_request_t *updates, int count)
{
    page_update_request_t cur;
    unsigned long flags, pfn;
    struct pfn_info *page;
    int err = 0, i;

    for ( i = 0; i < count; i++ )
    {
        if ( copy_from_user(&cur, updates, sizeof(cur)) )
        {
            kill_domain_with_errmsg("Cannot read page update request");
        }

        err = 1;

        pfn = cur.ptr >> PAGE_SHIFT;
        if ( !pfn )
        {
            switch ( cur.ptr )
            {
            case PGREQ_ADD_BASEPTR:
                err = get_l2_table(cur.val >> PAGE_SHIFT);
                break;
            case PGREQ_REMOVE_BASEPTR:
                if ( cur.val == __pa(pagetable_ptr(current->mm.pagetable)) )
                {
                    MEM_LOG("Attempt to remove current baseptr! %08lx",
                            cur.val);
                }
                else
                {
                    err = put_l2_table(cur.val >> PAGE_SHIFT);
                }
                break;
            }
        }
        else if ( (cur.ptr & (sizeof(l1_pgentry_t)-1)) || (pfn >= max_page) )
        {
            MEM_LOG("Page out of range (%08lx>%08lx) or misalign %08lx",
                    pfn, max_page, cur.ptr);
        }
        else
        {
            page = frame_table + pfn;
            flags = page->flags;
            if ( (flags & PG_domain_mask) == current->domain )
            {
                switch ( (flags & PG_type_mask) )
                {
                case PGT_l1_page_table: 
                    err = mod_l1_entry((l1_pgentry_t *)__va(cur.ptr), 
                                       mk_l1_pgentry(cur.val)); 
                    break;
                case PGT_l2_page_table: 
                    err = mod_l2_entry((l2_pgentry_t *)__va(cur.ptr),
                                       mk_l2_pgentry(cur.val)); 
                    break;
                }
            }
        }

        if ( err )
        {
            kill_domain_with_errmsg("Illegal page update request");
        }

        updates++;
    }

    __asm__ __volatile__ ("movl %%eax,%%cr3" : : 
                          "a" (__pa(pagetable_ptr(current->mm.pagetable))));
    return(0);
}


int do_set_pagetable(unsigned long ptr)
{
    struct pfn_info *page;
    unsigned long pfn, flags;

    if ( (ptr & ~PAGE_MASK) ) 
    {
        MEM_LOG("Misaligned new baseptr %08lx", ptr);
        return -1;
    }
    pfn = ptr >> PAGE_SHIFT;
    if ( pfn >= max_page )
    {
        MEM_LOG("Page out of range (%08lx>%08lx)", pfn, max_page);
        return -1;
    }
    page = frame_table + (ptr >> PAGE_SHIFT);
    flags = page->flags;
    if ( (flags & (PG_domain_mask|PG_type_mask)) != 
         (current->domain|PGT_l2_page_table) )
    {
        MEM_LOG("Page %08lx bad type/domain (dom=%ld) "
                "(type %08lx != expected %08x)",
                ptr, flags & PG_domain_mask, flags & PG_type_mask,
                PGT_l2_page_table);
        return -1;
    }
    current->mm.pagetable = mk_pagetable((unsigned long)__va(ptr));
    __asm__ __volatile__ ("movl %%eax,%%cr3" : : "a" (ptr));
    return 0;
}
