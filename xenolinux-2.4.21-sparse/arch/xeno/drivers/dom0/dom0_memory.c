#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/swapctl.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/list.h>

#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/mmu.h>

#include "dom0_ops.h"

extern struct list_head * find_direct(struct list_head *, unsigned long);

/*
 * bd240: functions below perform direct mapping to the real physical pages
 * needed for mapping various hypervisor specific structures needed in dom0
 * userspace by various management applications such as domain builder etc.
 */

#define direct_set_pte(pteptr, pteval) queue_l1_entry_update(__pa(pteptr)|PGREQ_UNCHECKED_UPDATE, (pteval).pte_low)

#define direct_pte_clear(pteptr) queue_l1_entry_update(__pa(pteptr)|PGREQ_UNCHECKED_UPDATE, 0)

#define __direct_pte(x) ((pte_t) { (x) } )
#define __direct_mk_pte(page_nr,pgprot) __direct_pte(((page_nr) << PAGE_SHIFT) | pgprot_val(pgprot))
#define direct_mk_pte_phys(physpage, pgprot)   __direct_mk_pte((physpage) >> PAGE_SHIFT, pgprot)

/*  Note: this is only safe if the mm semaphore is held when called. */

static int direct_remap_page(unsigned long from, unsigned long phys_addr, pgprot_t prot)
{
    struct mm_struct *mm = current->mm;
    pgd_t * dir;
    pmd_t *pmd;
    pte_t *pte;

    pte_t oldpage;

    dir = pgd_offset(mm, from);
    flush_cache_range(mm, from, from + PAGE_SIZE);
    
    spin_lock(&mm->page_table_lock);
    pmd = pmd_alloc(mm, dir, from);
    if (!pmd)
	return -ENOMEM;
    pte = pte_alloc(mm, pmd, from);
    if (!pte) {
	/* XXX free pmd? */
	return -ENOMEM;
    }

    /* Sanity check */
    oldpage = ptep_get_and_clear(pte);
    if (!pte_none(oldpage)) {
        printk("Page already in use!\n");
        BUG();
    }
    direct_set_pte(pte, direct_mk_pte_phys(phys_addr, prot));

    spin_unlock(&mm->page_table_lock);

    flush_tlb_range(mm, from, from + PAGE_SIZE);

    return 0;
}

/* 
 * used for remapping discontiguous bits of domain's memory, pages to map are
 * found from frame table beginning at the given first_pg index
 */ 
static int direct_remap_disc_page_range(unsigned long from, 
					unsigned long first_pg, int tot_pages, pgprot_t prot)
{
    dom0_op_t dom0_op;
    unsigned long *pfns = (unsigned long *)get_free_page(GFP_KERNEL);
    unsigned long start = from;
    int pages, i;

    while ( tot_pages != 0 )
    {
        dom0_op.cmd = DOM0_GETMEMLIST;
        dom0_op.u.getmemlist.start_pfn = first_pg;
        pages = 1023;
        dom0_op.u.getmemlist.num_pfns = 1024;
        if ( tot_pages < 1024 )
            dom0_op.u.getmemlist.num_pfns = pages = tot_pages;
        dom0_op.u.getmemlist.buffer = pfns;
        (void)HYPERVISOR_dom0_op(&dom0_op);
        first_pg = pfns[1023]; 

        for ( i = 0; i < pages; i++ )
        {
            if(direct_remap_page(start, pfns[i] << PAGE_SHIFT, 
				 prot))
                goto out;
            start += PAGE_SIZE;
            tot_pages--;
        }
    }

 out:
    free_page((unsigned long)pfns);
    return tot_pages;
} 
           
/* below functions replace standard sys_mmap and sys_munmap which are
 * absolutely useless for direct memory mapping. direct_zap* functions
 * are minor ammendments to the original versions in mm/memory.c. the
 * changes are to enable unmapping of real physical addresses.
 */

unsigned long direct_mmap(unsigned long phys_addr, unsigned long size, 
			  pgprot_t prot, int tot_pages)
{
    direct_mmap_node_t * dmmap;
    struct list_head * entry;
    unsigned long addr;
    int ret = 0;
    
    if(!(size & ~PAGE_MASK))
	return -EINVAL;

    if(!capable(CAP_SYS_ADMIN))
        return -EPERM;

    /* get unmapped area invokes xen specific arch_get_unmapped_area */
    addr = get_unmapped_area(NULL, 0, size, 0, 0);
    if(addr & ~PAGE_MASK)
        return -ENOMEM;

    /* add node on the list of directly mapped areas, make sure the
     * list remains sorted.
     */ 
    dmmap = (direct_mmap_node_t *)kmalloc(sizeof(direct_mmap_node_t), GFP_KERNEL);
    dmmap->vm_start = addr;
    dmmap->vm_end = addr + size;
    entry = find_direct(&current->mm->context.direct_list, addr);
    if(entry != &current->mm->context.direct_list){
	list_add_tail(&dmmap->list, entry);
    } else {
	list_add_tail(&dmmap->list, &current->mm->context.direct_list);
    }

    /* Acquire mm sem? XXX */
    /* and perform the mapping */
    ret = direct_remap_disc_page_range(addr, phys_addr >> PAGE_SHIFT, 
				       tot_pages, prot);
    /* Drop mm sem? XXX */

    if(ret == 0)
        return addr;
    else
        return ret;
}

/*
 * remove a user page
 *
 * There used to be a function here which could remove a whole range
 * of pages, but it was only ever called with that range equal to a
 * single page, so I simplified it a bit -- sos22.
 */
static void direct_zap_page(struct mm_struct *mm, unsigned long address)
{
    mmu_gather_t *tlb;
    pgd_t * dir;
    pmd_t * pmd;
    pte_t * pte;

    dir = pgd_offset(mm, address);

    /*
     * This is a long-lived spinlock. That's fine.
     * There's no contention, because the page table
     * lock only protects against kswapd anyway, and
     * even if kswapd happened to be looking at this
     * process we _want_ it to get stuck.
     */
    spin_lock(&mm->page_table_lock);
    flush_cache_range(mm, address, address + PAGE_SIZE);
    
    tlb = tlb_gather_mmu(mm);
    pmd = pmd_offset(dir, address);
    pte = pte_offset(pmd, address);
    direct_pte_clear(pte);
    tlb_finish_mmu(tlb, address, address + PAGE_SIZE);

    /* decrementing rss removed */
    spin_unlock(&mm->page_table_lock);
}


int direct_unmap(struct mm_struct *mm, unsigned long addr, unsigned long size)
{
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &mm->context.direct_list;    
    unsigned long end;

    curr = direct_list->next;
    while ( curr != direct_list )
    {
        node = list_entry(curr, direct_mmap_node_t, list);
        if ( node->vm_start == addr && node->vm_end == addr + size)
            break;
        curr = curr->next;
    }

    if ( curr == direct_list )
        return -1;

    list_del(&node->list);
    kfree(node);

    if (size & ~PAGE_MASK) {
	printk("Managed to map something which isn\'t a multiple of a page size...\n");
	BUG();
	return -EINVAL;
    }

    end = addr + size;
    while ( addr < end )
    {
        direct_zap_page(mm, addr);
        addr += PAGE_SIZE;
    }

    return 0;
} 
