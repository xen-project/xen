
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

#include "hypervisor_defs.h"

#define MAP_CONT    0
#define MAP_DISCONT 1

/*
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */

/* bd240: functions below perform direct mapping to the real physical pages needed for
 * mapping various hypervisor specific structures needed in dom0 userspace by various
 * management applications such as domain builder etc.
 */

#define direct_set_pte(pteptr, pteval) queue_l1_entry_update(__pa(pteptr) | PGREQ_UNCHECKED_UPDATE, (pteval).pte_low)

#define direct_pte_clear(pteptr) queue_l1_entry_update(__pa(pteptr) | PGREQ_UNCHECKED_UPDATE, 0)

#define __direct_pte(x) ((pte_t) { (x) } )
#define __direct_mk_pte(page_nr,pgprot) __direct_pte(((page_nr) << PAGE_SHIFT) | pgprot_val(pgprot))
#define direct_mk_pte_phys(physpage, pgprot)   __direct_mk_pte((physpage) >> PAGE_SHIFT, pgprot)

static inline void forget_pte(pte_t page)
{
    if (!pte_none(page)) {
        printk("forget_pte: old mapping existed!\n");
        BUG();
    }
}

static inline void direct_remappte_range(pte_t * pte, unsigned long address, unsigned long size,
	unsigned long phys_addr, pgprot_t prot)
{
	unsigned long end;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		pte_t oldpage;
		oldpage = ptep_get_and_clear(pte);
        
        printk(KERN_ALERT "bd240 debug: %lx - %lx\n", address, phys_addr);

 		direct_set_pte(pte, direct_mk_pte_phys(phys_addr, prot));

		forget_pte(oldpage);
		address += PAGE_SIZE;
		phys_addr += PAGE_SIZE;
		pte++;
	} while (address && (address < end));

	printk("bd240 debug: exit from direct_remappte_range\n");
}

static inline int direct_remappmd_range(struct mm_struct *mm, pmd_t * pmd, unsigned long address, unsigned long size,
	unsigned long phys_addr, pgprot_t prot)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	phys_addr -= address;
	do {
		pte_t * pte = pte_alloc(mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		direct_remappte_range(pte, address, end - address, address + phys_addr, prot);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

/*  Note: this is only safe if the mm semaphore is held when called. */
int direct_remap_page_range(unsigned long from, unsigned long phys_addr, unsigned long size, pgprot_t prot)
{
	int error = 0;
	pgd_t * dir;
	unsigned long beg = from;
	unsigned long end = from + size;
	struct mm_struct *mm = current->mm;

	phys_addr -= from;
	dir = pgd_offset(mm, from);
	flush_cache_range(mm, beg, end);
	if (from >= end)
		BUG();

	spin_lock(&mm->page_table_lock);
	do {
		pmd_t *pmd = pmd_alloc(mm, dir, from);
		error = -ENOMEM;
		if (!pmd)
			break;
		error = direct_remappmd_range(mm, pmd, from, end - from, phys_addr + from, prot);
		if (error)
			break;
		from = (from + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (from && (from < end));
	spin_unlock(&mm->page_table_lock);
	flush_tlb_range(mm, beg, end);
	return error;
}

/* 
 * used for remapping discontiguous bits of domain's memory, pages to map are
 * found from frame table beginning at the given first_pg index
 */ 
int direct_remap_disc_page_range(unsigned long from, unsigned long first_pg,
                int tot_pages, pgprot_t prot)
{
    frame_table_t * current_ft;
    unsigned long current_pfn;
    unsigned long start = from;
    int count = 0;

    current_ft = (frame_table_t *)(frame_table + first_pg);
    current_pfn = first_pg; 
    while(count < tot_pages){
            if(direct_remap_page_range(start, current_pfn << PAGE_SHIFT, PAGE_SIZE, prot))
                goto out;
            start += PAGE_SIZE;
            current_pfn = current_ft->next;
            current_ft = (frame_table_t *)(frame_table + current_pfn);
            count++;
    }

out:

    return tot_pages - count;
} 
           
/* below functions replace standard sys_mmap and sys_munmap which are absolutely useless
 * for direct memory mapping. direct_zap* functions are minor ammendments to the 
 * original versions in mm/memory.c. the changes are to enable unmapping of real physical
 * addresses.
 */

unsigned long direct_mmap(unsigned long phys_addr, unsigned long size, 
                pgprot_t prot, int flag, int tot_pages)
{
    direct_mmap_node_t * dmmap;
    unsigned long addr;
    int ret = 0;
    
    if(!capable(CAP_SYS_ADMIN)){
        ret = -EPERM;
        goto out;
    }

    /* get unmapped area invokes xen specific arch_get_unmapped_area */
    addr = get_unmapped_area(NULL, 0, size, 0, 0);
    if(addr & ~PAGE_MASK){
        ret = -ENOMEM;
        goto out;
    }

    /* add node on the list of directly mapped areas */ 
    dmmap = (direct_mmap_node_t *)kmalloc(GFP_KERNEL, sizeof(direct_mmap_node_t));
    dmmap->addr = addr;
    list_add(&dmmap->list, &current->mm->context.direct_list);

    /* and perform the mapping */
    if(flag == MAP_DISCONT){
        ret = direct_remap_disc_page_range(addr, phys_addr, tot_pages, prot);
    } else {
		printk(KERN_ALERT "bd240 debug: addr %lx, phys_addr %lx, size %lx\n",
			addr, phys_addr, size);
        ret = direct_remap_page_range(addr, phys_addr, size, prot);
    }

    if(ret == 0)
        ret = addr;

out: 
    return ret;
}

/* most of the checks, refcnt updates, cache stuff have been thrown out as they are not
 * needed
 */
static inline int direct_zap_pte_range(mmu_gather_t *tlb, pmd_t * pmd, unsigned long address, 
                unsigned long size)
{
	unsigned long offset;
	pte_t * ptep;
	int freed = 0;

	if (pmd_none(*pmd))
		return 0;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return 0;
	}
	ptep = pte_offset(pmd, address);
	offset = address & ~PMD_MASK;
	if (offset + size > PMD_SIZE)
		size = PMD_SIZE - offset;
	size &= PAGE_MASK;
	for (offset=0; offset < size; ptep++, offset += PAGE_SIZE) {
		pte_t pte = *ptep;
		if (pte_none(pte))
			continue;
		freed ++;
		direct_pte_clear(ptep);
	}

	return freed;
}

static inline int direct_zap_pmd_range(mmu_gather_t *tlb, pgd_t * dir, 
                unsigned long address, unsigned long size)
{
	pmd_t * pmd;
	unsigned long end;
	int freed;

	if (pgd_none(*dir))
		return 0;
	if (pgd_bad(*dir)) {
		pgd_ERROR(*dir);
		pgd_clear(dir);
		return 0;
	}
	pmd = pmd_offset(dir, address);
	end = address + size;
	if (end > ((address + PGDIR_SIZE) & PGDIR_MASK))
		end = ((address + PGDIR_SIZE) & PGDIR_MASK);
	freed = 0;
	do {
		freed += direct_zap_pte_range(tlb, pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK; 
		pmd++;
	} while (address < end);
	return freed;
}

/*
 * remove user pages in a given range.
 */
void direct_zap_page_range(struct mm_struct *mm, unsigned long address, unsigned long size)
{
	mmu_gather_t *tlb;
	pgd_t * dir;
	unsigned long start = address, end = address + size;
	int freed = 0;

	dir = pgd_offset(mm, address);

	/*
	 * This is a long-lived spinlock. That's fine.
	 * There's no contention, because the page table
	 * lock only protects against kswapd anyway, and
	 * even if kswapd happened to be looking at this
	 * process we _want_ it to get stuck.
	 */
	if (address >= end)
		BUG();
	spin_lock(&mm->page_table_lock);
	flush_cache_range(mm, address, end);
	tlb = tlb_gather_mmu(mm);

	do {
		freed += direct_zap_pmd_range(tlb, dir, address, end - address);
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));

	/* this will flush any remaining tlb entries */
	tlb_finish_mmu(tlb, start, end);

    /* decrementing rss removed */

	spin_unlock(&mm->page_table_lock);
}

int direct_unmap(unsigned long addr, unsigned long size)
{
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &current->mm->context.direct_list;    

    curr = direct_list->next;
    while(curr != direct_list){
        node = list_entry(curr, direct_mmap_node_t, list);
        if(node->addr == addr)
            break;
        curr = curr->next;
    }

    if(curr == direct_list)
        return -1;

    list_del(&node->list);
    kfree(node);

    direct_zap_page_range(current->mm, addr, size);
 
    return 0;
}

int direct_disc_unmap(unsigned long from, unsigned long first_pg, int tot_pages)
{
    int count = 0;
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &current->mm->context.direct_list;    

    curr = direct_list->next;
    while(curr != direct_list){
        node = list_entry(curr, direct_mmap_node_t, list);
        if(node->addr == from)
            break;
        curr = curr->next;
    }

    if(curr == direct_list)
        return -1;

    list_del(&node->list);
    kfree(node);

    while(count < tot_pages){
            direct_zap_page_range(current->mm, from, PAGE_SIZE);
            from += PAGE_SIZE;
            count++;
    }

    return 0;
} 
