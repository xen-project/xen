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

#define MAP_CONT    0
#define MAP_DISCONT 1

extern struct list_head * find_direct(struct list_head *, unsigned long);
extern int direct_remap_area_pages(struct mm_struct *, unsigned long, 
                                   unsigned long, unsigned long, pgprot_t);
extern void direct_zap_page_range(struct mm_struct *, unsigned long, 
                                  unsigned long);

/* 
 * used for remapping discontiguous bits of domain's memory, pages to map are
 * found from frame table beginning at the given first_pg index
 */ 
int direct_remap_disc_page_range(unsigned long from, 
                                 unsigned long first_pg, 
                                 int tot_pages, 
                                 pgprot_t prot)
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
            if(direct_remap_area_pages(current->mm,
                                       start, pfns[i] << PAGE_SHIFT, 
                                       PAGE_SIZE, prot))
                goto out;
            start += PAGE_SIZE;
            tot_pages--;
        }
    }

 out:
    free_page((unsigned long)pfns);
    return tot_pages;
} 
           

unsigned long direct_mmap(unsigned long phys_addr, unsigned long size, 
                          pgprot_t prot, int flag, int tot_pages)
{
    direct_mmap_node_t * dmmap;
    struct list_head * entry;
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

    /* and perform the mapping */
    if(flag == MAP_DISCONT){
        ret = direct_remap_disc_page_range(addr, phys_addr >> PAGE_SHIFT, 
                                           tot_pages, prot);
    } else {
        ret = direct_remap_area_pages(current->mm, 
                                      addr, phys_addr, size, prot);
    }

    if(ret == 0)
        ret = addr;

 out: 
    return ret;
}


int direct_unmap(struct mm_struct *mm, unsigned long addr, unsigned long size)
{
    int count = 0, tot_pages = (size+PAGE_SIZE-1) >> PAGE_SHIFT;
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &mm->context.direct_list;    

    curr = direct_list->next;
    while ( curr != direct_list )
    {
        node = list_entry(curr, direct_mmap_node_t, list);
        if ( node->vm_start == addr )
            break;
        curr = curr->next;
    }

    if ( curr == direct_list )
        return -1;

    list_del(&node->list);
    kfree(node);

    while ( count < tot_pages )
    {
        direct_zap_page_range(mm, addr, PAGE_SIZE);
        addr += PAGE_SIZE;
        count++;
    }

    return 0;
} 
