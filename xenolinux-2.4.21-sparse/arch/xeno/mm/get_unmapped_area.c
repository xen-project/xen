
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>

extern int direct_unmap(unsigned long, unsigned long);


int init_direct_list(struct mm_struct *mm)
{
    INIT_LIST_HEAD(&mm->context.direct_list);
    return 0;
}


void destroy_direct_list(struct mm_struct *mm)
{
    struct list_head *curr, *direct_list = &mm->context.direct_list;
    while ( (curr = direct_list->next) != direct_list )
    {
        direct_mmap_node_t *node = list_entry(curr, direct_mmap_node_t, list);
        if ( direct_unmap(node->vm_start, node->vm_end - node->vm_start) != 0 )
            BUG();
    }
}


struct list_head *find_direct(struct list_head *list, unsigned long addr)
{
    struct list_head * curr;
    struct list_head * direct_list = &current->mm->context.direct_list;
    direct_mmap_node_t * node;

    for ( curr = direct_list->next; curr != direct_list; curr = curr->next )
    {
        node = list_entry(curr, direct_mmap_node_t, list);
        if ( node->vm_start >= addr ) break;
    }

    return curr;
}


unsigned long arch_get_unmapped_area(struct file *filp, 
                                     unsigned long addr, 
                                     unsigned long len, 
                                     unsigned long pgoff, 
                                     unsigned long flags)
{
    struct vm_area_struct *vma;
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &current->mm->context.direct_list;

    if ( len > TASK_SIZE )
        return -ENOMEM;

    if ( addr )
    {
        addr = PAGE_ALIGN(addr);
        vma = find_vma(current->mm, addr);
        curr = find_direct(direct_list, addr);
        node = list_entry(curr, direct_mmap_node_t, list);
        if ( (TASK_SIZE - len >= addr) &&
             (!vma || addr + len <= vma->vm_start) &&
             ((curr == direct_list) || addr + len <= node->vm_start) )
            return addr;
    }

    addr = PAGE_ALIGN(TASK_UNMAPPED_BASE);


    /* Find first VMA and direct_map nodes with vm_start > addr */
    vma  = find_vma(current->mm, addr);
    curr = find_direct(direct_list, addr);
    node = list_entry(curr, direct_mmap_node_t, list);

    for ( ; ; )
    {
        if ( TASK_SIZE - len < addr ) return -ENOMEM;

        if ( vma && ((curr == direct_list) || 
                     (vma->vm_start < node->vm_start)) )
        {
            /* Do we fit before VMA node? */
            if ( addr + len <= vma->vm_start ) return addr;
            addr = vma->vm_end;
            vma = vma->vm_next;
        }
        else if ( curr != direct_list )
        {
            /* Do we fit before direct_map node? */
            if ( addr + len <= node->vm_start) return addr;
            addr = node->vm_end;
            curr = curr->next;
            node = list_entry(curr, direct_mmap_node_t, list);
        }
        else
        {
            /* !vma && curr == direct_list */
            return addr;
        }
    }
}
