
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

static int direct_mapped(unsigned long addr)
{
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &current->mm->context.direct_list;

    /* now, this loop is going to make things slow, maybe should think
     * of a better way to implement it, maybe without list_head
     */
    curr = direct_list->next;
    while(curr != direct_list){
        node = list_entry(curr, direct_mmap_node_t, list);
        if(node->addr == addr)
            break;
        curr = curr->next;
    } 

    if(curr == direct_list)
        return 0;

    return 1;
}

unsigned long arch_get_unmapped_area(struct file *filp, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct vm_area_struct *vma;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(current->mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	addr = PAGE_ALIGN(TASK_UNMAPPED_BASE);

	for (vma = find_vma(current->mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr)
			return -ENOMEM;
        
        /* here we check whether the vma is big enough and we also check
         * whether it has already been direct mapped, in which case it
         * is not available. this is the only difference to generic
         * arch_get_unmapped_area. 
         */
		printk(KERN_ALERT "bd240 debug: gua: vm addr found %lx\n", addr);
		if ((!vma || addr + len <= vma->vm_start) && !direct_mapped(addr)){
			printk(KERN_ALERT "bd240 debug: gua: first condition %d, %lx, %lx\n",vma, addr + len, vma->vm_start);
			printk(KERN_ALERT "bd240 debug: gua: second condition %d\n", direct_mapped(addr));

			return addr;
		}
		
        addr = vma->vm_end;
	}
}
