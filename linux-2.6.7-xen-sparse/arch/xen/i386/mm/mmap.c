
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/init.h>
#include <asm/pgalloc.h>

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (((TASK_SIZE - len) >= addr) &&
		    (addr >= (FIRST_USER_PGD_NR<<PGDIR_SHIFT)) &&
		    (!vma || ((addr + len) <= vma->vm_start)))
			return addr;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	start_addr = addr = mm->free_area_cache;
#else
	addr = PAGE_ALIGN(TASK_UNMAPPED_BASE);
#endif

full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = addr = TASK_UNMAPPED_BASE;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			mm->free_area_cache = addr + len;
#endif
			return addr;
		}
		addr = vma->vm_end;
	}
}

unsigned long
arch_check_fixed_mapping(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	if ( addr < (FIRST_USER_PGD_NR<<PGDIR_SHIFT) )
		return -EINVAL;
	return 0;
}
