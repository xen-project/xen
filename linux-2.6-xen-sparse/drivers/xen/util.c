#include <linux/config.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <xen/driver_util.h>

static int f(pte_t *pte, struct page *pmd_page, unsigned long addr, void *data)
{
	/* apply_to_page_range() does all the hard work. */
	return 0;
}

struct vm_struct *alloc_vm_area(unsigned long size)
{
	struct vm_struct *area;

	area = get_vm_area(size, VM_IOREMAP);
	if (area == NULL)
		return NULL;

	/*
	 * This ensures that page tables are constructed for this region
	 * of kernel virtual address space and mapped into init_mm.
	 */
	if (apply_to_page_range(&init_mm, (unsigned long)area->addr,
				area->size, f, NULL)) {
		free_vm_area(area);
		return NULL;
	}

	return area;
}
EXPORT_SYMBOL_GPL(alloc_vm_area);

void free_vm_area(struct vm_struct *area)
{
	struct vm_struct *ret;
	ret = remove_vm_area(area->addr);
	BUG_ON(ret != area);
	kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);

void lock_vm_area(struct vm_struct *area)
{
	unsigned long i;
	char c;

	/*
	 * Prevent context switch to a lazy mm that doesn't have this area
	 * mapped into its page tables.
	 */
	preempt_disable();

	/*
	 * Ensure that the page tables are mapped into the current mm. The
	 * page-fault path will copy the page directory pointers from init_mm.
	 */
	for (i = 0; i < area->size; i += PAGE_SIZE)
		(void)__get_user(c, (char __user *)area->addr + i);
}
EXPORT_SYMBOL_GPL(lock_vm_area);

void unlock_vm_area(struct vm_struct *area)
{
	preempt_enable();
}
EXPORT_SYMBOL_GPL(unlock_vm_area);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
