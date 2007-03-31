#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <xen/driver_util.h>

struct class *get_xen_class(void)
{
	static struct class *xen_class;

	if (xen_class)
		return xen_class;

	xen_class = class_create(THIS_MODULE, "xen");
	if (IS_ERR(xen_class)) {
		printk("Failed to create xen sysfs class.\n");
		xen_class = NULL;
	}

	return xen_class;
}
EXPORT_SYMBOL_GPL(get_xen_class);

/* Todo: merge ia64 ('auto-translate physmap') versions of these functions. */
#ifndef __ia64__

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

	/* Map page directories into every address space. */
#ifdef CONFIG_X86
	vmalloc_sync_all();
#endif

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

#endif /* !__ia64__ */
