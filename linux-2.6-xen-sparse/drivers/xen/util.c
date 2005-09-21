#include <linux/config.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

static int touch_fn(
	pte_t *pte, struct page *pte_page, unsigned long addr, void *data)
{
	char c;
	BUG_ON(!__get_user(c, (char *)addr));
	return 0;
}

struct vm_struct *prepare_vm_area(unsigned long size)
{
	struct vm_struct *area;

	area = get_vm_area(size, VM_IOREMAP);
	if (area == NULL)
		return NULL;

	/*
         * This ensures that page tables are constructed for this region
         * of kernel virtual address space. Furthermore, by touching each
         * memory page (in touch_fn()) we ensure that the page tables are
         * mapped into the current mm as well as init_mm.
         */
	if (generic_page_range(&init_mm, (unsigned long)area->addr,
			       area->size, touch_fn, NULL)) {
		vunmap(area->addr);
		return NULL;
	}

	return area;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
