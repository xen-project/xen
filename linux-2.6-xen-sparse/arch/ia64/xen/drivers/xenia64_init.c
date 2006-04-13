#ifdef __ia64__
#include <linux/config.h>
#include <linux/module.h>
#include <linux/efi.h>
#include <asm/sal.h>
#include <asm/hypervisor.h>
/* #include <asm-xen/evtchn.h> */
#include <xen/interface/arch-ia64.h>
#include <linux/vmalloc.h>

shared_info_t *HYPERVISOR_shared_info = (shared_info_t *)0xf100000000000000;
EXPORT_SYMBOL(HYPERVISOR_shared_info);

static int initialized;
start_info_t *xen_start_info;

int xen_init(void)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	if (initialized)
		return running_on_xen ? 0 : -1;

	if (!running_on_xen)
		return -1;

	xen_start_info = __va(s->arch.start_info_pfn << PAGE_SHIFT);
	xen_start_info->flags = s->arch.flags;
	printk("Running on Xen! start_info_pfn=0x%lx nr_pages=%ld flags=0x%x\n",
		s->arch.start_info_pfn, xen_start_info->nr_pages,
		xen_start_info->flags);

	evtchn_init();
	initialized = 1;
	return 0;
}

/* We just need a range of legal va here, though finally identity
 * mapped one is instead used for gnttab mapping.
 */
unsigned long alloc_empty_foreign_map_page_range(unsigned long pages)
{
	struct vm_struct *vma;

	if ( (vma = get_vm_area(PAGE_SIZE * pages, VM_ALLOC)) == NULL )
		return NULL;

	return (unsigned long)vma->addr;
}

#if 0
/* These should be define'd but some drivers use them without
 * a convenient arch include */
unsigned long mfn_to_pfn(unsigned long mfn) { return mfn; }
#endif
#endif
