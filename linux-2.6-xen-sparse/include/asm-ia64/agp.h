#ifndef _ASM_IA64_AGP_H
#define _ASM_IA64_AGP_H

/*
 * IA-64 specific AGP definitions.
 *
 * Copyright (C) 2002-2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */

/*
 * To avoid memory-attribute aliasing issues, we require that the AGPGART engine operate
 * in coherent mode, which lets us map the AGP memory as normal (write-back) memory
 * (unlike x86, where it gets mapped "write-coalescing").
 */
#define map_page_into_agp(page)		/* nothing */
#define unmap_page_from_agp(page)	/* nothing */
#define flush_agp_mappings()		/* nothing */
#define flush_agp_cache()		mb()

/* Convert a physical address to an address suitable for the GART. */
#ifndef CONFIG_XEN_IA64_DOM0_VP
#define phys_to_gart(x) (x)
#define gart_to_phys(x) (x)
#else
#define phys_to_gart(x) phys_to_machine_for_dma(x)
#define gart_to_phys(x) machine_to_phys_for_dma(x)
#endif

/* GATT allocation. Returns/accepts GATT kernel virtual address. */
#ifndef CONFIG_XEN_IA64_DOM0_VP
#define alloc_gatt_pages(order)		\
	((char *)__get_free_pages(GFP_KERNEL, (order)))
#define free_gatt_pages(table, order)	\
	free_pages((unsigned long)(table), (order))
#else
#include <asm/hypervisor.h>
static inline char*
alloc_gatt_pages(unsigned int order)
{
	unsigned long error;
	unsigned long ret = __get_free_pages(GFP_KERNEL, (order));
	if (ret == 0) {
		goto out;
	}
	error = xen_create_contiguous_region(ret, order, 0);
	if (error) {
		free_pages(ret, order);
		ret = 0;
	}
out:
	return (char*)ret;
}
static inline void
free_gatt_pages(void* table, unsigned int order)
{
	xen_destroy_contiguous_region((unsigned long)table, order);
	free_pages((unsigned long)table, order);
}
#endif /* CONFIG_XEN_IA64_DOM0_VP */

#endif /* _ASM_IA64_AGP_H */
