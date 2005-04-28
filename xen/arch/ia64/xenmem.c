/*
 * Xen memory allocator routines
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 * Copyright (C) 2005 Intel Corp.
 *
 * Routines used by ia64 machines with contiguous (or virtually contiguous)
 * memory.
 */

#include <linux/config.h>
#include <asm/pgtable.h>

extern struct page *zero_page_memmap_ptr;
struct pfn_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;

struct page *mem_map;
#define MAX_DMA_ADDRESS ~0UL	// FIXME???

#ifdef CONFIG_VIRTUAL_MEM_MAP
static unsigned long num_dma_physpages;
#endif

/*
 * Set up the page tables.
 */

void
paging_init (void)
{
	struct pfn_info *pg;
	/* Allocate and map the machine-to-phys table */
	if ((pg = alloc_domheap_pages(NULL, 10)) == NULL)
		panic("Not enough memory to bootstrap Xen.\n");
	memset(page_to_virt(pg), 0x55, 16UL << 20);

	/* Other mapping setup */

	zero_page_memmap_ptr = virt_to_page(ia64_imva(empty_zero_page));
}

/* FIXME: postpone support to machines with big holes between physical memorys.
 * Current hack allows only efi memdesc upto 4G place. (See efi.c)
 */
#ifndef CONFIG_VIRTUAL_MEM_MAP
#define FT_ALIGN_SIZE	(16UL << 20)
void __init init_frametable(void)
{
	unsigned long i, p;
	frame_table_size = max_page * sizeof(struct pfn_info);
	frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

	/* Request continuous trunk from boot allocator, since HV
	 * address is identity mapped */
	p = alloc_boot_pages(frame_table_size, FT_ALIGN_SIZE);
	if (p == 0)
		panic("Not enough memory for frame table.\n");

	frame_table = __va(p);
	memset(frame_table, 0, frame_table_size);
	printk("size of frame_table: %lukB\n",
		frame_table_size >> 10);
}
#endif
