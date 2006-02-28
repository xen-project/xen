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
#include <xen/mm.h>

extern struct page *zero_page_memmap_ptr;
struct page_info *frame_table;
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
unsigned long *mpt_table;
unsigned long mpt_table_size;

void
paging_init (void)
{
	unsigned int mpt_order;
	/* Create machine to physical mapping table
	 * NOTE: similar to frame table, later we may need virtually
	 * mapped mpt table if large hole exists. Also MAX_ORDER needs
	 * to be changed in common code, which only support 16M by far
	 */
	mpt_table_size = max_page * sizeof(unsigned long);
	mpt_order = get_order(mpt_table_size);
	ASSERT(mpt_order <= MAX_ORDER);
	if ((mpt_table = alloc_xenheap_pages(mpt_order)) == NULL)
		panic("Not enough memory to bootstrap Xen.\n");

	printk("machine to physical table: 0x%lx\n", (u64)mpt_table);
	memset(mpt_table, INVALID_M2P_ENTRY, mpt_table_size);
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
	unsigned long pfn;
	frame_table_size = max_page * sizeof(struct page_info);
	frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

	/* Request continuous trunk from boot allocator, since HV
	 * address is identity mapped */
	pfn = alloc_boot_pages(
            frame_table_size >> PAGE_SHIFT, FT_ALIGN_SIZE >> PAGE_SHIFT);
	if (pfn == 0)
		panic("Not enough memory for frame table.\n");

	frame_table = __va(pfn << PAGE_SHIFT);
	memset(frame_table, 0, frame_table_size);
	printk("size of frame_table: %lukB\n",
		frame_table_size >> 10);
}
#endif
