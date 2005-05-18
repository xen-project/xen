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
#ifdef CONFIG_VTI
unsigned long *mpt_table;
unsigned long *mpt_table_size;
#endif

void
paging_init (void)
{
	struct pfn_info *pg;

#ifdef CONFIG_VTI
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
	memset(mpt_table, 0x55, mpt_table_size);

	/* Any more setup here? On VMX enabled platform,
	 * there's no need to keep guest linear pg table,
	 * and read only mpt table. MAP cache is not used
	 * in this stage, and later it will be in region 5.
	 * IO remap is in region 6 with identity mapping.
	 */
	/* HV_tlb_init(); */

#else // CONFIG_VTI

	/* Allocate and map the machine-to-phys table */
	if ((pg = alloc_domheap_pages(NULL, 10)) == NULL)
		panic("Not enough memory to bootstrap Xen.\n");
	memset(page_to_virt(pg), 0x55, 16UL << 20);
#endif // CONFIG_VTI

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
