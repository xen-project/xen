/*
 * Initialize VHPT support.
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/dma.h>
#include <asm/vhpt.h>

unsigned long vhpt_paddr, vhpt_pend, vhpt_pte;

void vhpt_flush(void)
{
	struct vhpt_lf_entry *v = (void *)VHPT_ADDR;
	int i;

	for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++) {
		v->itir = 0;
		v->CChain = 0;
		v->page_flags = 0;
		v->ti_tag = INVALID_TI_TAG;
	}
	// initialize cache too???
}

void vhpt_map(void)
{
	unsigned long psr;

	psr = ia64_clear_ic();
	ia64_itr(0x2, IA64_TR_VHPT, VHPT_ADDR, vhpt_pte, VHPT_SIZE_LOG2);
	ia64_set_psr(psr);
	ia64_srlz_i();
}

void vhpt_init(void)
{
	unsigned long vhpt_total_size, vhpt_alignment, vhpt_imva;
#if !VHPT_ENABLED
	return;
#endif
	// allocate a huge chunk of physical memory.... how???
	vhpt_total_size = 1 << VHPT_SIZE_LOG2;	// 4MB, 16MB, 64MB, or 256MB
	vhpt_alignment = 1 << VHPT_SIZE_LOG2;	// 4MB, 16MB, 64MB, or 256MB
	printf("vhpt_init: vhpt size=%p, align=%p\n",vhpt_total_size,vhpt_alignment);
	/* This allocation only holds true if vhpt table is unique for
	 * all domains. Or else later new vhpt table should be allocated
	 * from domain heap when each domain is created. Assume xen buddy
	 * allocator can provide natural aligned page by order?
	 */
	vhpt_imva = alloc_xenheap_pages(VHPT_SIZE_LOG2 - PAGE_SHIFT);
	if (!vhpt_imva) {
		printf("vhpt_init: can't allocate VHPT!\n");
		while(1);
	}
	vhpt_paddr = __pa(vhpt_imva);
	vhpt_pend = vhpt_paddr + vhpt_total_size - 1;
	printf("vhpt_init: vhpt paddr=%p, end=%p\n",vhpt_paddr,vhpt_pend);
	vhpt_pte = pte_val(pfn_pte(vhpt_paddr >> PAGE_SHIFT, PAGE_KERNEL));
	vhpt_map();
	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
		VHPT_ENABLED);
	vhpt_flush();
}

