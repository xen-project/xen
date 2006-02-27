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
	int i, cnt = 0;
#if 0
static int firsttime = 2;

if (firsttime) firsttime--;
else {
printf("vhpt_flush: *********************************************\n");
printf("vhpt_flush: *********************************************\n");
printf("vhpt_flush: *********************************************\n");
printf("vhpt_flush: flushing vhpt (seems to crash at rid wrap?)...\n");
printf("vhpt_flush: *********************************************\n");
printf("vhpt_flush: *********************************************\n");
printf("vhpt_flush: *********************************************\n");
}
#endif
	for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++) {
		v->itir = 0;
		v->CChain = 0;
		v->page_flags = 0;
		v->ti_tag = INVALID_TI_TAG;
	}
	// initialize cache too???
}

#ifdef VHPT_GLOBAL
void vhpt_flush_address(unsigned long vadr, unsigned long addr_range)
{
	unsigned long ps;
	struct vhpt_lf_entry *vlfe;

	if ((vadr >> 61) == 7) {
		// no vhpt for region 7 yet, see vcpu_itc_no_srlz
		printf("vhpt_flush_address: region 7, spinning...\n");
		while(1);
	}
#if 0
	// this only seems to occur at shutdown, but it does occur
	if ((!addr_range) || addr_range & (addr_range - 1)) {
		printf("vhpt_flush_address: weird range, spinning...\n");
		while(1);
	}
//printf("************** vhpt_flush_address(%p,%p)\n",vadr,addr_range);
#endif
	while ((long)addr_range > 0) {
		vlfe = (struct vhpt_lf_entry *)ia64_thash(vadr);
		// FIXME: for now, just blow it away even if it belongs to
		// another domain.  Later, use ttag to check for match
//if (!(vlfe->ti_tag & INVALID_TI_TAG)) {
//printf("vhpt_flush_address: blowing away valid tag for vadr=%p\n",vadr);
//}
		vlfe->ti_tag |= INVALID_TI_TAG;
		addr_range -= PAGE_SIZE;
		vadr += PAGE_SIZE;
	}
}
#endif

void vhpt_map(void)
{
	unsigned long psr;

	psr = ia64_clear_ic();
	ia64_itr(0x2, IA64_TR_VHPT, VHPT_ADDR, vhpt_pte, VHPT_SIZE_LOG2);
	ia64_set_psr(psr);
	ia64_srlz_i();
}

void vhpt_multiple_insert(unsigned long vaddr, unsigned long pte, unsigned long logps)
{
	unsigned long mask = (1L << logps) - 1;
	extern long running_on_sim;
	int i;

	if (logps-PAGE_SHIFT > 10 && !running_on_sim) {
		// if this happens, we may want to revisit this algorithm
		printf("vhpt_multiple_insert:logps-PAGE_SHIFT>10,spinning..\n");
		while(1);
	}
	if (logps-PAGE_SHIFT > 2) {
		// FIXME: Should add counter here to see how often this
		//  happens (e.g. for 16MB pages!) and determine if it
		//  is a performance problem.  On a quick look, it takes
		//  about 39000 instrs for a 16MB page and it seems to occur
		//  only a few times/second, so OK for now.
		//  An alternate solution would be to just insert the one
		//  16KB in the vhpt (but with the full mapping)?
		//printf("vhpt_multiple_insert: logps-PAGE_SHIFT==%d,"
			//"va=%p, pa=%p, pa-masked=%p\n",
			//logps-PAGE_SHIFT,vaddr,pte&_PFN_MASK,
			//(pte&_PFN_MASK)&~mask);
	}
	vaddr &= ~mask;
	pte = ((pte & _PFN_MASK) & ~mask) | (pte & ~_PFN_MASK);
	for (i = 1L << (logps-PAGE_SHIFT); i > 0; i--) {
		vhpt_insert(vaddr,pte,logps<<2);
		vaddr += PAGE_SIZE;
	}
}

void vhpt_init(void)
{
	unsigned long vhpt_total_size, vhpt_alignment;
	struct page_info *page;
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
//	vhpt_imva = alloc_xenheap_pages(VHPT_SIZE_LOG2 - PAGE_SHIFT);
	page = alloc_domheap_pages(NULL, VHPT_SIZE_LOG2 - PAGE_SHIFT, 0);
	if (!page) {
		printf("vhpt_init: can't allocate VHPT!\n");
		while(1);
	}
	vhpt_paddr = page_to_maddr(page);
	vhpt_pend = vhpt_paddr + vhpt_total_size - 1;
	printf("vhpt_init: vhpt paddr=%p, end=%p\n",vhpt_paddr,vhpt_pend);
	vhpt_pte = pte_val(pfn_pte(vhpt_paddr >> PAGE_SHIFT, PAGE_KERNEL));
	vhpt_map();
	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
		VHPT_ENABLED);
	vhpt_flush();
}


void zero_vhpt_stats(void)
{
	return;
}

int dump_vhpt_stats(char *buf)
{
	int i;
	char *s = buf;
	struct vhpt_lf_entry *v = (void *)VHPT_ADDR;
	unsigned long vhpt_valid = 0, vhpt_chains = 0;

	for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++) {
		if (!(v->ti_tag & INVALID_TI_TAG)) vhpt_valid++;
		if (v->CChain) vhpt_chains++;
	}
	s += sprintf(s,"VHPT usage: %ld/%ld (%ld collision chains)\n",
		vhpt_valid,VHPT_NUM_ENTRIES,vhpt_chains);
	return s - buf;
}
