/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_FLUSHTLB_H__
#define __ASM_PPC_FLUSHTLB_H__

#include <xen/cpumask.h>

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
/* XXX lazy implementation just doesn't clear anything.... */
static inline void tlbflush_filter(cpumask_t *mask, uint32_t page_timestamp) {}

#define tlbflush_current_time()                 (0)

static inline void page_set_tlbflush_timestamp(struct page_info *page)
{
    page->tlbflush_timestamp = tlbflush_current_time();
}

/* Flush specified CPUs' TLBs */
void arch_flush_tlb_mask(const cpumask_t *mask);

#endif /* __ASM_PPC_FLUSHTLB_H__ */
