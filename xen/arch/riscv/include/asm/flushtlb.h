/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_FLUSHTLB_H__
#define __ASM_RISCV_FLUSHTLB_H__

#include <xen/bug.h>
#include <xen/cpumask.h>

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
/* XXX lazy implementation just doesn't clear anything.... */
static inline void tlbflush_filter(cpumask_t *mask, uint32_t page_timestamp) {}

#define tlbflush_current_time() (0)

static inline void page_set_tlbflush_timestamp(struct page_info *page)
{
    BUG_ON("unimplemented");
}

/* Flush specified CPUs' TLBs */
void arch_flush_tlb_mask(const cpumask_t *mask);

#endif /* __ASM_RISCV_FLUSHTLB_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
