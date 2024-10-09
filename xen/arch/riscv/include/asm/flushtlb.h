/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__FLUSHTLB_H
#define ASM__RISCV__FLUSHTLB_H

#include <xen/bug.h>
#include <xen/cpumask.h>

#include <asm/sbi.h>

/* Flush TLB of local processor for address va. */
static inline void flush_tlb_one_local(vaddr_t va)
{
    asm volatile ( "sfence.vma %0" :: "r" (va) : "memory" );
}

/* Flush a range of VA's hypervisor mappings from the TLB of all processors. */
static inline void flush_tlb_range_va(vaddr_t va, size_t size)
{
    BUG_ON(!sbi_has_rfence());
    sbi_remote_sfence_vma(NULL, va, size);
}

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

#endif /* ASM__RISCV__FLUSHTLB_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
