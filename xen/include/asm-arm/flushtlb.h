#ifndef __ASM_ARM_FLUSHTLB_H__
#define __ASM_ARM_FLUSHTLB_H__

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

#if defined(CONFIG_ARM_32)
# include <asm/arm32/flushtlb.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/flushtlb.h>
#else
# error "unknown ARM variant"
#endif

/* Flush specified CPUs' TLBs */
void flush_tlb_mask(const cpumask_t *mask);

#endif /* __ASM_ARM_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
