#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/cpumask.h>

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
/* XXX lazy implementation just doesn't clear anything.... */
#define tlbflush_filter(mask, page_timestamp)                           \
do {                                                                    \
} while ( 0 )

#define tlbflush_current_time()                 (0)

/* Flush local TLBs, current VMID only */
static inline void flush_tlb_local(void)
{
    dsb();

    WRITE_CP32((uint32_t) 0, TLBIALLIS);

    dsb();
    isb();
}

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_tlb_all_local(void)
{
    dsb();

    WRITE_CP32((uint32_t) 0, TLBIALLNSNHIS);

    dsb();
    isb();
}

/* Flush specified CPUs' TLBs */
void flush_tlb_mask(const cpumask_t *mask);

#endif /* __FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
