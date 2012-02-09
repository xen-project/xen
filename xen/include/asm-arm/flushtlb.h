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

/* Flush local TLBs */
void flush_tlb_local(void);

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
