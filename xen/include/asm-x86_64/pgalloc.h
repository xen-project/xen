#ifndef _X86_64_PGALLOC_H
#define _X86_64_PGALLOC_H

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/processor.h>
#include <asm/fixmap.h>

/* XXX probably should be moved to flushtlb.h */

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 */

#ifndef CONFIG_SMP

#define flush_tlb()               __flush_tlb()
#define flush_tlb_all()           __flush_tlb()
#define flush_tlb_all_pge()       __flush_tlb_pge()
#define local_flush_tlb()         __flush_tlb()
#define flush_tlb_cpu(_cpu)       __flush_tlb()
#define flush_tlb_mask(_mask)     __flush_tlb()
#define try_flush_tlb_mask(_mask) __flush_tlb()

#else
#include <xeno/smp.h>

extern int try_flush_tlb_mask(unsigned long mask);
extern void flush_tlb_mask(unsigned long mask);
extern void flush_tlb_all_pge(void);

#define flush_tlb()	    __flush_tlb()
#define flush_tlb_all()     flush_tlb_mask((1 << smp_num_cpus) - 1)
#define local_flush_tlb()   __flush_tlb()
#define flush_tlb_cpu(_cpu) flush_tlb_mask(1 << (_cpu))

#endif

#endif /* _X86_64_PGALLOC_H */
