#ifndef _I386_PGALLOC_H
#define _I386_PGALLOC_H

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/processor.h>
#include <asm/fixmap.h>

#define pgd_quicklist (current_cpu_data.pgd_quick)
#define pmd_quicklist (current_cpu_data.pmd_quick)
#define pte_quicklist (current_cpu_data.pte_quick)
#define pgtable_cache_size (current_cpu_data.pgtable_cache_sz)


/*
 * Allocate and free page tables.
 */


#define pte_free(pte)		pte_free_fast(pte)
#define pgd_alloc(mm)		get_pgd_fast()
#define pgd_free(pgd)		free_pgd_fast(pgd)

/*
 * allocating and freeing a pmd is trivial: the 1-entry pmd is
 * inside the pgd, so has no extra memory associated with it.
 * (In the PAE case we free the pmds as part of the pgd.)
 */

#define pmd_alloc_one_fast(mm, addr)	({ BUG(); ((pmd_t *)1); })
#define pmd_alloc_one(mm, addr)		({ BUG(); ((pmd_t *)2); })
#define pmd_free_slow(x)		do { } while (0)
#define pmd_free_fast(x)		do { } while (0)
#define pmd_free(x)			do { } while (0)
#define pgd_populate(mm, pmd, pte)	BUG()

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP

#define flush_tlb()         __flush_tlb()
#define flush_tlb_all()     __flush_tlb_all()
#define local_flush_tlb()   __flush_tlb()
#define flush_tlb_cpu(_cpu) __flush_tlb()

#else

#include <xeno/smp.h>

#define flush_tlb()	    __flush_tlb()
#define local_flush_tlb()   __flush_tlb()

extern void flush_tlb_all(void);

extern void flush_tlb_others(unsigned long cpumask);
static inline void flush_tlb_cpu(unsigned int cpu)
{
    if ( cpu == smp_processor_id() )
        __flush_tlb();
    else
        flush_tlb_others(1<<cpu);
}

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

struct tlb_state
{
	struct mm_struct *active_mm;
	int state;
};
extern struct tlb_state cpu_tlbstate[NR_CPUS];


#endif

static inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
	/* i386 does not keep any page table caches in TLB */
}

#endif /* _I386_PGALLOC_H */
