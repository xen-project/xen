#ifndef _I386_PGALLOC_H
#define _I386_PGALLOC_H

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/hypervisor.h>
#include <asm/fixmap.h>
#include <linux/threads.h>

#define pgd_quicklist (current_cpu_data.pgd_quick)
#define pmd_quicklist (current_cpu_data.pmd_quick)
#define pte_quicklist (current_cpu_data.pte_quick)
#define pgtable_cache_size (current_cpu_data.pgtable_cache_sz)

#define pmd_populate(mm, pmd, pte) \
 set_pmd(pmd, __pmd(_PAGE_TABLE + __pa(pte)))

static __inline__ pgd_t *get_pgd_slow(void)
{
    pgd_t *pgd = (pgd_t *)__get_free_page(GFP_KERNEL);
    pgd_t *kpgd;
    pmd_t *kpmd;
    pte_t *kpte;

    if (pgd) {
        memset(pgd, 0, USER_PTRS_PER_PGD * sizeof(pgd_t));
        memcpy(pgd + USER_PTRS_PER_PGD, 
               init_mm.pgd + USER_PTRS_PER_PGD, 
               (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
        kpgd = pgd_offset_k((unsigned long)pgd);
        kpmd = pmd_offset(kpgd, (unsigned long)pgd);
        kpte = pte_offset(kpmd, (unsigned long)pgd);
        queue_l1_entry_update(__pa(kpte), (*(unsigned long *)kpte)&~_PAGE_RW);
        queue_baseptr_create(__pa(pgd));
    }

    return pgd;
}

#if 0
static __inline__ pgd_t *get_pgd_fast(void)
{
    unsigned long *ret;

    if ((ret = pgd_quicklist) != NULL) {
        pgd_quicklist = (unsigned long *)(*ret);
        ret[0] = 0;
        pgtable_cache_size--;
    } else
        ret = (unsigned long *)get_pgd_slow();
    return (pgd_t *)ret;
}

static __inline__ void free_pgd_fast(pgd_t *pgd)
{
    *(unsigned long *)pgd = (unsigned long) pgd_quicklist;
    pgd_quicklist = (unsigned long *) pgd;
    pgtable_cache_size++;
}
#else
#define get_pgd_fast get_pgd_slow
#define free_pgd_fast free_pgd_slow
#endif

static __inline__ void free_pgd_slow(pgd_t *pgd)
{
    pgd_t *kpgd;
    pmd_t *kpmd;
    pte_t *kpte;
    queue_baseptr_remove(__pa(pgd));
    kpgd = pgd_offset_k((unsigned long)pgd);
    kpmd = pmd_offset(kpgd, (unsigned long)pgd);
    kpte = pte_offset(kpmd, (unsigned long)pgd);
    queue_l1_entry_update(__pa(kpte), (*(unsigned long *)kpte)|_PAGE_RW);
    free_page((unsigned long)pgd);
}

static inline pte_t *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
    pte_t *pte;
    pgd_t *kpgd;
    pmd_t *kpmd;
    pte_t *kpte;

    pte = (pte_t *) __get_free_page(GFP_KERNEL);
    if (pte)
    {
        clear_page(pte);
        kpgd = pgd_offset_k((unsigned long)pte);
        kpmd = pmd_offset(kpgd, (unsigned long)pte);
        kpte = pte_offset(kpmd, (unsigned long)pte);
        queue_l1_entry_update(__pa(kpte), (*(unsigned long *)kpte)&~_PAGE_RW);
    }
    return pte;
}

#if 0
static inline pte_t *pte_alloc_one_fast(struct mm_struct *mm, unsigned long address)
{
    unsigned long *ret;

    if ((ret = (unsigned long *)pte_quicklist) != NULL) {
        pte_quicklist = (unsigned long *)(*ret);
        ret[0] = ret[1];
        pgtable_cache_size--;
    }
    return (pte_t *)ret;
}

static __inline__ void pte_free_fast(pte_t *pte)
{
    *(unsigned long *)pte = (unsigned long) pte_quicklist;
    pte_quicklist = (unsigned long *) pte;
    pgtable_cache_size++;
}
#else
#define pte_alloc_one_fast pte_alloc_one
#define pte_free_fast pte_free_slow
#endif

static __inline__ void pte_free_slow(pte_t *pte)
{
    pgd_t *kpgd;
    pmd_t *kpmd;
    pte_t *kpte;
    kpgd = pgd_offset_k((unsigned long)pte);
    kpmd = pmd_offset(kpgd, (unsigned long)pte);
    kpte = pte_offset(kpmd, (unsigned long)pte);
    queue_l1_entry_update(__pa(kpte), (*(unsigned long *)kpte)|_PAGE_RW);
    free_page((unsigned long)pte);
}

#define pte_free(pte)		pte_free_fast(pte)
#define pgd_alloc(mm)		get_pgd_fast()
#define pgd_free(pgd)		free_pgd_fast(pgd)

#define pmd_alloc_one_fast(mm, addr)	({ BUG(); ((pmd_t *)1); })
#define pmd_alloc_one(mm, addr)		({ BUG(); ((pmd_t *)2); })
#define pmd_free_slow(x)		do { } while (0)
#define pmd_free_fast(x)		do { } while (0)
#define pmd_free(x)			do { } while (0)
#define pgd_populate(mm, pmd, pte)	BUG()

extern int do_check_pgt_cache(int, int);

/*
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 */

#define flush_tlb() __flush_tlb()
#define flush_tlb_all() __flush_tlb_all()
#define local_flush_tlb() __flush_tlb()

static inline void flush_tlb_mm(struct mm_struct *mm)
{
    if (mm == current->active_mm)
        __flush_tlb();
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
                                  unsigned long addr)
{
    if (vma->vm_mm == current->active_mm)
        __flush_tlb_one(addr);
}

static inline void flush_tlb_range(struct mm_struct *mm,
                                   unsigned long start, unsigned long end)
{
    if (mm == current->active_mm)
        __flush_tlb();
}

static inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
    /* i386 does not keep any page table caches in TLB */
}

#endif /* _I386_PGALLOC_H */
