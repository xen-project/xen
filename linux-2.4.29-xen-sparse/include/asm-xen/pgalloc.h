#ifndef _I386_PGALLOC_H
#define _I386_PGALLOC_H

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/hypervisor.h>
#include <linux/threads.h>

/*
 * Quick lists are aligned so that least significant bits of array pointer
 * are all zero when list is empty, and all one when list is full.
 */
#define QUICKLIST_ENTRIES 256
#define QUICKLIST_EMPTY(_l) !((unsigned long)(_l) & ((QUICKLIST_ENTRIES*4)-1))
#define QUICKLIST_FULL(_l)  QUICKLIST_EMPTY((_l)+1)
#define pgd_quicklist (current_cpu_data.pgd_quick)
#define pmd_quicklist (current_cpu_data.pmd_quick)
#define pte_quicklist (current_cpu_data.pte_quick)
#define pgtable_cache_size (current_cpu_data.pgtable_cache_sz)

#define pmd_populate(mm, pmd, pte) 		  \
 do {                                             \
  set_pmd(pmd, __pmd(_PAGE_TABLE + __pa(pte)));   \
 } while ( 0 )

/*
 * Allocate and free page tables.
 */

#if defined (CONFIG_X86_PAE)

#error "no PAE support as yet"

/*
 * We can't include <linux/slab.h> here, thus these uglinesses.
 */
struct kmem_cache_s;

extern struct kmem_cache_s *pae_pgd_cachep;
extern void *kmem_cache_alloc(struct kmem_cache_s *, int);
extern void kmem_cache_free(struct kmem_cache_s *, void *);


static inline pgd_t *get_pgd_slow(void)
{
	int i;
	pgd_t *pgd = kmem_cache_alloc(pae_pgd_cachep, GFP_KERNEL);

	if (pgd) {
		for (i = 0; i < USER_PTRS_PER_PGD; i++) {
			unsigned long pmd = __get_free_page(GFP_KERNEL);
			if (!pmd)
				goto out_oom;
			clear_page(pmd);
			set_pgd(pgd + i, __pgd(1 + __pa(pmd)));
		}
		memcpy(pgd + USER_PTRS_PER_PGD,
			init_mm.pgd + USER_PTRS_PER_PGD,
			(PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
	}
	return pgd;
out_oom:
	for (i--; i >= 0; i--)
		free_page((unsigned long)__va(pgd_val(pgd[i])-1));
	kmem_cache_free(pae_pgd_cachep, pgd);
	return NULL;
}

#else

static inline pgd_t *get_pgd_slow(void)
{
	pgd_t *pgd = (pgd_t *)__get_free_page(GFP_KERNEL);

	if (pgd) {
		memset(pgd, 0, USER_PTRS_PER_PGD * sizeof(pgd_t));
		memcpy(pgd + USER_PTRS_PER_PGD,
			init_mm.pgd + USER_PTRS_PER_PGD,
			(PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
		__make_page_readonly(pgd);
		queue_pgd_pin(__pa(pgd));
		flush_page_update_queue();
	}
	return pgd;
}

#endif /* CONFIG_X86_PAE */

static inline pgd_t *get_pgd_fast(void)
{
	unsigned long ret;

	if ( !QUICKLIST_EMPTY(pgd_quicklist) ) {
		ret = *(--pgd_quicklist);
		pgtable_cache_size--;

	} else
		ret = (unsigned long)get_pgd_slow();
	return (pgd_t *)ret;
}

static inline void free_pgd_slow(pgd_t *pgd)
{
#if defined(CONFIG_X86_PAE)
#error
	int i;

	for (i = 0; i < USER_PTRS_PER_PGD; i++)
		free_page((unsigned long)__va(pgd_val(pgd[i])-1));
	kmem_cache_free(pae_pgd_cachep, pgd);
#else
	queue_pgd_unpin(__pa(pgd));
	__make_page_writable(pgd);
	flush_page_update_queue();
	free_page((unsigned long)pgd);
#endif
}

static inline void free_pgd_fast(pgd_t *pgd)
{
        if ( !QUICKLIST_FULL(pgd_quicklist) ) {
                *(pgd_quicklist++) = (unsigned long)pgd;
                pgtable_cache_size++;
        } else
                free_pgd_slow(pgd);
}

static inline pte_t *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
    pte_t *pte;

    pte = (pte_t *) __get_free_page(GFP_KERNEL);
    if (pte)
    {
        clear_page(pte);
        __make_page_readonly(pte);
        queue_pte_pin(__pa(pte));
        flush_page_update_queue();
    }
    return pte;

}

static inline pte_t *pte_alloc_one_fast(struct mm_struct *mm,
					unsigned long address)
{
    unsigned long ret = 0;
    if ( !QUICKLIST_EMPTY(pte_quicklist) ) {
        ret = *(--pte_quicklist);
        pgtable_cache_size--;
    }
    return (pte_t *)ret;
}

static __inline__ void pte_free_slow(pte_t *pte)
{
    queue_pte_unpin(__pa(pte));
    __make_page_writable(pte);
    flush_page_update_queue();
    free_page((unsigned long)pte);
}

static inline void pte_free_fast(pte_t *pte)
{
    if ( !QUICKLIST_FULL(pte_quicklist) ) {
        *(pte_quicklist++) = (unsigned long)pte;
        pgtable_cache_size++;
    } else
        pte_free_slow(pte);
}

#define pte_free(pte)		pte_free_fast(pte)
#define pgd_free(pgd)		free_pgd_fast(pgd)
#define pgd_alloc(mm)		get_pgd_fast()

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

extern int do_check_pgt_cache(int, int);

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP

#define flush_tlb() __flush_tlb()
#define flush_tlb_all() __flush_tlb_all()
#define local_flush_tlb() __flush_tlb()

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	if (mm == current->active_mm) xen_tlb_flush();
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
	unsigned long addr)
{
	if (vma->vm_mm == current->active_mm) xen_invlpg(addr);
}

static inline void flush_tlb_range(struct mm_struct *mm,
	unsigned long start, unsigned long end)
{
	if (mm == current->active_mm) xen_tlb_flush();
}

#else
#error no kernel SMP support yet...
#include <asm/smp.h>

#define local_flush_tlb() \
	__flush_tlb()

extern void flush_tlb_all(void);
extern void flush_tlb_current_task(void);
extern void flush_tlb_mm(struct mm_struct *);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);

#define flush_tlb()	flush_tlb_current_task()

static inline void flush_tlb_range(struct mm_struct * mm, unsigned long start, unsigned long end)
{
	flush_tlb_mm(mm);
}

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

struct tlb_state
{
	struct mm_struct *active_mm;
	int state;
} ____cacheline_aligned;
extern struct tlb_state cpu_tlbstate[NR_CPUS];

#endif /* CONFIG_SMP */

static inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
    /* i386 does not keep any page table caches in TLB */
}

/*
 * NB. The 'domid' field should be zero if mapping I/O space (non RAM).
 * Otherwise it identifies the owner of the memory that is being mapped.
 */
extern int direct_remap_area_pages(struct mm_struct *mm,
                                   unsigned long address, 
                                   unsigned long machine_addr,
                                   unsigned long size, 
                                   pgprot_t prot,
                                   domid_t  domid);

extern int __direct_remap_area_pages(struct mm_struct *mm,
				     unsigned long address, 
				     unsigned long size, 
				     mmu_update_t *v);



#endif /* _I386_PGALLOC_H */
