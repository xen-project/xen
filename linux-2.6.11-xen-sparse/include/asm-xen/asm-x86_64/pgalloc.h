#ifndef _X86_64_PGALLOC_H
#define _X86_64_PGALLOC_H

#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/pda.h>
#include <linux/threads.h>
#include <linux/mm.h>
#include <asm/io.h>		/* for phys_to_virt and page_to_pseudophys */

void make_page_readonly(void *va);
void make_page_writable(void *va);
void make_pages_readonly(void *va, unsigned int nr);
void make_pages_writable(void *va, unsigned int nr);

#define __user_pgd(pgd) ((pgd) + PTRS_PER_PGD)

static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	set_pmd(pmd, __pmd(_PAGE_TABLE | __pa(pte)));
        flush_page_update_queue();
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd, struct page *pte)
{
	set_pmd(pmd, __pmd(_PAGE_TABLE | (page_to_pfn(pte) << PAGE_SHIFT)));
        flush_page_update_queue();
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	set_pud(pud, __pud(_PAGE_TABLE | __pa(pmd)));
        flush_page_update_queue();
}

/*
 * We need to use the batch mode here, but pgd_pupulate() won't be
 * be called frequently.
 */
static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
        set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
        set_pgd(__user_pgd(pgd), __pgd(_PAGE_TABLE | __pa(pud)));
        flush_page_update_queue();
}

extern __inline__ pmd_t *get_pmd(void)
{
        pmd_t *pmd = (pmd_t *)get_zeroed_page(GFP_KERNEL);
        if (!pmd)
		return NULL;
        make_page_readonly(pmd);
        xen_pmd_pin(__pa(pmd));
        flush_page_update_queue();        
	return pmd;
}

extern __inline__ void pmd_free(pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
        xen_pmd_unpin(__pa(pmd));
        make_page_writable(pmd);
        flush_page_update_queue();
	free_page((unsigned long)pmd);
}

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
        pmd_t *pmd = (pmd_t *) get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
        if (!pmd)
		return NULL;
        make_page_readonly(pmd);
        xen_pmd_pin(__pa(pmd)); 
        flush_page_update_queue(); 
        return pmd;
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
        pud_t *pud = (pud_t *) get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
        if (!pud)
		return NULL;
        make_page_readonly(pud);
        xen_pud_pin(__pa(pud)); 
        flush_page_update_queue(); 
        return pud;
}

static inline void pud_free(pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
        xen_pud_unpin(__pa(pud));
        make_page_writable(pud);
	flush_page_update_queue(); 
	free_page((unsigned long)pud);
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
        /*
         * We allocate two contiguous pages for kernel and user.
         */
        unsigned boundary;
	pgd_t *pgd = (pgd_t *)__get_free_pages(GFP_KERNEL|__GFP_REPEAT, 1);

	if (!pgd)
		return NULL;
	/*
	 * Copy kernel pointers in from init.
	 * Could keep a freelist or slab cache of those because the kernel
	 * part never changes.
	 */
	boundary = pgd_index(__PAGE_OFFSET);
	memset(pgd, 0, boundary * sizeof(pgd_t));
	memcpy(pgd + boundary,
	       init_level4_pgt + boundary,
	       (PTRS_PER_PGD - boundary) * sizeof(pgd_t));

	memset(__user_pgd(pgd), 0, PAGE_SIZE); /* clean up user pgd */
        make_pages_readonly(pgd, 2);

        xen_pgd_pin(__pa(pgd)); /* kernel */
        xen_pgd_pin(__pa(__user_pgd(pgd))); /* user */
        /*
         * Set level3_user_pgt for vsyscall area
         */
	set_pgd(__user_pgd(pgd) + pgd_index(VSYSCALL_START), 
                mk_kernel_pgd(__pa_symbol(level3_user_pgt)));
        flush_page_update_queue();
	return pgd;
}

static inline void pgd_free(pgd_t *pgd)
{
	BUG_ON((unsigned long)pgd & (PAGE_SIZE-1));
        xen_pgd_unpin(__pa(pgd));
        xen_pgd_unpin(__pa(__user_pgd(pgd)));
        make_pages_writable(pgd, 2);
	flush_page_update_queue(); 
	free_pages((unsigned long)pgd, 1);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
        pte_t *pte = (pte_t *)get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
        if (!pte)
		return NULL;
        make_page_readonly(pte);
        xen_pte_pin(__pa(pte));
	flush_page_update_queue(); 
	return pte;
}

static inline struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	pte_t *pte = (void *)get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
	if (!pte)
		return NULL;
        make_page_readonly(pte);
        xen_pte_pin(__pa(pte));
	flush_page_update_queue(); 
	return virt_to_page((unsigned long)pte);
}

/* Should really implement gc for free page table pages. This could be
   done with a reference count in struct page. */

extern __inline__ void pte_free_kernel(pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
        xen_pte_unpin(__pa(pte));
        make_page_writable(pte);
	flush_page_update_queue(); 
	free_page((unsigned long)pte); 
}

extern void pte_free(struct page *pte);

//#define __pte_free_tlb(tlb,pte) tlb_remove_page((tlb),(pte)) 

#define __pte_free_tlb(tlb,x)   pte_free((x))
#define __pmd_free_tlb(tlb,x)   pmd_free((x))
#define __pud_free_tlb(tlb,x)   pud_free((x))

#endif /* _X86_64_PGALLOC_H */
