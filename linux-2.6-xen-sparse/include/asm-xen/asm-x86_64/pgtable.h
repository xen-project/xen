#ifndef _X86_64_PGTABLE_H
#define _X86_64_PGTABLE_H

/*
 * This file contains the functions and defines necessary to modify and use
 * the x86-64 page table tree.
 */
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <linux/threads.h>
#include <linux/sched.h>
#include <asm/pda.h>
#ifdef CONFIG_XEN
#include <asm-xen/hypervisor.h>

extern pud_t level3_user_pgt[512];
extern pud_t init_level4_user_pgt[];

extern void xen_init_pt(void);

#define virt_to_ptep(__va)						\
({									\
	pgd_t *__pgd = pgd_offset_k((unsigned long)(__va));		\
	pud_t *__pud = pud_offset(__pgd, (unsigned long)(__va));	\
	pmd_t *__pmd = pmd_offset(__pud, (unsigned long)(__va));	\
	pte_offset_kernel(__pmd, (unsigned long)(__va));		\
})

#define arbitrary_virt_to_machine(__va)					\
({									\
	pte_t *__pte = virt_to_ptep(__va);				\
	unsigned long __pa = (*(unsigned long *)__pte) & PAGE_MASK;	\
	__pa | ((unsigned long)(__va) & (PAGE_SIZE-1));			\
})
#endif

extern pud_t level3_kernel_pgt[512];
extern pud_t level3_physmem_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pgd_t init_level4_pgt[];
extern unsigned long __supported_pte_mask;

#define swapper_pg_dir init_level4_pgt

extern int nonx_setup(char *str);
extern void paging_init(void);
extern void clear_kernel_mapping(unsigned long addr, unsigned long size);

extern unsigned long pgkern_mask;

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long empty_zero_page[PAGE_SIZE/sizeof(unsigned long)];
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT	39
#define PTRS_PER_PGD	512

/*
 * 3rd level page
 */
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %p(%016lx).\n", __FILE__, __LINE__, &(e), pte_val(e))
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %p(%016lx).\n", __FILE__, __LINE__, &(e), pmd_val(e))
#define pud_ERROR(e) \
	printk("%s:%d: bad pud %p(%016lx).\n", __FILE__, __LINE__, &(e), pud_val(e))
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %p(%016lx).\n", __FILE__, __LINE__, &(e), pgd_val(e))

#define pgd_none(x)	(!pgd_val(x))
#define pud_none(x)	(!pud_val(x))

#define set_pte_batched(pteptr, pteval) \
	queue_l1_entry_update(pteptr, (pteval))

extern inline int pud_present(pud_t pud)	{ return !pud_none(pud); }

static inline void set_pte(pte_t *dst, pte_t val)
{
	*dst = val;
}

#define set_pmd(pmdptr, pmdval) xen_l2_entry_update(pmdptr, (pmdval))
#define set_pud(pudptr, pudval) xen_l3_entry_update(pudptr, (pudval))
#define set_pgd(pgdptr, pgdval) xen_l4_entry_update(pgdptr, (pgdval))

extern inline void pud_clear (pud_t * pud)
{
	set_pud(pud, __pud(0));
}

#define __user_pgd(pgd) ((pgd) + PTRS_PER_PGD)

extern inline void pgd_clear (pgd_t * pgd)
{
        set_pgd(pgd, __pgd(0));
        set_pgd(__user_pgd(pgd), __pgd(0));
}

#define pud_page(pud) \
    ((unsigned long) __va(pud_val(pud) & PHYSICAL_PAGE_MASK))

/*
 * A note on implementation of this atomic 'get-and-clear' operation.
 * This is actually very simple because Xen Linux can only run on a single
 * processor. Therefore, we cannot race other processors setting the 'accessed'
 * or 'dirty' bits on a page-table entry.
 * Even if pages are shared between domains, that is not a problem because
 * each domain will have separate page tables, with their own versions of
 * accessed & dirty state.
 */
#define ptep_get_and_clear(mm,addr,xp)	__pte_ma(xchg(&(xp)->pte, 0))

#if 0
static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *xp)
{
        pte_t pte = *xp;
        if (pte.pte)
                set_pte(xp, __pte_ma(0));
        return pte;
}
#endif

#define pte_same(a, b)		((a).pte == (b).pte)

#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

#define USER_PTRS_PER_PGD	(TASK_SIZE/PGDIR_SIZE)
#define FIRST_USER_ADDRESS	0

#ifndef __ASSEMBLY__
#define MAXMEM		 0x3fffffffffffUL
#define VMALLOC_START    0xffffc20000000000UL
#define VMALLOC_END      0xffffe1ffffffffffUL
#define MODULES_VADDR    0xffffffff88000000UL
#define MODULES_END      0xfffffffffff00000UL
#define MODULES_LEN   (MODULES_END - MODULES_VADDR)

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_RW		1
#define _PAGE_BIT_USER		2
#define _PAGE_BIT_PWT		3
#define _PAGE_BIT_PCD		4
#define _PAGE_BIT_ACCESSED	5
#define _PAGE_BIT_DIRTY		6
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_NX           63       /* No execute: only valid after cpuid check */

#define _PAGE_PRESENT	0x001
#define _PAGE_RW	0x002
#define _PAGE_USER	0x004
#define _PAGE_PWT	0x008
#define _PAGE_PCD	0x010
#define _PAGE_ACCESSED	0x020
#define _PAGE_DIRTY	0x040
#define _PAGE_PSE	0x080	/* 2MB page */
#define _PAGE_FILE	0x040	/* set:pagecache, unset:swap */
#define _PAGE_GLOBAL	0x100	/* Global TLB entry */

#define _PAGE_PROTNONE	0x080	/* If not present */
#define _PAGE_NX        (1UL<<_PAGE_BIT_NX)

#define _PAGE_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _KERNPG_TABLE	_PAGE_TABLE

#define _PAGE_CHG_MASK	(PTE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_NONE	__pgprot(_PAGE_PROTNONE | _PAGE_ACCESSED)
#define PAGE_SHARED	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_SHARED_EXEC __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY_NOEXEC __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_COPY PAGE_COPY_NOEXEC
#define PAGE_COPY_EXEC __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_READONLY	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_READONLY_EXEC __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define __PAGE_KERNEL \
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_NX | _PAGE_USER )
#define __PAGE_KERNEL_EXEC \
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER )
#define __PAGE_KERNEL_NOCACHE \
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_PCD | _PAGE_ACCESSED | _PAGE_NX | _PAGE_USER )
#define __PAGE_KERNEL_RO \
	(_PAGE_PRESENT | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_NX | _PAGE_USER )
#define __PAGE_KERNEL_VSYSCALL \
	(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_USER )
#define __PAGE_KERNEL_VSYSCALL_NOCACHE \
	(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_PCD | _PAGE_USER )
#define __PAGE_KERNEL_LARGE \
	(__PAGE_KERNEL | _PAGE_PSE | _PAGE_USER )


/*
 * We don't support GLOBAL page in xenolinux64
 */
#define MAKE_GLOBAL(x) __pgprot((x))

#define PAGE_KERNEL MAKE_GLOBAL(__PAGE_KERNEL)
#define PAGE_KERNEL_EXEC MAKE_GLOBAL(__PAGE_KERNEL_EXEC)
#define PAGE_KERNEL_RO MAKE_GLOBAL(__PAGE_KERNEL_RO)
#define PAGE_KERNEL_NOCACHE MAKE_GLOBAL(__PAGE_KERNEL_NOCACHE)
#define PAGE_KERNEL_VSYSCALL32 __pgprot(__PAGE_KERNEL_VSYSCALL)
#define PAGE_KERNEL_VSYSCALL MAKE_GLOBAL(__PAGE_KERNEL_VSYSCALL)
#define PAGE_KERNEL_LARGE MAKE_GLOBAL(__PAGE_KERNEL_LARGE)
#define PAGE_KERNEL_VSYSCALL_NOCACHE MAKE_GLOBAL(__PAGE_KERNEL_VSYSCALL_NOCACHE)

/*         xwr */
#define __P000	PAGE_NONE
#define __P001	PAGE_READONLY
#define __P010	PAGE_COPY
#define __P011	PAGE_COPY
#define __P100	PAGE_READONLY_EXEC
#define __P101	PAGE_READONLY_EXEC
#define __P110	PAGE_COPY_EXEC
#define __P111	PAGE_COPY_EXEC

#define __S000	PAGE_NONE
#define __S001	PAGE_READONLY
#define __S010	PAGE_SHARED
#define __S011	PAGE_SHARED
#define __S100	PAGE_READONLY_EXEC
#define __S101	PAGE_READONLY_EXEC
#define __S110	PAGE_SHARED_EXEC
#define __S111	PAGE_SHARED_EXEC

static inline unsigned long pgd_bad(pgd_t pgd)
{
       unsigned long val = pgd_val(pgd);
       val &= ~PTE_MASK;
       val &= ~(_PAGE_USER | _PAGE_DIRTY);
       return val & ~(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED);
}

static inline unsigned long pud_bad(pud_t pud) 
{ 
       unsigned long val = pud_val(pud);
       val &= ~PTE_MASK; 
       val &= ~(_PAGE_USER | _PAGE_DIRTY); 
       return val & ~(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED);      
} 

inline static void set_pte_at(struct mm_struct *mm, unsigned long addr, 
		       pte_t *ptep, pte_t val )
{
    if ( ((mm != current->mm) && (mm != &init_mm)) ||
	 HYPERVISOR_update_va_mapping( (addr), (val), 0 ) )
    {
        set_pte(ptep, val);
    }
}

#define pte_none(x)	(!(x).pte)
#define pte_present(x)	((x).pte & (_PAGE_PRESENT | _PAGE_PROTNONE))
#define pte_clear(mm,addr,xp)	do { set_pte_at(mm, addr, xp, __pte(0)); } while (0)

#define pages_to_mb(x) ((x) >> (20-PAGE_SHIFT))

/*
 * We detect special mappings in one of two ways:
 *  1. If the MFN is an I/O page then Xen will set the m2p entry
 *     to be outside our maximum possible pseudophys range.
 *  2. If the MFN belongs to a different domain then we will certainly
 *     not have MFN in our p2m table. Conversely, if the page is ours,
 *     then we'll have p2m(m2p(MFN))==MFN.
 * If we detect a special mapping then it doesn't have a 'struct page'.
 * We force !pfn_valid() by returning an out-of-range pointer.
 *
 * NB. These checks require that, for any MFN that is not in our reservation,
 * there is no PFN such that p2m(PFN) == MFN. Otherwise we can get confused if
 * we are foreign-mapping the MFN, and the other domain as m2p(MFN) == PFN.
 * Yikes! Various places must poke in INVALID_P2M_ENTRY for safety.
 * 
 * NB2. When deliberately mapping foreign pages into the p2m table, you *must*
 *      use FOREIGN_FRAME(). This will cause pte_pfn() to choke on it, as we
 *      require. In all the cases we care about, the FOREIGN_FRAME bit is
 *      masked (e.g., pfn_to_mfn()) so behaviour there is correct.
 */
#define pte_mfn(_pte) (((_pte).pte & PTE_MASK) >> PAGE_SHIFT)
#define pte_pfn(_pte)							\
({									\
	unsigned long mfn = pte_mfn(_pte);                              \
	unsigned long pfn = mfn_to_pfn(mfn);                            \
	if ((pfn >= max_mapnr) || (phys_to_machine_mapping[pfn] != mfn))\
		pfn = max_mapnr; /* special: force !pfn_valid() */	\
	pfn;								\
})

#define pte_page(x)	pfn_to_page(pte_pfn(x))

static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	pte_t pte;
        
	(pte).pte = (pfn_to_mfn(page_nr) << PAGE_SHIFT);
	(pte).pte |= pgprot_val(pgprot);
	(pte).pte &= __supported_pte_mask;
	return pte;
}

#define pfn_pte_ma(pfn, prot)	__pte_ma((((pfn) << PAGE_SHIFT) | pgprot_val(prot)) & __supported_pte_mask)
/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
#define __pte_val(x)	((x).pte)

static inline int pte_user(pte_t pte)		{ return __pte_val(pte) & _PAGE_USER; }
extern inline int pte_read(pte_t pte)		{ return __pte_val(pte) & _PAGE_USER; }
extern inline int pte_exec(pte_t pte)		{ return __pte_val(pte) & _PAGE_USER; }
extern inline int pte_dirty(pte_t pte)		{ return __pte_val(pte) & _PAGE_DIRTY; }
extern inline int pte_young(pte_t pte)		{ return __pte_val(pte) & _PAGE_ACCESSED; }
extern inline int pte_write(pte_t pte)		{ return __pte_val(pte) & _PAGE_RW; }
static inline int pte_file(pte_t pte)		{ return __pte_val(pte) & _PAGE_FILE; }

extern inline pte_t pte_rdprotect(pte_t pte)	{ __pte_val(pte) &= ~_PAGE_USER; return pte; }
extern inline pte_t pte_exprotect(pte_t pte)	{ __pte_val(pte) &= ~_PAGE_USER; return pte; }
extern inline pte_t pte_mkclean(pte_t pte)	{ __pte_val(pte) &= ~_PAGE_DIRTY; return pte; }
extern inline pte_t pte_mkold(pte_t pte)	{ __pte_val(pte) &= ~_PAGE_ACCESSED; return pte; }
extern inline pte_t pte_wrprotect(pte_t pte)	{ __pte_val(pte) &= ~_PAGE_RW; return pte; }
extern inline pte_t pte_mkread(pte_t pte)	{ __pte_val(pte) |= _PAGE_USER; return pte; }
extern inline pte_t pte_mkexec(pte_t pte)	{ __pte_val(pte) |= _PAGE_USER; return pte; }
extern inline pte_t pte_mkdirty(pte_t pte)	{ __pte_val(pte) |= _PAGE_DIRTY; return pte; }
extern inline pte_t pte_mkyoung(pte_t pte)	{ __pte_val(pte) |= _PAGE_ACCESSED; return pte; }
extern inline pte_t pte_mkwrite(pte_t pte)	{ __pte_val(pte) |= _PAGE_RW; return pte; }

struct vm_area_struct;

static inline int ptep_test_and_clear_dirty(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	int ret = pte_dirty(pte);
	if (ret)
		set_pte(ptep, pte_mkclean(pte));
	return ret;
}

static inline int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	int ret = pte_young(pte);
	if (ret)
		set_pte(ptep, pte_mkold(pte));
	return ret;
}

static inline void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	if (pte_write(pte))
		set_pte(ptep, pte_wrprotect(pte));
}

/*
 * Macro to mark a page protection value as "uncacheable".
 */
#define pgprot_noncached(prot)	(__pgprot(pgprot_val(prot) | _PAGE_PCD | _PAGE_PWT))

#define __LARGE_PTE (_PAGE_PSE|_PAGE_PRESENT) 
static inline int pmd_large(pmd_t pte) { 
	return (pmd_val(pte) & __LARGE_PTE) == __LARGE_PTE; 
} 	


/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */

#define page_pte(page) page_pte_prot(page, __pgprot(0))

/*
 * Level 4 access.
 * Never use these in the common code.
 */
#define pgd_page(pgd) ((unsigned long) __va(pgd_val(pgd) & PTE_MASK))
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD-1))
#define pgd_offset(mm, addr) ((mm)->pgd + pgd_index(addr))
#define pgd_offset_k(address) (pgd_t *)(init_level4_pgt + pgd_index(address))
#define pgd_present(pgd) (pgd_val(pgd) & _PAGE_PRESENT)
#define mk_kernel_pgd(address) __pgd((address) | _KERNPG_TABLE)

/* PUD - Level3 access */
/* to find an entry in a page-table-directory. */
#define pud_index(address) (((address) >> PUD_SHIFT) & (PTRS_PER_PUD-1))
#define pud_offset(pgd, address) ((pud_t *) pgd_page(*(pgd)) + pud_index(address))
static inline pud_t *__pud_offset_k(pud_t *pud, unsigned long address)
{ 
	return pud + pud_index(address);
} 

/* Find correct pud via the hidden fourth level page level: */

/* This accesses the reference page table of the boot cpu. 
   Other CPUs get synced lazily via the page fault handler. */
static inline pud_t *pud_offset_k(unsigned long address)
{
	unsigned long addr;

	addr = pgd_val(init_level4_pgt[pud_index(address)]);
	addr &= PHYSICAL_PAGE_MASK; /* machine physical */
        addr = machine_to_phys(addr);
	return __pud_offset_k((pud_t *)__va(addr), address);
}

/* PMD  - Level 2 access */
#define pmd_page_kernel(pmd) ((unsigned long) __va(pmd_val(pmd) & PTE_MASK))
#define pmd_page(pmd)		(pfn_to_page(pmd_val(pmd) >> PAGE_SHIFT))

#define pmd_index(address) (((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))
#define pmd_offset(dir, address) ((pmd_t *) pud_page(*(dir)) + \
                                  pmd_index(address))
#define pmd_none(x)	(!pmd_val(x))
/* pmd_present doesn't just test the _PAGE_PRESENT bit since wr.p.t.
   can temporarily clear it. */
#define pmd_present(x)	(pmd_val(x))
#define pmd_clear(xp)	do { set_pmd(xp, __pmd(0)); } while (0)
#define	pmd_bad(x)	((pmd_val(x) & (~PAGE_MASK & ~_PAGE_PRESENT)) != (_KERNPG_TABLE & ~_PAGE_PRESENT))
#define pfn_pmd(nr,prot) (__pmd(((nr) << PAGE_SHIFT) | pgprot_val(prot)))
#define pmd_pfn(x)  ((pmd_val(x) >> PAGE_SHIFT) & __PHYSICAL_MASK)

#define pte_to_pgoff(pte) ((pte_val(pte) & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT)
#define pgoff_to_pte(off) ((pte_t) { ((off) << PAGE_SHIFT) | _PAGE_FILE })
#define PTE_FILE_MAX_BITS __PHYSICAL_MASK_SHIFT

/* PTE - Level 1 access. */

/* page, protection -> pte */
#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))
#define mk_pte_huge(entry) (pte_val(entry) |= _PAGE_PRESENT | _PAGE_PSE)
 
/* physical address -> PTE */
static inline pte_t mk_pte_phys(unsigned long physpage, pgprot_t pgprot)
{ 
	pte_t pte;
	(pte).pte = physpage | pgprot_val(pgprot); 
	return pte; 
}
 
/* Change flags of a PTE */
extern inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{ 
        (pte).pte &= _PAGE_CHG_MASK;
	(pte).pte |= pgprot_val(newprot);
	(pte).pte &= __supported_pte_mask;
       return pte; 
}

#define pte_index(address) \
		((address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset_kernel(dir, address) ((pte_t *) pmd_page_kernel(*(dir)) + \
			pte_index(address))

/* x86-64 always has all page tables mapped. */
#define pte_offset_map(dir,address) pte_offset_kernel(dir,address)
#define pte_offset_map_nested(dir,address) pte_offset_kernel(dir,address)
#define pte_unmap(pte) /* NOP */
#define pte_unmap_nested(pte) /* NOP */ 

#define update_mmu_cache(vma,address,pte) do { } while (0)

/* We only update the dirty/accessed state if we set
 * the dirty bit by hand in the kernel, since the hardware
 * will do the accessed bit for us, and we don't want to
 * race with other CPU's that might be updating the dirty
 * bit at the same time. */
#define  __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
#if 0
#define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
	do {								  \
		if (__dirty) {						  \
			set_pte(__ptep, __entry);			  \
			flush_tlb_page(__vma, __address);		  \
		}							  \
	} while (0)
#endif
#define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
	do {								  \
		if (__dirty) {						  \
		        if ( likely((__vma)->vm_mm == current->mm) ) {    \
			    BUG_ON(HYPERVISOR_update_va_mapping((__address), (__entry), UVMF_INVLPG|UVMF_MULTI|(unsigned long)((__vma)->vm_mm->cpu_vm_mask.bits))); \
			} else {                                          \
                            xen_l1_entry_update((__ptep), (__entry)); \
			    flush_tlb_page((__vma), (__address));         \
			}                                                 \
		}							  \
	} while (0)

/* Encode and de-code a swap entry */
#define __swp_type(x)			(((x).val >> 1) & 0x3f)
#define __swp_offset(x)			((x).val >> 8)
#define __swp_entry(type, offset)	((swp_entry_t) { ((type) << 1) | ((offset) << 8) })
#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)		((pte_t) { (x).val })

#endif /* !__ASSEMBLY__ */

extern int kern_addr_valid(unsigned long addr); 

#define DOMID_LOCAL (0xFFFFU)

int direct_remap_pfn_range(struct mm_struct *mm,
                            unsigned long address,
                            unsigned long mfn,
                            unsigned long size,
                            pgprot_t prot,
                            domid_t  domid);

int create_lookup_pte_addr(struct mm_struct *mm,
                           unsigned long address,
                           unsigned long *ptep);

int touch_pte_range(struct mm_struct *mm,
                    unsigned long address,
                    unsigned long size);

#define io_remap_page_range(vma, vaddr, paddr, size, prot)		\
		direct_remap_pfn_range((vma)->vm_mm,vaddr,paddr>>PAGE_SHIFT,size,prot,DOMID_IO)

#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)		\
		direct_remap_pfn_range((vma)->vm_mm,vaddr,pfn,size,prot,DOMID_IO)

#define MK_IOSPACE_PFN(space, pfn)	(pfn)
#define GET_IOSPACE(pfn)		0
#define GET_PFN(pfn)			(pfn)

#define HAVE_ARCH_UNMAPPED_AREA

#define pgtable_cache_init()   do { } while (0)
#define check_pgt_cache()      do { } while (0)

#define PAGE_AGP    PAGE_KERNEL_NOCACHE
#define HAVE_PAGE_AGP 1

/* fs/proc/kcore.c */
#define	kc_vaddr_to_offset(v) ((v) & __VIRTUAL_MASK)
#define	kc_offset_to_vaddr(o) \
   (((o) & (1UL << (__VIRTUAL_MASK_SHIFT-1))) ? ((o) | (~__VIRTUAL_MASK)) : (o))

#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_DIRTY
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_PTEP_SET_WRPROTECT
#define __HAVE_ARCH_PTE_SAME
#include <asm-generic/pgtable.h>

#endif /* _X86_64_PGTABLE_H */
