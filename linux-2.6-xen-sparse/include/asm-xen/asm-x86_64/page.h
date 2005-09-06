#ifndef _X86_64_PAGE_H
#define _X86_64_PAGE_H

#include <linux/config.h>
/* #include <linux/string.h> */
#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif
#include <asm-xen/xen-public/xen.h> 
#include <asm-xen/foreign_page.h>

#define arch_free_page(_page,_order)			\
({	int foreign = PageForeign(_page);		\
	if (foreign)					\
		(PageForeignDestructor(_page))(_page);	\
	foreign;					\
})
#define HAVE_ARCH_FREE_PAGE

#ifdef CONFIG_XEN_SCRUB_PAGES
#define scrub_pages(_p,_n) memset((void *)(_p), 0, (_n) << PAGE_SHIFT)
#else
#define scrub_pages(_p,_n) ((void)0)
#endif

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#ifdef __ASSEMBLY__
#define PAGE_SIZE	(0x1 << PAGE_SHIFT)
#else
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define PHYSICAL_PAGE_MASK	(~(PAGE_SIZE-1) & (__PHYSICAL_MASK << PAGE_SHIFT))

#define THREAD_ORDER 1 
#ifdef __ASSEMBLY__
#define THREAD_SIZE  (1 << (PAGE_SHIFT + THREAD_ORDER))
#else
#define THREAD_SIZE  (1UL << (PAGE_SHIFT + THREAD_ORDER))
#endif
#define CURRENT_MASK (~(THREAD_SIZE-1))

#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#define HPAGE_SHIFT PMD_SHIFT
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

void clear_page(void *);
void copy_page(void *, void *);

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

#define alloc_zeroed_user_highpage(vma, vaddr) alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, vaddr)
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

/**** MACHINE <-> PHYSICAL CONVERSION MACROS ****/
#define INVALID_P2M_ENTRY	(~0UL)
#define FOREIGN_FRAME(m)	((m) | (1UL<<63))
extern unsigned long *phys_to_machine_mapping;
#define pfn_to_mfn(pfn)	\
(phys_to_machine_mapping[(unsigned int)(pfn)] & ~(1UL << 63))
static inline unsigned long mfn_to_pfn(unsigned long mfn)
{
	unsigned long pfn;

	/*
	 * The array access can fail (e.g., device space beyond end of RAM).
	 * In such cases it doesn't matter what we return (we return garbage),
	 * but we must handle the fault without crashing!
	 */
	asm (
		"1:	movq %1,%0\n"
		"2:\n"
		".section __ex_table,\"a\"\n"
		"	.align 8\n"
		"	.quad 1b,2b\n"
		".previous"
		: "=r" (pfn) : "m" (machine_to_phys_mapping[mfn]) );

	return pfn;
}

/* Definitions for machine and pseudophysical addresses. */
typedef unsigned long paddr_t;
typedef unsigned long maddr_t;

static inline maddr_t phys_to_machine(paddr_t phys)
{
	maddr_t machine = pfn_to_mfn(phys >> PAGE_SHIFT);
	machine = (machine << PAGE_SHIFT) | (phys & ~PAGE_MASK);
	return machine;
}

static inline paddr_t machine_to_phys(maddr_t machine)
{
	paddr_t phys = mfn_to_pfn(machine >> PAGE_SHIFT);
	phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
	return phys;
}

/*
 * These are used to make use of C type-checking..
 */
typedef struct { unsigned long pte; } pte_t;
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pud; } pud_t;
typedef struct { unsigned long pgd; } pgd_t;
#define PTE_MASK	PHYSICAL_PAGE_MASK

typedef struct { unsigned long pgprot; } pgprot_t;

#define pte_val(x)	(((x).pte & 1) ? machine_to_phys((x).pte) : \
			 (x).pte)
#define pte_val_ma(x)	((x).pte)

static inline unsigned long pmd_val(pmd_t x)
{
	unsigned long ret = x.pmd;
	if (ret) ret = machine_to_phys(ret);
	return ret;
}

static inline unsigned long pud_val(pud_t x)
{
	unsigned long ret = x.pud;
	if (ret) ret = machine_to_phys(ret);
	return ret;
}

static inline unsigned long pgd_val(pgd_t x)
{
	unsigned long ret = x.pgd;
	if (ret) ret = machine_to_phys(ret);
	return ret;
}

#define pgprot_val(x)	((x).pgprot)

#define __pte_ma(x)     ((pte_t) { (x) } )

static inline pte_t __pte(unsigned long x)
{
	if (x & 1) x = phys_to_machine(x);
	return ((pte_t) { (x) });
}

static inline pmd_t __pmd(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pmd_t) { (x) });
}

static inline pud_t __pud(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pud_t) { (x) });
}

static inline pgd_t __pgd(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pgd_t) { (x) });
}

#define __pgprot(x)	((pgprot_t) { (x) } )

#define __START_KERNEL		0xffffffff80100000UL
#define __START_KERNEL_map	0xffffffff80000000UL
#define __PAGE_OFFSET           0xffff880000000000UL	

#else
#define __START_KERNEL		0xffffffff80100000
#define __START_KERNEL_map	0xffffffff80000000
#define __PAGE_OFFSET           0xffff880000000000
#endif /* !__ASSEMBLY__ */

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

/* See Documentation/x86_64/mm.txt for a description of the memory map. */
#define __PHYSICAL_MASK_SHIFT	46
#define __PHYSICAL_MASK		((1UL << __PHYSICAL_MASK_SHIFT) - 1)
#define __VIRTUAL_MASK_SHIFT	48
#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)

#define KERNEL_TEXT_SIZE  (40UL*1024*1024)
#define KERNEL_TEXT_START 0xffffffff80000000UL 

#ifndef __ASSEMBLY__

#include <asm/bug.h>

/* Pure 2^n version of get_order */
extern __inline__ int get_order(unsigned long size)
{
	int order;

	size = (size-1) >> (PAGE_SHIFT-1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

#endif /* __ASSEMBLY__ */

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

/* Note: __pa(&symbol_visible_to_c) should be always replaced with __pa_symbol.
   Otherwise you risk miscompilation. */ 
#define __pa(x)			(((unsigned long)(x)>=__START_KERNEL_map)?(unsigned long)(x) - (unsigned long)__START_KERNEL_map:(unsigned long)(x) - PAGE_OFFSET)
/* __pa_symbol should be used for C visible symbols.
   This seems to be the official gcc blessed way to do such arithmetic. */ 
#define __pa_symbol(x)		\
	({unsigned long v;  \
	  asm("" : "=r" (v) : "0" (x)); \
	  __pa(v); })

#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#ifndef CONFIG_DISCONTIGMEM
#define pfn_to_page(pfn)	(mem_map + (pfn))
#define page_to_pfn(page)	((unsigned long)((page) - mem_map))
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif

#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(v)	(phys_to_machine(__pa(v)))
#define machine_to_virt(m)	(__va(machine_to_phys(m)))
#define virt_to_mfn(v)		(pfn_to_mfn(__pa(v) >> PAGE_SHIFT))
#define mfn_to_virt(m)		(__va(mfn_to_pfn(m) << PAGE_SHIFT))

#define VM_DATA_DEFAULT_FLAGS \
	(((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0 ) | \
	 VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#define __HAVE_ARCH_GATE_AREA 1	

#endif /* __KERNEL__ */

#endif /* _X86_64_PAGE_H */
