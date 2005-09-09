#ifndef _I386_PAGE_H
#define _I386_PAGE_H

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <linux/config.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/bug.h>
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

#ifdef CONFIG_X86_USE_3DNOW

#include <asm/mmx.h>

#define clear_page(page)	mmx_clear_page((void *)(page))
#define copy_page(to,from)	mmx_copy_page(to,from)

#else

#define alloc_zeroed_user_highpage(vma, vaddr) alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, vaddr)
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

/*
 *	On older X86 processors it's not a win to use MMX here it seems.
 *	Maybe the K6-III ?
 */
 
#define clear_page(page)	memset((void *)(page), 0, PAGE_SIZE)
#define copy_page(to,from)	memcpy((void *)(to), (void *)(from), PAGE_SIZE)

#endif

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

/**** MACHINE <-> PHYSICAL CONVERSION MACROS ****/
#define INVALID_P2M_ENTRY	(~0UL)
#define FOREIGN_FRAME(m)	((m) | (1UL<<31))
extern unsigned long *phys_to_machine_mapping;
#define pfn_to_mfn(pfn)	\
(phys_to_machine_mapping[(unsigned int)(pfn)] & ~(1UL<<31))
static inline unsigned long mfn_to_pfn(unsigned long mfn)
{
	unsigned long pfn;

	/*
	 * The array access can fail (e.g., device space beyond end of RAM).
	 * In such cases it doesn't matter what we return (we return garbage),
	 * but we must handle the fault without crashing!
	 */
	asm (
		"1:	movl %1,%0\n"
		"2:\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 1b,2b\n"
		".previous"
		: "=r" (pfn) : "m" (machine_to_phys_mapping[mfn]) );

	return pfn;
}

/* Definitions for machine and pseudophysical addresses. */
#ifdef CONFIG_X86_PAE
typedef unsigned long long paddr_t;
typedef unsigned long long maddr_t;
#else
typedef unsigned long paddr_t;
typedef unsigned long maddr_t;
#endif

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
extern int nx_enabled;
#ifdef CONFIG_X86_PAE
extern unsigned long long __supported_pte_mask;
typedef struct { unsigned long pte_low, pte_high; } pte_t;
typedef struct { unsigned long long pmd; } pmd_t;
typedef struct { unsigned long long pgd; } pgd_t;
typedef struct { unsigned long long pgprot; } pgprot_t;
#define __pte(x) ({ unsigned long long _x = (x);        \
    if (_x & 1) _x = phys_to_machine(_x);               \
    ((pte_t) {(unsigned long)(_x), (unsigned long)(_x>>32)}); })
#define __pgd(x) ({ unsigned long long _x = (x); \
    (((_x)&1) ? ((pgd_t) {phys_to_machine(_x)}) : ((pgd_t) {(_x)})); })
#define __pmd(x) ({ unsigned long long _x = (x); \
    (((_x)&1) ? ((pmd_t) {phys_to_machine(_x)}) : ((pmd_t) {(_x)})); })
static inline unsigned long long pte_val(pte_t x)
{
	unsigned long long ret;

	if (x.pte_low) {
		ret = x.pte_low | (unsigned long long)x.pte_high << 32;
		ret = machine_to_phys(ret) | 1;
	} else {
		ret = 0;
	}
	return ret;
}
static inline unsigned long long pmd_val(pmd_t x)
{
	unsigned long long ret = x.pmd;
	if (ret) ret = machine_to_phys(ret) | 1;
	return ret;
}
static inline unsigned long long pgd_val(pgd_t x)
{
	unsigned long long ret = x.pgd;
	if (ret) ret = machine_to_phys(ret) | 1;
	return ret;
}
static inline unsigned long long pte_val_ma(pte_t x)
{
	return (unsigned long long)x.pte_high << 32 | x.pte_low;
}
#define HPAGE_SHIFT	21
#else
typedef struct { unsigned long pte_low; } pte_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pgprot; } pgprot_t;
#define boot_pte_t pte_t /* or would you rather have a typedef */
#define pte_val(x)	(((x).pte_low & 1) ? machine_to_phys((x).pte_low) : \
			 (x).pte_low)
#define pte_val_ma(x)	((x).pte_low)
#define __pte(x) ({ unsigned long _x = (x); \
    (((_x)&1) ? ((pte_t) {phys_to_machine(_x)}) : ((pte_t) {(_x)})); })
#define __pgd(x) ({ unsigned long _x = (x); \
    (((_x)&1) ? ((pgd_t) {phys_to_machine(_x)}) : ((pgd_t) {(_x)})); })
static inline unsigned long pgd_val(pgd_t x)
{
	unsigned long ret = x.pgd;
	if (ret) ret = machine_to_phys(ret) | 1;
	return ret;
}
#define HPAGE_SHIFT	22
#endif
#define PTE_MASK	PAGE_MASK

#ifdef CONFIG_HUGETLB_PAGE
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA
#endif

#define pgprot_val(x)	((x).pgprot)

#define __pte_ma(x)	((pte_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

#endif /* !__ASSEMBLY__ */

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

/*
 * This handles the memory map.. We could make this a config
 * option, but too many people screw it up, and too few need
 * it.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB. 
 *
 * If you want more physical memory than this then see the CONFIG_HIGHMEM4G
 * and CONFIG_HIGHMEM64G options in the kernel configuration.
 */

#ifndef __ASSEMBLY__

/*
 * This much address space is reserved for vmalloc() and iomap()
 * as well as fixmap mappings.
 */
extern unsigned int __VMALLOC_RESERVE;

/* Pure 2^n version of get_order */
static __inline__ int get_order(unsigned long size)
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

extern int sysctl_legacy_va_layout;

#endif /* __ASSEMBLY__ */

#ifdef __ASSEMBLY__
#define __PAGE_OFFSET		(0xC0000000)
#else
#define __PAGE_OFFSET		(0xC0000000UL)
#endif


#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define VMALLOC_RESERVE		((unsigned long)__VMALLOC_RESERVE)
#define MAXMEM			(HYPERVISOR_VIRT_START-__PAGE_OFFSET-__VMALLOC_RESERVE)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#ifndef CONFIG_DISCONTIGMEM
#define pfn_to_page(pfn)	(mem_map + (pfn))
#define page_to_pfn(page)	((unsigned long)((page) - mem_map))
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif /* !CONFIG_DISCONTIGMEM */
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#define VM_DATA_DEFAULT_FLAGS \
	(VM_READ | VM_WRITE | \
	((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0 ) | \
		 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(v)	(phys_to_machine(__pa(v)))
#define machine_to_virt(m)	(__va(machine_to_phys(m)))
#define virt_to_mfn(v)		(pfn_to_mfn(__pa(v) >> PAGE_SHIFT))
#define mfn_to_virt(m)		(__va(mfn_to_pfn(m) << PAGE_SHIFT))

#endif /* __KERNEL__ */

#endif /* _I386_PAGE_H */
