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

#ifdef CONFIG_XEN_SHADOW_MODE
#include <asm/bug.h>
#endif /* CONFIG_XEN_SHADOW_MODE */

#include <linux/config.h>
#include <linux/string.h>
#include <linux/types.h>
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
#ifndef CONFIG_XEN_SHADOW_MODE
extern unsigned int *phys_to_machine_mapping;
#define pfn_to_mfn(_pfn) ((unsigned long)(phys_to_machine_mapping[(_pfn)]))
#define mfn_to_pfn(_mfn) ((unsigned long)(machine_to_phys_mapping[(_mfn)]))
static inline unsigned long phys_to_machine(unsigned long phys)
#else /* CONFIG_XEN_SHADOW_MODE */
extern unsigned int *__vms_phys_to_machine_mapping;
#define __vms_pfn_to_mfn(_pfn) ((unsigned long)(__vms_phys_to_machine_mapping[(_pfn)]))
#define __vms_mfn_to_pfn(_mfn) ({ BUG(); ((unsigned long)(__vms_machine_to_phys_mapping[(_mfn)])); })
static inline unsigned long __vms_phys_to_machine(unsigned long phys)
#endif /* CONFIG_XEN_SHADOW_MODE */
{
#ifndef CONFIG_XEN_SHADOW_MODE
	unsigned long machine = pfn_to_mfn(phys >> PAGE_SHIFT);
#else /* CONFIG_XEN_SHADOW_MODE */
	unsigned long machine = __vms_pfn_to_mfn(phys >> PAGE_SHIFT);
#endif /* CONFIG_XEN_SHADOW_MODE */
	machine = (machine << PAGE_SHIFT) | (phys & ~PAGE_MASK);
	return machine;
}
#ifndef CONFIG_XEN_SHADOW_MODE
static inline unsigned long machine_to_phys(unsigned long machine)
#else /* CONFIG_XEN_SHADOW_MODE */
static inline unsigned long __vms_machine_to_phys(unsigned long machine)
#endif /* CONFIG_XEN_SHADOW_MODE */
{
#ifndef CONFIG_XEN_SHADOW_MODE
	unsigned long phys = mfn_to_pfn(machine >> PAGE_SHIFT);
#else /* CONFIG_XEN_SHADOW_MODE */
	unsigned long phys = __vms_mfn_to_pfn(machine >> PAGE_SHIFT);
#endif /* CONFIG_XEN_SHADOW_MODE */
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
#define pte_val(x)	((x).pte_low | ((unsigned long long)(x).pte_high << 32))
#define HPAGE_SHIFT	21
#else
typedef struct { unsigned long pte_low; } pte_t;
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pgprot; } pgprot_t;
#define boot_pte_t pte_t /* or would you rather have a typedef */
#ifndef CONFIG_XEN_SHADOW_MODE
#define pte_val(x)	(((x).pte_low & 1) ? machine_to_phys((x).pte_low) : \
			 (x).pte_low)
#define pte_val_ma(x)	((x).pte_low)
#else /* CONFIG_XEN_SHADOW_MODE */
#define pte_val(x)	((x).pte_low)
#define __vms_pte_val_ma(x)	((x).pte_low)
#endif /* CONFIG_XEN_SHADOW_MODE */
#define HPAGE_SHIFT	22
#endif
#define PTE_MASK	PAGE_MASK

#ifdef CONFIG_HUGETLB_PAGE
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA
#endif


static inline unsigned long pmd_val(pmd_t x)
{
#ifndef CONFIG_XEN_SHADOW_MODE
	unsigned long ret = x.pmd;
	if (ret) ret = machine_to_phys(ret);
	return ret;
#else /* CONFIG_XEN_SHADOW_MODE */
	return x.pmd;
#endif /* CONFIG_XEN_SHADOW_MODE */
}
#define pgd_val(x)	({ BUG(); (unsigned long)0; })
#define pgprot_val(x)	((x).pgprot)

static inline pte_t __pte(unsigned long x)
{
#ifndef CONFIG_XEN_SHADOW_MODE
	if (x & 1) x = phys_to_machine(x);
#endif /* ! CONFIG_XEN_SHADOW_MODE */
	return ((pte_t) { (x) });
}
#ifndef CONFIG_XEN_SHADOW_MODE
#define __pte_ma(x)	((pte_t) { (x) } )
#endif /* ! CONFIG_XEN_SHADOW_MODE */
static inline pmd_t __pmd(unsigned long x)
{
#ifndef CONFIG_XEN_SHADOW_MODE
	if ((x & 1)) x = phys_to_machine(x);
#endif /* ! CONFIG_XEN_SHADOW_MODE */
	return ((pmd_t) { (x) });
}
#define __pgd(x)	({ BUG(); (pgprot_t) { 0 }; })
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
#define MAXMEM			(-__PAGE_OFFSET-__VMALLOC_RESERVE)
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
#ifndef CONFIG_XEN_SHADOW_MODE
#define virt_to_machine(_a)	(phys_to_machine(__pa(_a)))
#define machine_to_virt(_m)	(__va(machine_to_phys(_m)))
#else /* CONFIG_XEN_SHADOW_MODE */
#define __vms_virt_to_machine(_a)	(__vms_phys_to_machine(__pa(_a)))
#define __vms_machine_to_virt(_m)	(__va(__vms_machine_to_phys(_m)))
#endif /* CONFIG_XEN_SHADOW_MODE */

#endif /* __KERNEL__ */

#endif /* _I386_PAGE_H */
