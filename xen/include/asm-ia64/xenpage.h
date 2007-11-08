#ifndef _ASM_IA64_XENPAGE_H
#define _ASM_IA64_XENPAGE_H

#ifndef __ASSEMBLY__
#undef mfn_valid
#undef page_to_mfn
#undef mfn_to_page
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
#undef ia64_mfn_valid
extern int ia64_mfn_valid (unsigned long pfn);
# define mfn_valid(_pfn)	(((_pfn) < max_page) && ia64_mfn_valid(_pfn))
#else
# define mfn_valid(_pfn)	((_pfn) < max_page)
#endif
# define page_to_mfn(_page)	((unsigned long) ((_page) - frame_table))
# define mfn_to_page(_pfn)	(frame_table + (_pfn))


#include <asm/xensystem.h>

static inline unsigned long __virt_to_maddr(unsigned long va)
{
	if (va - KERNEL_START < xenheap_size)
		return xen_pstart + (va - KERNEL_START);
	else
		return (va & ((1UL << 60) - 1));
}

#define virt_to_maddr(va)	(__virt_to_maddr((unsigned long)va))


#undef page_to_maddr
#undef virt_to_page
#define page_to_maddr(page)	(page_to_mfn(page) << PAGE_SHIFT)
#define virt_to_page(kaddr)	(mfn_to_page(virt_to_maddr(kaddr) >> PAGE_SHIFT))

#define page_to_virt(_page)	maddr_to_virt(page_to_maddr(_page))
#define maddr_to_page(kaddr)	mfn_to_page(((kaddr) >> PAGE_SHIFT))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define virt_to_mfn(va)		(virt_to_maddr(va) >> PAGE_SHIFT)
#define mfn_to_virt(mfn)	maddr_to_virt(mfn << PAGE_SHIFT)

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn)	((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)	((unsigned long)((pa) >> PAGE_SHIFT))

typedef union xen_va {
	struct {
		unsigned long off : 60;
		unsigned long reg : 4;
	} f;
	unsigned long l;
	void *p;
} xen_va;

static inline int get_order_from_bytes(paddr_t size)
{
    int order;
    size = (size-1) >> PAGE_SHIFT;
    for ( order = 0; size; order++ )
        size >>= 1;
    return order;
}

static inline int get_order_from_pages(unsigned long nr_pages)
{
    int order;
    nr_pages--;
    for ( order = 0; nr_pages; order++ )
        nr_pages >>= 1;
    return order;
}

static inline int get_order_from_shift(unsigned long shift)
{
    if (shift <= PAGE_SHIFT)
	return 0;
    else
	return shift - PAGE_SHIFT;
}
/* from identity va to xen va */
#define virt_to_xenva(va)	((unsigned long)va - PAGE_OFFSET - \
				 xen_pstart + KERNEL_START)


#undef __pa
#undef __va
#define __pa(x)		(virt_to_maddr(x))
#define __va(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})

/* It is sometimes very useful to have unsigned long as result.  */
#define __va_ul(x)	({xen_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.l;})

#endif
#endif /* _ASM_IA64_XENPAGE_H */
