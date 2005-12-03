#ifndef _ASM_IA64_XENPAGE_H
#define _ASM_IA64_XENPAGE_H

#ifdef CONFIG_DISCONTIGMEM
#error "xenpage.h: page macros need to be defined for CONFIG_DISCONTIGMEM"
#endif

#undef pfn_valid
#undef page_to_pfn
#undef pfn_to_page
# define pfn_valid(_pfn)	((_pfn) < max_page)
# define page_to_pfn(_page)	((unsigned long) ((_page) - frame_table))
# define pfn_to_page(_pfn)	(frame_table + (_pfn))

#undef page_to_phys
#undef virt_to_page
#define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define page_to_virt(_page)	phys_to_virt(page_to_phys(_page))
#define phys_to_page(kaddr)	pfn_to_page(((kaddr) >> PAGE_SHIFT))

#ifndef __ASSEMBLY__
typedef union xen_va {
	struct {
		unsigned long off : 60;
		unsigned long reg : 4;
	} f;
	unsigned long l;
	void *p;
} xen_va;

static inline int get_order_from_bytes(physaddr_t size)
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

#endif

#undef __pa
#undef __va
#define __pa(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
#define __va(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})

#undef PAGE_OFFSET
#define PAGE_OFFSET	__IA64_UL_CONST(0xf000000000000000)

#endif /* _ASM_IA64_XENPAGE_H */
