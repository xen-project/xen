
#ifndef __XEN_MM_H__
#define __XEN_MM_H__

struct domain;
struct pfn_info;

/* Boot-time allocator. Turns into generic allocator after bootstrap. */
unsigned long init_boot_allocator(unsigned long bitmap_start);
void init_boot_pages(unsigned long ps, unsigned long pe);
unsigned long alloc_boot_pages(unsigned long size, unsigned long align);
void end_boot_allocator(void);

/* Generic allocator. These functions are *not* interrupt-safe. */
void init_heap_pages(
    unsigned int zone, struct pfn_info *pg, unsigned long nr_pages);
struct pfn_info *alloc_heap_pages(unsigned int zone, unsigned int order);
void free_heap_pages(
    unsigned int zone, struct pfn_info *pg, unsigned int order);
void scrub_heap_pages(void);

/* Xen suballocator. These functions are interrupt-safe. */
void init_xenheap_pages(unsigned long ps, unsigned long pe);
unsigned long alloc_xenheap_pages(unsigned int order);
void free_xenheap_pages(unsigned long p, unsigned int order);
#define alloc_xenheap_page() (alloc_xenheap_pages(0))
#define free_xenheap_page(_p) (free_xenheap_pages(_p,0))

/* Domain suballocator. These functions are *not* interrupt-safe.*/
void init_domheap_pages(unsigned long ps, unsigned long pe);
struct pfn_info *alloc_domheap_pages(struct domain *d, unsigned int order);
void free_domheap_pages(struct pfn_info *pg, unsigned int order);
unsigned long avail_domheap_pages(void);
#define alloc_domheap_page(_d) (alloc_domheap_pages(_d,0))
#define free_domheap_page(_p) (free_domheap_pages(_p,0))

#include <asm/mm.h>

#endif /* __XEN_MM_H__ */
