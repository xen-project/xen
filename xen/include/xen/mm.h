
#ifndef __XEN_MM_H__
#define __XEN_MM_H__

struct domain;
struct pfn_info;

/* Generic allocator */
unsigned long init_heap_allocator(
    unsigned long bitmap_start, unsigned long max_pages);
void init_heap_pages(int zone, struct pfn_info *pg, unsigned long nr_pages);
struct pfn_info *alloc_heap_pages(int zone, int order);
void free_heap_pages(int zone, struct pfn_info *pg, int order);
void scrub_heap_pages(void);

/* Xen suballocator */
void init_xenheap_pages(unsigned long ps, unsigned long pe);
unsigned long alloc_xenheap_pages(int order);
void free_xenheap_pages(unsigned long p, int order);
#define alloc_xenheap_page() (alloc_xenheap_pages(0))
#define free_xenheap_page(_p) (free_xenheap_pages(_p,0))

/* Domain suballocator */
void init_domheap_pages(unsigned long ps, unsigned long pe);
struct pfn_info *alloc_domheap_pages(struct domain *d, int order);
void free_domheap_pages(struct pfn_info *pg, int order);
unsigned long avail_domheap_pages(void);
#define alloc_domheap_page(_d) (alloc_domheap_pages(_d,0))
#define free_domheap_page(_p) (free_domheap_pages(_p,0))

#include <asm/mm.h>

#endif /* __XEN_MM_H__ */
