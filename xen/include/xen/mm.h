
#ifndef __XEN_MM_H__
#define __XEN_MM_H__

/* page_alloc.c */
void init_page_allocator(unsigned long min, unsigned long max);
unsigned long alloc_xenheap_pages(int order);
void free_xenheap_pages(unsigned long p, int order);
#define alloc_xenheap_page() (alloc_xenheap_pages(0))
#define free_xenheap_page(_p) (free_xenheap_pages(_p,0))

#include <asm/mm.h>

#endif /* __XEN_MM_H__ */
