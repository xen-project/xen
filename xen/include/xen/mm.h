
#ifndef __XEN_MM_H__
#define __XEN_MM_H__

/* page_alloc.c */
void init_page_allocator(unsigned long min, unsigned long max);
unsigned long __get_free_pages(int order);
void __free_pages(unsigned long p, int order);
#define get_free_page()   (__get_free_pages(0))
#define __get_free_page() (__get_free_pages(0))
#define free_pages(_p,_o) (__free_pages(_p,_o))
#define free_page(_p)     (__free_pages(_p,0))

#include <asm/mm.h>

#endif /* __XEN_MM_H__ */
