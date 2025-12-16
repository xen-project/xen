#ifndef ASM_RISCV_PAGING_H
#define ASM_RISCV_PAGING_H

#include <asm-generic/paging.h>

struct domain;

int paging_domain_init(struct domain *d);

int paging_freelist_adjust(struct domain *d, unsigned long pages,
                           bool *preempted);

int paging_ret_to_domheap(struct domain *d, unsigned int nr_pages);
int paging_refill_from_domheap(struct domain *d, unsigned int nr_pages);

void paging_free_page(struct domain *d, struct page_info *pg);

struct page_info *paging_alloc_page(struct domain *d);

#endif /* ASM_RISCV_PAGING_H */
