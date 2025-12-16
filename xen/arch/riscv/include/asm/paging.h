#ifndef ASM_RISCV_PAGING_H
#define ASM_RISCV_PAGING_H

#include <asm-generic/paging.h>

struct domain;

int paging_domain_init(struct domain *d);

int paging_freelist_adjust(struct domain *d, unsigned long pages,
                           bool *preempted);

#endif /* ASM_RISCV_PAGING_H */
