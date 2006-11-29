#ifndef _PGTABLE_NOPUD_H
#define _PGTABLE_NOPUD_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
#error "This version of Linux should not need compat pgtable-nopud.h"
#endif

#define pud_t             pgd_t
#define pud_offset(d, va)     d
#define pud_none(pud)         0
#define pud_present(pud)      1
#define pud_bad(pud)          0
#define PTRS_PER_PUD          1

#endif /* _PGTABLE_NOPUD_H */
