#ifndef _PGTABLE_NOPMD_H
#define _PGTABLE_NOPMD_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
#error "This version of Linux should not need compat pgtable-nopmd.h"
#endif

#define pud_t             pgd_t
#define pud_offset(d, va)     d
#define pud_none(pud)         0
#define pud_present(pud)      1
#define PTRS_PER_PUD          1

#endif /* _PGTABLE_NOPMD_H */
