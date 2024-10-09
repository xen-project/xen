/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__EARLY_PRINTK_H
#define ASM__RISCV__EARLY_PRINTK_H

#include <xen/early_printk.h>

#ifdef CONFIG_EARLY_PRINTK
void early_printk(const char *str);
#else
static inline void early_printk(const char *s) {};
#endif

#endif /* ASM__RISCV__EARLY_PRINTK_H */
