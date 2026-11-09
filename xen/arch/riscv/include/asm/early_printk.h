/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef RISCV_EARLY_PRINTK_H
#define RISCV_EARLY_PRINTK_H

#include <xen/early_printk.h>

#ifdef CONFIG_EARLY_PRINTK
void early_printk(const char *str);
#else
static inline void early_printk(const char *s) {};
#endif

#endif /* RISCV_EARLY_PRINTK_H */
