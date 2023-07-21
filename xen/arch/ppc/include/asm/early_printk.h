/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_EARLY_PRINTK_H
#define _ASM_PPC_EARLY_PRINTK_H

#include <xen/early_printk.h>

#ifdef CONFIG_EARLY_PRINTK
void early_printk_init(void (*putchar)(char));
void early_printk(const char *s);
#else
static inline void early_printk_init(void (*putchar)(char)) {}
static inline void early_printk(const char *s) {}
#endif

#endif /* _ASM_PPC_EARLY_PRINTK_H */
