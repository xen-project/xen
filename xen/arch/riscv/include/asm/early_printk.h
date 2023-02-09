#ifndef __EARLY_PRINTK_H__
#define __EARLY_PRINTK_H__

#include <xen/early_printk.h>

#ifdef CONFIG_EARLY_PRINTK
void early_printk(const char *str);
#else
static inline void early_printk(const char *s) {};
#endif

#endif /* __EARLY_PRINTK_H__ */
