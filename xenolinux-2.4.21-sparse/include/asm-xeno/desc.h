#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/ldt.h>

#ifndef __ASSEMBLY__

struct desc_struct {
	unsigned long a,b;
};

struct Xgt_desc_struct {
	unsigned short size;
	unsigned long address __attribute__((packed));
};

extern struct desc_struct default_ldt[];

static inline void clear_LDT(void)
{
    queue_set_ldt((unsigned long)&default_ldt[0], 5);
}

static inline void load_LDT(struct mm_struct *mm)
{
    void *segments = mm->context.segments;
    int count = LDT_ENTRIES;

    if (!segments) {
        segments = &default_ldt[0];
        count = 5;
    }
         
    queue_set_ldt((unsigned long)segments, count);
}

#endif /* __ASSEMBLY__ */

#endif /* __ARCH_DESC_H__ */
