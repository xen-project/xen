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
    /*
     * NB. We load the default_ldt for lcall7/27 handling on demand, as
     * it slows down context switching. Noone uses it anyway.
     */
    queue_set_ldt(0, 0);
}

static inline void load_LDT(struct mm_struct *mm)
{
    void *segments = mm->context.segments;
    int count = 0;

    if ( unlikely(segments != NULL) )
        count = LDT_ENTRIES;
         
    queue_set_ldt((unsigned long)segments, count);
}

#endif /* __ASSEMBLY__ */

#endif /* __ARCH_DESC_H__ */
