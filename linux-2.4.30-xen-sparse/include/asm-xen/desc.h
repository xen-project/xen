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

static inline void load_LDT(mm_context_t *pc)
{
    void *segments = pc->ldt;
    int count = pc->size;
    
    if ( count == 0 )
        segments = NULL;
    
    queue_set_ldt((unsigned long)segments, count);               
}

#endif /* __ASSEMBLY__ */

#endif /* __ARCH_DESC_H__ */
