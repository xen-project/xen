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

static inline void load_LDT(mm_context_t *pc)
{
    void *segments = pc->ldt;
    int count = pc->size;
    
    if ( count == 0 )
        segments = NULL;
    
    xen_set_ldt((unsigned long)segments, count);               
}

#endif /* __ASSEMBLY__ */

#endif /* __ARCH_DESC_H__ */
