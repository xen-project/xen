
#ifndef __i386_MMU_H
#define __i386_MMU_H

#include <linux/list.h>

/* describes dirrectly mapped vma nodes */
typedef struct {
    struct list_head list;
    unsigned long vm_start;
	unsigned long vm_end;
} direct_mmap_node_t;

/*
 * The i386 doesn't have a mmu context, but
 * we put the segment information here.
 */
typedef struct { 
	void *segments;
	unsigned long cpuvalid;
    struct list_head direct_list;
} mm_context_t;

#endif
