#ifndef __i386_MMU_H
#define __i386_MMU_H

/*
 * The i386 doesn't have a mmu context, but
 * we put the segment information here.
 */
typedef struct { 
	void *segments;
	unsigned long cpuvalid;
} mm_context_t;

#endif
