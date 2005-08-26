#ifndef __x86_64_MMU_H
#define __x86_64_MMU_H

#include <linux/spinlock.h>
#include <asm/semaphore.h>

/*
 * The x86_64 doesn't have a mmu context, but
 * we put the segment information here.
 *
 * cpu_vm_mask is used to optimize ldt flushing.
 */
typedef struct { 
	void *ldt;
	rwlock_t ldtlock; 
	int size;
	struct semaphore sem; 
#ifdef CONFIG_XEN
	unsigned pinned:1;
	struct list_head unpinned;
#endif
} mm_context_t;

#ifdef CONFIG_XEN
extern struct list_head mm_unpinned;
extern spinlock_t mm_unpinned_lock;

/* mm/memory.c:exit_mmap hook */
extern void _arch_exit_mmap(struct mm_struct *mm);
#define arch_exit_mmap(_mm) _arch_exit_mmap(_mm)
#endif

#endif
