#ifndef __I386_MMU_CONTEXT_H
#define __I386_MMU_CONTEXT_H

#include <linux/config.h>
#include <asm/desc.h>
#include <asm/atomic.h>
#include <asm/pgalloc.h>

/*
 * hooks to add arch specific data into the mm struct.
 * Note that destroy_context is called even if init_new_context
 * fails.
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm);
void destroy_context(struct mm_struct *mm);

#ifdef CONFIG_SMP

static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk, unsigned cpu)
{
	if(cpu_tlbstate[cpu].state == TLBSTATE_OK)
		cpu_tlbstate[cpu].state = TLBSTATE_LAZY;	
}
#else
static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk, unsigned cpu)
{
}
#endif

extern pgd_t *cur_pgd;
extern int mm_state_sync;
#define STATE_SYNC_PT  1
#define STATE_SYNC_LDT 2

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next, struct task_struct *tsk, unsigned cpu)
{
	if (prev != next) {
		/* stop flush ipis for the previous mm */
		clear_bit(cpu, &prev->cpu_vm_mask);
		/* Re-load page tables */
		cur_pgd = next->pgd;
		mm_state_sync |= STATE_SYNC_PT;
		/* load_LDT, if either the previous or next thread
		 * has a non-default LDT.
		 */
		if (next->context.size+prev->context.size)
			mm_state_sync |= STATE_SYNC_LDT;
	}
}

#define activate_mm(prev, next)                                 \
do {                                                            \
	switch_mm((prev),(next),NULL,smp_processor_id());       \
	if (mm_state_sync & STATE_SYNC_PT)                      \
		xen_pt_switch(__pa(cur_pgd));                   \
	if (mm_state_sync & STATE_SYNC_LDT)                     \
		load_LDT(&(next)->context);                     \
	mm_state_sync = 0;                                      \
} while ( 0 )

#endif
