/******************************************************************************
 * xen/mm/hypervisor.c
 * 
 * Update page tables via the hypervisor.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <asm/hypervisor.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/multicall.h>

/*
 * This suffices to protect us if we ever move to SMP domains.
 * Further, it protects us against interrupts. At the very least, this is
 * required for the network driver which flushes the update queue before
 * pushing new receive buffers.
 */
static spinlock_t update_lock = SPIN_LOCK_UNLOCKED;

#define QUEUE_SIZE 2048
static mmu_update_t update_queue[QUEUE_SIZE];
unsigned int mmu_update_queue_idx = 0;
#define idx mmu_update_queue_idx

#if MMU_UPDATE_DEBUG > 0
page_update_debug_t update_debug_queue[QUEUE_SIZE] = {{0}};
#undef queue_l1_entry_update
#undef queue_l2_entry_update
static void DEBUG_allow_pt_reads(void)
{
    pte_t *pte;
    mmu_update_t update;
    int i;
    for ( i = idx-1; i >= 0; i-- )
    {
        pte = update_debug_queue[i].ptep;
        if ( pte == NULL ) continue;
        update_debug_queue[i].ptep = NULL;
        update.ptr = virt_to_machine(pte);
        update.val = update_debug_queue[i].pteval;
        HYPERVISOR_mmu_update(&update, 1);
    }
}
static void DEBUG_disallow_pt_read(unsigned long va)
{
    pte_t *pte;
    pmd_t *pmd;
    pgd_t *pgd;
    unsigned long pteval;
    /*
     * We may fault because of an already outstanding update.
     * That's okay -- it'll get fixed up in the fault handler.
     */
    mmu_update_t update;
    pgd = pgd_offset_k(va);
    pmd = pmd_offset(pgd, va);
    pte = pte_offset(pmd, va);
    update.ptr = virt_to_machine(pte);
    pteval = *(unsigned long *)pte;
    update.val = pteval & ~_PAGE_PRESENT;
    HYPERVISOR_mmu_update(&update, 1);
    update_debug_queue[idx].ptep = pte;
    update_debug_queue[idx].pteval = pteval;
}
#endif

#if MMU_UPDATE_DEBUG > 1
#undef queue_pt_switch
#undef queue_tlb_flush
#undef queue_invlpg
#undef queue_pgd_pin
#undef queue_pgd_unpin
#undef queue_pte_pin
#undef queue_pte_unpin
#endif


/*
 * MULTICALL_flush_page_update_queue:
 *   This is a version of the flush which queues as part of a multicall.
 */
void MULTICALL_flush_page_update_queue(void)
{
    unsigned long flags;
    unsigned int _idx;
    spin_lock_irqsave(&update_lock, flags);
    if ( (_idx = idx) != 0 ) 
    {
#if MMU_UPDATE_DEBUG > 1
        printk("Flushing %d entries from pt update queue\n", idx);
#endif
#if MMU_UPDATE_DEBUG > 0
        DEBUG_allow_pt_reads();
#endif
        idx = 0;
        wmb(); /* Make sure index is cleared first to avoid double updates. */
        queue_multicall2(__HYPERVISOR_mmu_update, 
                         (unsigned long)update_queue, 
                         _idx);
    }
    spin_unlock_irqrestore(&update_lock, flags);
}

static inline void __flush_page_update_queue(void)
{
    unsigned int _idx = idx;
#if MMU_UPDATE_DEBUG > 1
    printk("Flushing %d entries from pt update queue\n", idx);
#endif
#if MMU_UPDATE_DEBUG > 0
    DEBUG_allow_pt_reads();
#endif
    idx = 0;
    wmb(); /* Make sure index is cleared first to avoid double updates. */
    if ( unlikely(HYPERVISOR_mmu_update(update_queue, _idx) < 0) )
        panic("Failed to execute MMU updates");
}

void _flush_page_update_queue(void)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    if ( idx != 0 ) __flush_page_update_queue();
    spin_unlock_irqrestore(&update_lock, flags);
}

static inline void increment_index(void)
{
    idx++;
    if ( unlikely(idx == QUEUE_SIZE) ) __flush_page_update_queue();
}

void queue_l1_entry_update(pte_t *ptr, unsigned long val)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
#if MMU_UPDATE_DEBUG > 0
    DEBUG_disallow_pt_read((unsigned long)ptr);
#endif
    update_queue[idx].ptr = virt_to_machine(ptr);
    update_queue[idx].val = val;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_l2_entry_update(pmd_t *ptr, unsigned long val)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr = virt_to_machine(ptr);
    update_queue[idx].val = val;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_pt_switch(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_NEW_BASEPTR;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_tlb_flush(void)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_TLB_FLUSH;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_invlpg(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND;
    update_queue[idx].ptr |= ptr & PAGE_MASK;
    update_queue[idx].val  = MMUEXT_INVLPG;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_pgd_pin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_PIN_L2_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_pgd_unpin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_UNPIN_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_pte_pin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_PIN_L1_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_pte_unpin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_UNPIN_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_set_ldt(unsigned long ptr, unsigned long len)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND | ptr;
    update_queue[idx].val  = MMUEXT_SET_LDT | (len << MMUEXT_CMD_SHIFT);
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}
