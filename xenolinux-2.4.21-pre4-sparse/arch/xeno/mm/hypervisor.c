/******************************************************************************
 * xeno/mm/hypervisor.c
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

/*
 * A note on atomicity of these operations. We assume that queue_xxx
 * operations never occur in an asynchronous (eg. interrupt) context.
 * Therefore they do not need to be synchronised w.r.t. each other.
 * However, flush_update_queue may be called from an interrupt context
 * (eg. this is done in the network driver).
 * 
 * We use lock-free techniques to synchronise on the queue index. If a
 * queue_xxx operation finds this index changes while it runs, it will
 * fail and retry.
 * 
 * Flush operations must synchronize with themselves. They do this by
 * atomically updating the index to zero on entry. This effectively locks
 * out any other asynchronous calls to a flush operation.
 * 
 * Debug routines synchronise by disabling interrupts. It's easier that way.
 */

#define QUEUE_SIZE 2048
static page_update_request_t update_queue[QUEUE_SIZE];
volatile unsigned int pt_update_queue_idx = 0;

#if PT_UPDATE_DEBUG > 0
page_update_debug_t update_debug_queue[QUEUE_SIZE] = {{0}};
#undef queue_l1_entry_update
#undef queue_l2_entry_update
static void DEBUG_allow_pt_reads(void)
{
    pte_t *pte;
    page_update_request_t update;
    unsigned int idx;
    unsigned long flags;
    int i;
    local_irq_save(flags);
    idx = pt_update_queue_idx;
    for ( i = idx-1; i >= 0; i-- )
    {
        pte = update_debug_queue[i].ptep;
        if ( pte == NULL ) continue;
        update_debug_queue[i].ptep = NULL;
        update.ptr = phys_to_machine(__pa(pte));
        update.val = update_debug_queue[i].pteval;
        HYPERVISOR_pt_update(&update, 1);
    }
    local_irq_restore(flags);
}
static void DEBUG_disallow_pt_read(unsigned long pa)
{
    pte_t *pte;
    pmd_t *pmd;
    pgd_t *pgd;
    unsigned long pteval, flags;
    unsigned int idx;
    local_irq_save(flags);
    idx = pt_update_queue_idx;
    /*
     * We may fault because of an already outstanding update.
     * That's okay -- it'll get fixed up in the fault handler.
     */
    page_update_request_t update;
    unsigned long va = (unsigned long)__va(pa);
    pgd = pgd_offset_k(va);
    pmd = pmd_offset(pgd, va);
    pte = pte_offset(pmd, va);
    update.ptr = phys_to_machine(__pa(pte));
    pteval = *(unsigned long *)pte;
    update.val = pteval & ~_PAGE_PRESENT;
    HYPERVISOR_pt_update(&update, 1);
    update_debug_queue[idx].ptep = pte;
    update_debug_queue[idx].pteval = pteval;
    local_irq_restore(flags);
}
#endif

#if PT_UPDATE_DEBUG > 1
#undef queue_pt_switch
#undef queue_tlb_flush
#undef queue_invlpg
#undef queue_pgd_pin
#undef queue_pgd_unpin
#undef queue_pte_pin
#undef queue_pte_unpin
#endif


/*
 * This is the current pagetable base pointer, which is updated
 * on context switch.
 */
unsigned long pt_baseptr;

void _flush_page_update_queue(void)
{
    unsigned int idx = xchg(&pt_update_queue_idx, 0);
    if ( idx == 0 ) return;
#if PT_UPDATE_DEBUG > 1
    printk("Flushing %d entries from pt update queue\n", idx);
#endif
#if PT_UPDATE_DEBUG > 0
    DEBUG_allow_pt_reads();
#endif
    HYPERVISOR_pt_update(update_queue, idx);
}

void queue_l1_entry_update(unsigned long ptr, unsigned long val)
{
    unsigned int idx;
#if PT_UPDATE_DEBUG > 0
    DEBUG_disallow_pt_read(ptr);
#endif
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr = phys_to_machine(ptr);
        update_queue[idx].val = val;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );    
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_l2_entry_update(unsigned long ptr, unsigned long val)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr = phys_to_machine(ptr);
        update_queue[idx].val = val;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_pt_switch(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = phys_to_machine(ptr);
        update_queue[idx].ptr |= PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_NEW_BASEPTR;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_tlb_flush(void)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_TLB_FLUSH;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_invlpg(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = ptr & PAGE_MASK;
        update_queue[idx].val |= PGEXT_INVLPG;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_pgd_pin(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = phys_to_machine(ptr);
        update_queue[idx].ptr |= PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_PIN_L2_TABLE;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_pgd_unpin(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = phys_to_machine(ptr);
        update_queue[idx].ptr |= PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_UNPIN_TABLE;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_pte_pin(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = phys_to_machine(ptr);
        update_queue[idx].ptr |= PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_PIN_L1_TABLE;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}

void queue_pte_unpin(unsigned long ptr)
{
    unsigned int idx;
    do {
        idx = pt_update_queue_idx;
        update_queue[idx].ptr  = phys_to_machine(ptr);
        update_queue[idx].ptr |= PGREQ_EXTENDED_COMMAND;
        update_queue[idx].val  = PGEXT_UNPIN_TABLE;
    } while ( cmpxchg(&pt_update_queue_idx, idx, idx+1) != idx );
    if ( idx == (QUEUE_SIZE-1) ) _flush_page_update_queue();
}
