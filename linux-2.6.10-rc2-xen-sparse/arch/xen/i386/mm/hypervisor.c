/******************************************************************************
 * mm/hypervisor.c
 * 
 * Update page tables via the hypervisor.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/multicall.h>

/*
 * This suffices to protect us if we ever move to SMP domains.
 * Further, it protects us against interrupts. At the very least, this is
 * required for the network driver which flushes the update queue before
 * pushing new receive buffers.
 */
static spinlock_t update_lock = SPIN_LOCK_UNLOCKED;

/* Linux 2.6 isn't using the traditional batched interface. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define QUEUE_SIZE 2048
#define pte_offset_kernel pte_offset
#else
#define QUEUE_SIZE 128
#endif

static mmu_update_t update_queue[QUEUE_SIZE];
unsigned int mmu_update_queue_idx = 0;
#define idx mmu_update_queue_idx

#if MMU_UPDATE_DEBUG > 0
page_update_debug_t update_debug_queue[QUEUE_SIZE] = {{0}};
#undef queue_l1_entry_update
#undef queue_l2_entry_update
#endif
#if MMU_UPDATE_DEBUG > 3
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
        HYPERVISOR_mmu_update(&update, 1, NULL);
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
    pte = pte_offset_kernel(pmd, va); /* XXXcl */
    update.ptr = virt_to_machine(pte);
    pteval = *(unsigned long *)pte;
    update.val = pteval & ~_PAGE_PRESENT;
    HYPERVISOR_mmu_update(&update, 1, NULL);
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
#undef queue_set_ldt
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
	    if (idx > 1)
        printk("Flushing %d entries from pt update queue\n", idx);
#endif
#if MMU_UPDATE_DEBUG > 3
        DEBUG_allow_pt_reads();
#endif
        idx = 0;
        wmb(); /* Make sure index is cleared first to avoid double updates. */
        queue_multicall3(__HYPERVISOR_mmu_update, 
                         (unsigned long)update_queue, 
                         (unsigned long)_idx, 
                         (unsigned long)NULL);
    }
    spin_unlock_irqrestore(&update_lock, flags);
}

static inline void __flush_page_update_queue(void)
{
    unsigned int _idx = idx;
#if MMU_UPDATE_DEBUG > 1
    if (idx > 1)
    printk("Flushing %d entries from pt update queue\n", idx);
#endif
#if MMU_UPDATE_DEBUG > 3
    DEBUG_allow_pt_reads();
#endif
    idx = 0;
    wmb(); /* Make sure index is cleared first to avoid double updates. */
    if ( unlikely(HYPERVISOR_mmu_update(update_queue, _idx, NULL) < 0) )
    {
        printk(KERN_ALERT "Failed to execute MMU updates.\n");
        BUG();
    }
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

static inline void increment_index_and_flush(void)
{
    idx++;
    __flush_page_update_queue();
}

void queue_l1_entry_update(pte_t *ptr, unsigned long val)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
#if MMU_UPDATE_DEBUG > 3
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

void queue_machphys_update(unsigned long mfn, unsigned long pfn)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    update_queue[idx].val = pfn;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

/* queue and flush versions of the above */
void xen_l1_entry_update(pte_t *ptr, unsigned long val)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
#if MMU_UPDATE_DEBUG > 3
    DEBUG_disallow_pt_read((unsigned long)ptr);
#endif
    update_queue[idx].ptr = virt_to_machine(ptr);
    update_queue[idx].val = val;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_l2_entry_update(pmd_t *ptr, unsigned long val)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr = virt_to_machine(ptr);
    update_queue[idx].val = val;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_pt_switch(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_NEW_BASEPTR;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_tlb_flush(void)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_TLB_FLUSH;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_invlpg(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND;
    update_queue[idx].ptr |= ptr & PAGE_MASK;
    update_queue[idx].val  = MMUEXT_INVLPG;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_pgd_pin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_PIN_L2_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_pgd_unpin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_UNPIN_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_pte_pin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_PIN_L1_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_pte_unpin(unsigned long ptr)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = phys_to_machine(ptr);
    update_queue[idx].ptr |= MMU_EXTENDED_COMMAND;
    update_queue[idx].val  = MMUEXT_UNPIN_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_set_ldt(unsigned long ptr, unsigned long len)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr  = MMU_EXTENDED_COMMAND | ptr;
    update_queue[idx].val  = MMUEXT_SET_LDT | (len << MMUEXT_CMD_SHIFT);
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    update_queue[idx].ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    update_queue[idx].val = pfn;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

#ifdef CONFIG_XEN_PHYSDEV_ACCESS

unsigned long allocate_empty_lowmem_region(unsigned long pages)
{
    pgd_t         *pgd; 
    pmd_t         *pmd;
    pte_t         *pte;
    unsigned long *pfn_array;
    unsigned long  vstart;
    unsigned long  i;
    int            ret;
    unsigned int   order = get_order(pages*PAGE_SIZE);

    vstart = __get_free_pages(GFP_KERNEL, order);
    if ( vstart == 0 )
        return 0UL;

    scrub_pages(vstart, 1 << order);

    pfn_array = vmalloc((1<<order) * sizeof(*pfn_array));
    if ( pfn_array == NULL )
        BUG();

    for ( i = 0; i < (1<<order); i++ )
    {
        pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
        pmd = pmd_offset(pgd, (vstart + (i*PAGE_SIZE)));
        pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE))); 
        pfn_array[i] = pte->pte_low >> PAGE_SHIFT;
        queue_l1_entry_update(pte, 0);
        phys_to_machine_mapping[__pa(vstart)>>PAGE_SHIFT] = INVALID_P2M_ENTRY;
    }

    /* Flush updates through and flush the TLB. */
    xen_tlb_flush();

    ret = HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
                                pfn_array, 1<<order, 0);
    if ( unlikely(ret != (1<<order)) )
    {
        printk(KERN_WARNING "Unable to reduce memory reservation (%d)\n", ret);
        BUG();
    }

    vfree(pfn_array);

    return vstart;
}

void deallocate_lowmem_region(unsigned long vstart, unsigned long pages)
{
    pgd_t         *pgd; 
    pmd_t         *pmd;
    pte_t         *pte;
    unsigned long *pfn_array;
    unsigned long  i;
    int            ret;
    unsigned int   order = get_order(pages*PAGE_SIZE);

    pfn_array = vmalloc((1<<order) * sizeof(*pfn_array));
    if ( pfn_array == NULL )
        BUG();

    ret = HYPERVISOR_dom_mem_op(MEMOP_increase_reservation,
                                pfn_array, 1<<order, 0);
    if ( unlikely(ret != (1<<order)) )
    {
        printk(KERN_WARNING "Unable to increase memory reservation (%d)\n",
               ret);
        BUG();
    }

    for ( i = 0; i < (1<<order); i++ )
    {
        pgd = pgd_offset_k(   (vstart + (i*PAGE_SIZE)));
        pmd = pmd_offset(pgd, (vstart + (i*PAGE_SIZE)));
        pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
        queue_l1_entry_update(pte, (pfn_array[i]<<PAGE_SHIFT)|__PAGE_KERNEL);
        queue_machphys_update(pfn_array[i], __pa(vstart)>>PAGE_SHIFT);
        phys_to_machine_mapping[__pa(vstart)>>PAGE_SHIFT] = pfn_array[i];
    }

    flush_page_update_queue();

    vfree(pfn_array);

    free_pages(vstart, order);
}

#endif /* CONFIG_XEN_PHYSDEV_ACCESS */
