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
#include <asm-xen/balloon.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/percpu.h>
#endif

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
#ifdef CONFIG_SMP
#define QUEUE_SIZE 1
#else
#define QUEUE_SIZE 1
#endif
#endif

DEFINE_PER_CPU(mmu_update_t, update_queue[QUEUE_SIZE]);
DEFINE_PER_CPU(unsigned int, mmu_update_queue_idx);

/*
 * MULTICALL_flush_page_update_queue:
 *   This is a version of the flush which queues as part of a multicall.
 */
void MULTICALL_flush_page_update_queue(void)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    unsigned int _idx;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    if ( (_idx = idx) != 0 ) 
    {
        per_cpu(mmu_update_queue_idx, cpu) = 0;
        wmb(); /* Make sure index is cleared first to avoid double updates. */
        queue_multicall3(__HYPERVISOR_mmu_update, 
                         (unsigned long)&per_cpu(update_queue[0], cpu), 
                         (unsigned long)_idx, 
                         (unsigned long)NULL);
    }
    spin_unlock_irqrestore(&update_lock, flags);
}

static inline void __flush_page_update_queue(void)
{
    int cpu = smp_processor_id();
    unsigned int _idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(mmu_update_queue_idx, cpu) = 0;
    wmb(); /* Make sure index is cleared first to avoid double updates. */
    if ( unlikely(HYPERVISOR_mmu_update(&per_cpu(update_queue[0], cpu), _idx, NULL) < 0) )
    {
        printk(KERN_ALERT "Failed to execute MMU updates.\n");
        BUG();
    }
}

void _flush_page_update_queue(void)
{
    int cpu = smp_processor_id();
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    if ( per_cpu(mmu_update_queue_idx, cpu) != 0 ) __flush_page_update_queue();
    spin_unlock_irqrestore(&update_lock, flags);
}

static inline void increment_index(void)
{
    int cpu = smp_processor_id();
    per_cpu(mmu_update_queue_idx, cpu)++;
    if ( unlikely(per_cpu(mmu_update_queue_idx, cpu) == QUEUE_SIZE) ) __flush_page_update_queue();
}

static inline void increment_index_and_flush(void)
{
    int cpu = smp_processor_id();
    per_cpu(mmu_update_queue_idx, cpu)++;
    __flush_page_update_queue();
}

void queue_l1_entry_update(pte_t *ptr, unsigned long val)
{
    set_pte(ptr, __pte(val));
}

void queue_l2_entry_update(pmd_t *ptr, unsigned long val)
{
    set_pmd(ptr, __pmd(val));
}

void queue_pt_switch(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_NEW_BASEPTR;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_tlb_flush(void)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_TLB_FLUSH;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_invlpg(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).ptr |= ptr & PAGE_MASK;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_INVLPG;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_queue_pgd_pin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_PIN_L2_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_queue_pgd_unpin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_UNPIN_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_queue_pte_pin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_PIN_L1_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_queue_pte_unpin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_UNPIN_TABLE;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_set_ldt(unsigned long ptr, unsigned long len)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND | ptr;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_SET_LDT | (len << MMUEXT_CMD_SHIFT);
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

void queue_machphys_update(unsigned long mfn, unsigned long pfn)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    per_cpu(update_queue[idx], cpu).val = pfn;
    increment_index();
    spin_unlock_irqrestore(&update_lock, flags);
}

/* queue and flush versions of the above */
void xen_l1_entry_update(pte_t *ptr, unsigned long val)
{
    set_pte(ptr, __pte(val));
}

void xen_l2_entry_update(pmd_t *ptr, unsigned long val)
{
    set_pmd(ptr, __pmd(val));
}

void xen_pt_switch(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_NEW_BASEPTR;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_tlb_flush(void)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_TLB_FLUSH;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_invlpg(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).ptr |= ptr & PAGE_MASK;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_INVLPG;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_xen_pgd_pin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_PIN_L2_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_xen_pgd_unpin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_UNPIN_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_xen_pte_pin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_PIN_L1_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void __vms_xen_pte_unpin(unsigned long ptr)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = __vms_phys_to_machine(ptr);
    per_cpu(update_queue[idx], cpu).ptr |= MMU_EXTENDED_COMMAND;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_UNPIN_TABLE;
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_set_ldt(unsigned long ptr, unsigned long len)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr  = MMU_EXTENDED_COMMAND | ptr;
    per_cpu(update_queue[idx], cpu).val  = MMUEXT_SET_LDT | (len << MMUEXT_CMD_SHIFT);
    increment_index_and_flush();
    spin_unlock_irqrestore(&update_lock, flags);
}

void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
    int cpu = smp_processor_id();
    int idx;
    unsigned long flags;
    spin_lock_irqsave(&update_lock, flags);
    idx = per_cpu(mmu_update_queue_idx, cpu);
    per_cpu(update_queue[idx], cpu).ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    per_cpu(update_queue[idx], cpu).val = pfn;
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
        __vms_phys_to_machine_mapping[__pa(vstart)>>PAGE_SHIFT] = INVALID_P2M_ENTRY;
    }

    /* Flush updates through and flush the TLB. */
    xen_tlb_flush();

    balloon_put_pages(pfn_array, 1 << order);

    vfree(pfn_array);

    return vstart;
}

#endif /* CONFIG_XEN_PHYSDEV_ACCESS */
