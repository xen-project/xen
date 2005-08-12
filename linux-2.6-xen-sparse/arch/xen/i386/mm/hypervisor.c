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
#include <asm-xen/balloon.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/percpu.h>
#include <asm/tlbflush.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pte_offset_kernel pte_offset
#define pud_t pgd_t
#define pud_offset(d, va) d
#elif defined(CONFIG_X86_64)
#define pmd_val_ma(v) (v).pmd
#else
#ifdef CONFIG_X86_PAE
# define pmd_val_ma(v) ((v).pmd)
# define pud_val_ma(v) ((v).pgd.pgd)
#else
# define pmd_val_ma(v) ((v).pud.pgd.pgd)
#endif
#endif

#ifndef CONFIG_XEN_SHADOW_MODE
void xen_l1_entry_update(pte_t *ptr, pte_t val)
{
    mmu_update_t u;
    u.ptr = virt_to_machine(ptr);
    u.val = pte_val_ma(val);
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_l2_entry_update(pmd_t *ptr, pmd_t val)
{
    mmu_update_t u;
    u.ptr = virt_to_machine(ptr);
    u.val = pmd_val_ma(val);
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

#ifdef CONFIG_X86_PAE
void xen_l3_entry_update(pud_t *ptr, pud_t val)
{
    mmu_update_t u;
    u.ptr = virt_to_machine(ptr);
    u.val = pud_val_ma(val);
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif

#ifdef CONFIG_X86_64
void xen_l3_entry_update(pud_t *ptr, pud_t val)
{
    mmu_update_t u;
    u.ptr = virt_to_machine(ptr);
    u.val = val.pud;
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_l4_entry_update(pgd_t *ptr, pgd_t val)
{
    mmu_update_t u;
    u.ptr = virt_to_machine(ptr);
    u.val = val.pgd;
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif /* CONFIG_X86_64 */
#endif /* CONFIG_XEN_SHADOW_MODE */

void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
    mmu_update_t u;
    u.ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    u.val = pfn;
    BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_pt_switch(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_NEW_BASEPTR;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_new_user_pt(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_NEW_USER_BASEPTR;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush(void)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_TLB_FLUSH_LOCAL;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_INVLPG_LOCAL;
    op.linear_addr = ptr & PAGE_MASK;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

#ifdef CONFIG_SMP

void xen_tlb_flush_all(void)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_TLB_FLUSH_ALL;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush_mask(cpumask_t *mask)
{
    struct mmuext_op op;
    if ( cpus_empty(*mask) )
        return;
    op.cmd = MMUEXT_TLB_FLUSH_MULTI;
    op.vcpumask = mask->bits;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg_all(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_INVLPG_ALL;
    op.linear_addr = ptr & PAGE_MASK;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg_mask(cpumask_t *mask, unsigned long ptr)
{
    struct mmuext_op op;
    if ( cpus_empty(*mask) )
        return;
    op.cmd = MMUEXT_INVLPG_MULTI;
    op.vcpumask = mask->bits;
    op.linear_addr = ptr & PAGE_MASK;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

#endif /* CONFIG_SMP */

#ifndef CONFIG_XEN_SHADOW_MODE
void xen_pgd_pin(unsigned long ptr)
{
    struct mmuext_op op;
#ifdef CONFIG_X86_64
    op.cmd = MMUEXT_PIN_L4_TABLE;
#elif defined(CONFIG_X86_PAE)
    op.cmd = MMUEXT_PIN_L3_TABLE;
#else
    op.cmd = MMUEXT_PIN_L2_TABLE;
#endif
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pgd_unpin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pte_pin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_PIN_L1_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pte_unpin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

#ifdef CONFIG_X86_64
void xen_pud_pin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_PIN_L3_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pud_unpin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pmd_pin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_PIN_L2_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pmd_unpin(unsigned long ptr)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
#endif /* CONFIG_X86_64 */
#endif /* CONFIG_XEN_SHADOW_MODE */

void xen_set_ldt(unsigned long ptr, unsigned long len)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_SET_LDT;
    op.linear_addr = ptr;
    op.nr_ents = len;
    BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_contig_memory(unsigned long vstart, unsigned int order)
{
    /*
     * Ensure multi-page extents are contiguous in machine memory. This code 
     * could be cleaned up some, and the number of hypercalls reduced.
     */
    pgd_t         *pgd; 
    pud_t         *pud; 
    pmd_t         *pmd;
    pte_t         *pte;
    unsigned long  mfn, i, flags;

    scrub_pages(vstart, 1 << order);

    balloon_lock(flags);

    /* 1. Zap current PTEs, giving away the underlying pages. */
    for (i = 0; i < (1<<order); i++) {
        pgd = pgd_offset_k(vstart + (i*PAGE_SIZE));
        pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
        pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
        pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
        mfn = pte_mfn(*pte);
        BUG_ON(HYPERVISOR_update_va_mapping(
            vstart + (i*PAGE_SIZE), __pte_ma(0), 0));
        phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
            INVALID_P2M_ENTRY;
        BUG_ON(HYPERVISOR_dom_mem_op(
            MEMOP_decrease_reservation, &mfn, 1, 0) != 1);
    }

    /* 2. Get a new contiguous memory extent. */
    BUG_ON(HYPERVISOR_dom_mem_op(
	       MEMOP_increase_reservation, &mfn, 1, order | (32<<8)) != 1);

    /* 3. Map the new extent in place of old pages. */
    for (i = 0; i < (1<<order); i++) {
        BUG_ON(HYPERVISOR_update_va_mapping(
            vstart + (i*PAGE_SIZE),
            __pte_ma(((mfn+i)<<PAGE_SHIFT)|__PAGE_KERNEL), 0));
        xen_machphys_update(mfn+i, (__pa(vstart)>>PAGE_SHIFT)+i);
        phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] = mfn+i;
    }

    flush_tlb_all();

    balloon_unlock(flags);
}

#ifdef CONFIG_XEN_PHYSDEV_ACCESS

unsigned long allocate_empty_lowmem_region(unsigned long pages)
{
    pgd_t         *pgd;
    pud_t         *pud; 
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
        pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
        pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
        pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE))); 
        pfn_array[i] = pte_mfn(*pte);
#ifdef CONFIG_X86_64
        xen_l1_entry_update(pte, __pte(0));
#else
        BUG_ON(HYPERVISOR_update_va_mapping(vstart + (i*PAGE_SIZE), 
					    __pte_ma(0), 0));
#endif
        phys_to_machine_mapping[(__pa(vstart)>>PAGE_SHIFT)+i] =
            INVALID_P2M_ENTRY;
    }

    flush_tlb_all();

    balloon_put_pages(pfn_array, 1 << order);

    vfree(pfn_array);

    return vstart;
}

#endif /* CONFIG_XEN_PHYSDEV_ACCESS */
