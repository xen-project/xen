/******************************************************************************
 * arch/x86/x86_64/mm.c
 * 
 * Modifications to Linux original are copyright (c) 2004, K A Fraser tr This 
 * program is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 59 
 * Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/asm_defns.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/hypercall.h>
#include <asm/msr.h>
#include <public/memory.h>

#ifdef CONFIG_COMPAT
unsigned int m2p_compat_vstart = __HYPERVISOR_COMPAT_VIRT_START;
#endif

struct page_info *alloc_xen_pagetable(void)
{
    extern int early_boot;
    unsigned long pfn;

    if ( !early_boot )
        return alloc_domheap_page(NULL);

    pfn = alloc_boot_pages(1, 1);
    return ((pfn == 0) ? NULL : mfn_to_page(pfn));
}

void free_xen_pagetable(struct page_info *pg)
{
    free_domheap_page(pg);
}

l2_pgentry_t *virt_to_xen_l2e(unsigned long v)
{
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;

    pl4e = &idle_pg_table[l4_table_offset(v)];
    if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
    {
        pl3e = page_to_virt(alloc_xen_pagetable());
        clear_page(pl3e);
        l4e_write(pl4e, l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR));
    }
    
    pl3e = l4e_to_l3e(*pl4e) + l3_table_offset(v);
    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
    {
        pl2e = page_to_virt(alloc_xen_pagetable());
        clear_page(pl2e);
        l3e_write(pl3e, l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR));
    }
    
    pl2e = l3e_to_l2e(*pl3e) + l2_table_offset(v);
    return pl2e;
}

void __init paging_init(void)
{
    unsigned long i, mpt_size, va;
    l3_pgentry_t *l3_ro_mpt;
    l2_pgentry_t *l2_ro_mpt = NULL;
    struct page_info *l1_pg, *l2_pg;

    /* Create user-accessible L2 directory to map the MPT for guests. */
    if ( (l2_pg = alloc_domheap_page(NULL)) == NULL )
        goto nomem;
    l3_ro_mpt = clear_page(page_to_virt(l2_pg));
    l4e_write(&idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)],
              l4e_from_page(l2_pg, __PAGE_HYPERVISOR | _PAGE_USER));

    /*
     * Allocate and map the machine-to-phys table.
     * This also ensures L3 is present for fixmaps.
     */
    mpt_size  = (max_page * BYTES_PER_LONG) + (1UL << L2_PAGETABLE_SHIFT) - 1;
    mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        if ( (l1_pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER, 0)) == NULL )
            goto nomem;
        map_pages_to_xen(
            RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT),
            page_to_mfn(l1_pg), 
            1UL << PAGETABLE_ORDER,
            PAGE_HYPERVISOR);
        memset((void *)(RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT)), 0x55,
               1UL << L2_PAGETABLE_SHIFT);
        if ( !((unsigned long)l2_ro_mpt & ~PAGE_MASK) )
        {
            if ( (l2_pg = alloc_domheap_page(NULL)) == NULL )
                goto nomem;
            va = RO_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT);
            l2_ro_mpt = clear_page(page_to_virt(l2_pg));
            l3e_write(&l3_ro_mpt[l3_table_offset(va)],
                      l3e_from_page(l2_pg, __PAGE_HYPERVISOR | _PAGE_USER));
            l2_ro_mpt += l2_table_offset(va);
        }
        /* NB. Cannot be GLOBAL as shadow_mode_translate reuses this area. */
        l2e_write(l2_ro_mpt, l2e_from_page(
            l1_pg, /*_PAGE_GLOBAL|*/_PAGE_PSE|_PAGE_USER|_PAGE_PRESENT));
        l2_ro_mpt++;
    }

#ifdef CONFIG_COMPAT
    if ( !compat_disabled )
    {
        /* Create user-accessible L2 directory to map the MPT for compatibility guests. */
        BUILD_BUG_ON(l4_table_offset(RDWR_MPT_VIRT_START) !=
                     l4_table_offset(HIRO_COMPAT_MPT_VIRT_START));
        l3_ro_mpt = l4e_to_l3e(idle_pg_table[l4_table_offset(HIRO_COMPAT_MPT_VIRT_START)]);
        if ( (l2_pg = alloc_domheap_page(NULL)) == NULL )
            goto nomem;
        compat_idle_pg_table_l2 = l2_ro_mpt = clear_page(page_to_virt(l2_pg));
        l3e_write(&l3_ro_mpt[l3_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
                  l3e_from_page(l2_pg, __PAGE_HYPERVISOR));
        l2_ro_mpt += l2_table_offset(HIRO_COMPAT_MPT_VIRT_START);
        /*
         * Allocate and map the compatibility mode machine-to-phys table.
        */
        mpt_size = (mpt_size >> 1) + (1UL << (L2_PAGETABLE_SHIFT - 1));
        if ( mpt_size > RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START )
            mpt_size = RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START;
        mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
        if ( m2p_compat_vstart + mpt_size < MACH2PHYS_COMPAT_VIRT_END )
            m2p_compat_vstart = MACH2PHYS_COMPAT_VIRT_END - mpt_size;
        for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
        {
            if ( (l1_pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER, 0)) == NULL )
                goto nomem;
            map_pages_to_xen(
                RDWR_COMPAT_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT),
                page_to_mfn(l1_pg),
                1UL << PAGETABLE_ORDER,
                PAGE_HYPERVISOR);
            memset((void *)(RDWR_COMPAT_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT)),
                   0x55,
                   1UL << L2_PAGETABLE_SHIFT);
            /* NB. Cannot be GLOBAL as the pt entries get copied into per-VM space. */
            l2e_write(l2_ro_mpt, l2e_from_page(l1_pg, _PAGE_PSE|_PAGE_PRESENT));
            l2_ro_mpt++;
        }
    }
#endif

    /* Set up linear page table mapping. */
    l4e_write(&idle_pg_table[l4_table_offset(LINEAR_PT_VIRT_START)],
              l4e_from_paddr(__pa(idle_pg_table), __PAGE_HYPERVISOR));
    return;

 nomem:
    panic("Not enough memory for m2p table\n");    
}

void __init setup_idle_pagetable(void)
{
    /* Install per-domain mappings for idle domain. */
    l4e_write(&idle_pg_table[l4_table_offset(PERDOMAIN_VIRT_START)],
              l4e_from_page(
                  virt_to_page(idle_vcpu[0]->domain->arch.mm_perdomain_l3),
                  __PAGE_HYPERVISOR));
}

void __init zap_low_mappings(void)
{
    l4e_write(&idle_pg_table[0], l4e_empty());
    flush_tlb_all_pge();
}

void subarch_init_memory(void)
{
    unsigned long i, v, m2p_start_mfn;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;

    /*
     * We are rather picky about the layout of 'struct page_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them.
     */
    BUILD_BUG_ON(offsetof(struct page_info, u.inuse._domain) != 
                 (offsetof(struct page_info, count_info) + sizeof(u32)));
    BUILD_BUG_ON((offsetof(struct page_info, count_info) & 7) != 0);
    BUILD_BUG_ON(sizeof(struct page_info) !=
                 (32 + BITS_TO_LONGS(NR_CPUS)*sizeof(long)));

    /* M2P table is mappable read-only by privileged domains. */
    for ( v  = RDWR_MPT_VIRT_START;
          v != RDWR_MPT_VIRT_END;
          v += 1 << L2_PAGETABLE_SHIFT )
    {
        l3e = l4e_to_l3e(idle_pg_table[l4_table_offset(v)])[
            l3_table_offset(v)];
        if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
            continue;
        l2e = l3e_to_l2e(l3e)[l2_table_offset(v)];
        if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
            continue;
        m2p_start_mfn = l2e_get_pfn(l2e);

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            struct page_info *page = mfn_to_page(m2p_start_mfn + i);
            share_xen_page_with_privileged_guests(page, XENSHARE_readonly);
        }
    }
#ifdef CONFIG_COMPAT
    if ( !compat_disabled )
    {
        for ( v  = RDWR_COMPAT_MPT_VIRT_START;
              v != RDWR_COMPAT_MPT_VIRT_END;
              v += 1 << L2_PAGETABLE_SHIFT )
        {
            l3e = l4e_to_l3e(idle_pg_table[l4_table_offset(v)])[
                l3_table_offset(v)];
            if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
                continue;
            l2e = l3e_to_l2e(l3e)[l2_table_offset(v)];
            if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
                continue;
            m2p_start_mfn = l2e_get_pfn(l2e);

            for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
            {
                struct page_info *page = mfn_to_page(m2p_start_mfn + i);
                share_xen_page_with_privileged_guests(page, XENSHARE_readonly);
            }
        }
    }
#endif
}

long subarch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct xen_machphys_mfn_list xmml;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;
    unsigned long v;
    xen_pfn_t mfn;
    unsigned int i;
    long rc = 0;

    switch ( op )
    {
    case XENMEM_machphys_mfn_list:
        if ( copy_from_guest(&xmml, arg, 1) )
            return -EFAULT;

        for ( i = 0, v = RDWR_MPT_VIRT_START;
              (i != xmml.max_extents) && (v != RDWR_MPT_VIRT_END);
              i++, v += 1 << 21 )
        {
            l3e = l4e_to_l3e(idle_pg_table[l4_table_offset(v)])[
                l3_table_offset(v)];
            if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
                break;
            l2e = l3e_to_l2e(l3e)[l2_table_offset(v)];
            if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
                break;
            mfn = l2e_get_pfn(l2e) + l1_table_offset(v);
            if ( copy_to_guest_offset(xmml.extent_start, i, &mfn, 1) )
                return -EFAULT;
        }

        xmml.nr_extents = i;
        if ( copy_to_guest(arg, &xmml, 1) )
            return -EFAULT;

        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

long do_stack_switch(unsigned long ss, unsigned long esp)
{
    fixup_guest_stack_selector(current->domain, ss);
    current->arch.guest_context.kernel_ss = ss;
    current->arch.guest_context.kernel_sp = esp;
    return 0;
}

long do_set_segment_base(unsigned int which, unsigned long base)
{
    struct vcpu *v = current;
    long ret = 0;

    switch ( which )
    {
    case SEGBASE_FS:
        if ( wrmsr_safe(MSR_FS_BASE, base, base>>32) )
            ret = -EFAULT;
        else
            v->arch.guest_context.fs_base = base;
        break;

    case SEGBASE_GS_USER:
        if ( wrmsr_safe(MSR_SHADOW_GS_BASE, base, base>>32) )
            ret = -EFAULT;
        else
            v->arch.guest_context.gs_base_user = base;
        break;

    case SEGBASE_GS_KERNEL:
        if ( wrmsr_safe(MSR_GS_BASE, base, base>>32) )
            ret = -EFAULT;
        else
            v->arch.guest_context.gs_base_kernel = base;
        break;

    case SEGBASE_GS_USER_SEL:
        __asm__ __volatile__ (
            "     swapgs              \n"
            "1:   movl %k0,%%gs       \n"
            "    "safe_swapgs"        \n"
            ".section .fixup,\"ax\"   \n"
            "2:   xorl %k0,%k0        \n"
            "     jmp  1b             \n"
            ".previous                \n"
            ".section __ex_table,\"a\"\n"
            "    .align 8             \n"
            "    .quad 1b,2b          \n"
            ".previous                  "
            : : "r" (base&0xffff) );
        break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}


/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(const struct domain *dom, struct desc_struct *d)
{
    u32 a = d->a, b = d->b;
    u16 cs;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /* Check and fix up the DPL. */
    if ( (b & _SEGMENT_DPL) < (GUEST_KERNEL_RPL(dom) << 13) )
        d->b = b = (b & ~_SEGMENT_DPL) | (GUEST_KERNEL_RPL(dom) << 13);

    /* All code and data segments are okay. No base/limit checking. */
    if ( (b & _SEGMENT_S) )
    {
        if ( !IS_COMPAT(dom) || !(b & _SEGMENT_L) )
            goto good;
        goto bad;
    }

    /* Invalid type 0 is harmless. It is used for 2nd half of a call gate. */
    if ( (b & _SEGMENT_TYPE) == 0x000 )
        goto good;

    /* Everything but a call gate is discarded here. */
    if ( (b & _SEGMENT_TYPE) != 0xc00 )
        goto bad;

    /* Validate and fix up the target code selector. */
    cs = a >> 16;
    fixup_guest_code_selector(dom, cs);
    if ( !guest_gate_selector_okay(dom, cs) )
        goto bad;
    a = d->a = (d->a & 0xffffU) | (cs << 16);

    /* Reserved bits must be zero. */
    if ( (b & 0xe0) != 0 )
        goto bad;
        
 good:
    return 1;
 bad:
    return 0;
}

#include "compat/mm.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
