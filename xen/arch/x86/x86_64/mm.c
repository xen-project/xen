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
#include <asm/current.h>
#include <asm/asm_defns.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/msr.h>
#include <public/memory.h>

struct pfn_info *alloc_xen_pagetable(void)
{
    extern int early_boot;
    unsigned long pfn;

    if ( !early_boot )
        return alloc_domheap_page(NULL);

    pfn = alloc_boot_pages(1, 1);
    return ((pfn == 0) ? NULL : pfn_to_page(pfn));
}

void free_xen_pagetable(struct pfn_info *pg)
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
        *pl4e = l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR);
    }
    
    pl3e = l4e_to_l3e(*pl4e) + l3_table_offset(v);
    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
    {
        pl2e = page_to_virt(alloc_xen_pagetable());
        clear_page(pl2e);
        *pl3e = l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR);
    }
    
    pl2e = l3e_to_l2e(*pl3e) + l2_table_offset(v);
    return pl2e;
}

void __init paging_init(void)
{
    unsigned long i, mpt_size;
    l3_pgentry_t *l3_ro_mpt;
    l2_pgentry_t *l2_ro_mpt;
    struct pfn_info *pg;

    idle_vcpu[0]->arch.monitor_table = mk_pagetable(__pa(idle_pg_table));

    /* Create user-accessible L2 directory to map the MPT for guests. */
    l3_ro_mpt = alloc_xenheap_page();
    clear_page(l3_ro_mpt);
    idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)] =
        l4e_from_page(
            virt_to_page(l3_ro_mpt), __PAGE_HYPERVISOR | _PAGE_USER);
    l2_ro_mpt = alloc_xenheap_page();
    clear_page(l2_ro_mpt);
    l3_ro_mpt[l3_table_offset(RO_MPT_VIRT_START)] =
        l3e_from_page(
            virt_to_page(l2_ro_mpt), __PAGE_HYPERVISOR | _PAGE_USER);
    l2_ro_mpt += l2_table_offset(RO_MPT_VIRT_START);

    /*
     * Allocate and map the machine-to-phys table.
     * This also ensures L3 is present for fixmaps.
     */
    mpt_size  = (max_page * BYTES_PER_LONG) + (1UL << L2_PAGETABLE_SHIFT) - 1;
    mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        if ( (pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER, 0)) == NULL )
            panic("Not enough memory for m2p table\n");
        map_pages_to_xen(
            RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT), page_to_pfn(pg), 
            1UL << PAGETABLE_ORDER,
            PAGE_HYPERVISOR);
        memset((void *)(RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT)), 0x55,
               1UL << L2_PAGETABLE_SHIFT);
        *l2_ro_mpt++ = l2e_from_page(
            pg, _PAGE_GLOBAL|_PAGE_PSE|_PAGE_USER|_PAGE_PRESENT);
        BUG_ON(((unsigned long)l2_ro_mpt & ~PAGE_MASK) == 0);
    }

    /* Set up linear page table mapping. */
    idle_pg_table[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_paddr(__pa(idle_pg_table), __PAGE_HYPERVISOR);

    /* Install per-domain mappings for idle domain. */
    idle_pg_table[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_page(
            virt_to_page(idle_vcpu[0]->domain->arch.mm_perdomain_l3),
            __PAGE_HYPERVISOR);
}

void __init zap_low_mappings(void)
{
    idle_pg_table[0] = l4e_empty();
    flush_tlb_all_pge();
}

void subarch_init_memory(struct domain *dom_xen)
{
    unsigned long i, v, m2p_start_mfn;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;

    /*
     * We are rather picky about the layout of 'struct pfn_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them.
     */
    if ( ((offsetof(struct pfn_info, u.inuse._domain) != 
           (offsetof(struct pfn_info, count_info) + sizeof(u32)))) ||
         ((offsetof(struct pfn_info, count_info) & 7) != 0) ||
         (sizeof(struct pfn_info) != 40) )
    {
        printk("Weird pfn_info layout (%ld,%ld,%ld)\n",
               offsetof(struct pfn_info, count_info),
               offsetof(struct pfn_info, u.inuse._domain),
               sizeof(struct pfn_info));
        for ( ; ; ) ;
    }

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
            struct pfn_info *page = pfn_to_page(m2p_start_mfn + i);
            page->count_info = PGC_allocated | 1;
            /* gdt to make sure it's only mapped read-only by non-privileged
               domains. */
            page->u.inuse.type_info = PGT_gdt_page | 1;
            page_set_owner(page, dom_xen);
        }
    }
}

long subarch_memory_op(int op, void *arg)
{
    struct xen_machphys_mfn_list xmml;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;
    unsigned long mfn, v;
    unsigned int i;
    long rc = 0;

    switch ( op )
    {
    case XENMEM_machphys_mfn_list:
        if ( copy_from_user(&xmml, arg, sizeof(xmml)) )
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
            if ( put_user(mfn, &xmml.extent_start[i]) )
                return -EFAULT;
        }

        if ( put_user(i, &((struct xen_machphys_mfn_list *)arg)->nr_extents) )
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
    if ( (ss & 3) != 3 )
        return -EPERM;
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
        if ( wrmsr_user(MSR_FS_BASE, base, base>>32) )
            ret = -EFAULT;
        else
            v->arch.guest_context.fs_base = base;
        break;

    case SEGBASE_GS_USER:
        if ( wrmsr_user(MSR_SHADOW_GS_BASE, base, base>>32) )
            ret = -EFAULT;
        else
            v->arch.guest_context.gs_base_user = base;
        break;

    case SEGBASE_GS_KERNEL:
        if ( wrmsr_user(MSR_GS_BASE, base, base>>32) )
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
int check_descriptor(struct desc_struct *d)
{
    u32 a = d->a, b = d->b;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /* The guest can only safely be executed in ring 3. */
    if ( (b & _SEGMENT_DPL) != _SEGMENT_DPL )
        goto bad;

    /* All code and data segments are okay. No base/limit checking. */
    if ( (b & _SEGMENT_S) )
        goto good;

    /* Invalid type 0 is harmless. It is used for 2nd half of a call gate. */
    if ( (b & _SEGMENT_TYPE) == 0x000 )
        goto good;

    /* Everything but a call gate is discarded here. */
    if ( (b & _SEGMENT_TYPE) != 0xc00 )
        goto bad;

    /* Can't allow far jump to a Xen-private segment. */
    if ( !VALID_CODESEL(a>>16) )
        goto bad;

    /* Reserved bits must be zero. */
    if ( (b & 0xe0) != 0 )
        goto bad;
        
 good:
    return 1;
 bad:
    return 0;
}

void memguard_guard_stack(void *p)
{
    p = (void *)((unsigned long)p + PAGE_SIZE);
    memguard_guard_range(p, 2 * PAGE_SIZE);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
