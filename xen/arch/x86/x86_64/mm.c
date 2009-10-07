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
#include <xen/numa.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/asm_defns.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/hypercall.h>
#include <asm/msr.h>
#include <asm/setup.h>
#include <public/memory.h>

/* Parameters for PFN/MADDR compression. */
unsigned long __read_mostly max_pdx;
unsigned long __read_mostly pfn_pdx_bottom_mask = ~0UL;
unsigned long __read_mostly ma_va_bottom_mask = ~0UL;
unsigned long __read_mostly pfn_top_mask = 0;
unsigned long __read_mostly ma_top_mask = 0;
unsigned long __read_mostly pfn_hole_mask = 0;
unsigned int __read_mostly pfn_pdx_hole_shift = 0;

#ifdef CONFIG_COMPAT
unsigned int m2p_compat_vstart = __HYPERVISOR_COMPAT_VIRT_START;
#endif

DEFINE_PER_CPU_READ_MOSTLY(void *, compat_arg_xlat);

/* Top-level master (and idle-domain) page directory. */
l4_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    idle_pg_table[L4_PAGETABLE_ENTRIES];

/* Enough page directories to map bottom 4GB of the memory map. */
l3_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    l3_identmap[L3_PAGETABLE_ENTRIES];
l2_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    l2_identmap[4*L2_PAGETABLE_ENTRIES];

/* Enough page directories to map the Xen text and static data. */
l3_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    l3_xenmap[L3_PAGETABLE_ENTRIES];
l2_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    l2_xenmap[L2_PAGETABLE_ENTRIES];

int __mfn_valid(unsigned long mfn)
{
    return likely(mfn < max_page) &&
           likely(!(mfn & pfn_hole_mask)) &&
           likely(test_bit(pfn_to_pdx(mfn) / PDX_GROUP_COUNT,
                           pdx_group_valid));
}

void *alloc_xen_pagetable(void)
{
    unsigned long mfn;

    if ( !early_boot )
    {
        struct page_info *pg = alloc_domheap_page(NULL, 0);
        BUG_ON(pg == NULL);
        return page_to_virt(pg);
    }

    mfn = alloc_boot_pages(1, 1);
    return mfn_to_virt(mfn);
}

l3_pgentry_t *virt_to_xen_l3e(unsigned long v)
{
    l4_pgentry_t *pl4e;

    pl4e = &idle_pg_table[l4_table_offset(v)];
    if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
    {
        l3_pgentry_t *pl3e = alloc_xen_pagetable();
        clear_page(pl3e);
        l4e_write(pl4e, l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR));
    }
    
    return l4e_to_l3e(*pl4e) + l3_table_offset(v);
}

l2_pgentry_t *virt_to_xen_l2e(unsigned long v)
{
    l3_pgentry_t *pl3e;

    pl3e = virt_to_xen_l3e(v);
    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
    {
        l2_pgentry_t *pl2e = alloc_xen_pagetable();
        clear_page(pl2e);
        l3e_write(pl3e, l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR));
    }

    BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
    return l3e_to_l2e(*pl3e) + l2_table_offset(v);
}

void *do_page_walk(struct vcpu *v, unsigned long addr)
{
    unsigned long mfn = pagetable_get_pfn(v->arch.guest_table);
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    if ( is_hvm_vcpu(v) )
        return NULL;

    l4t = mfn_to_virt(mfn);
    l4e = l4t[l4_table_offset(addr)];
    mfn = l4e_get_pfn(l4e);
    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return NULL;

    l3t = mfn_to_virt(mfn);
    l3e = l3t[l3_table_offset(addr)];
    mfn = l3e_get_pfn(l3e);
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) || !mfn_valid(mfn) )
        return NULL;
    if ( (l3e_get_flags(l3e) & _PAGE_PSE) )
        return mfn_to_virt(mfn) + (addr & ((1UL << L3_PAGETABLE_SHIFT) - 1));

    l2t = mfn_to_virt(mfn);
    l2e = l2t[l2_table_offset(addr)];
    mfn = l2e_get_pfn(l2e);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) || !mfn_valid(mfn) )
        return NULL;
    if ( (l2e_get_flags(l2e) & _PAGE_PSE) )
        return mfn_to_virt(mfn) + (addr & ((1UL << L2_PAGETABLE_SHIFT) - 1));

    l1t = mfn_to_virt(mfn);
    l1e = l1t[l1_table_offset(addr)];
    mfn = l1e_get_pfn(l1e);
    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) || !mfn_valid(mfn) )
        return NULL;

    return mfn_to_virt(mfn) + (addr & ~PAGE_MASK);
}

void __init pfn_pdx_hole_setup(unsigned long mask)
{
    unsigned int i, j, bottom_shift, hole_shift;

    for ( hole_shift = bottom_shift = j = 0; ; )
    {
        i = find_next_zero_bit(&mask, BITS_PER_LONG, j);
        j = find_next_bit(&mask, BITS_PER_LONG, i);
        if ( j >= BITS_PER_LONG )
            break;
        if ( j - i > hole_shift )
        {
            hole_shift = j - i;
            bottom_shift = i;
        }
    }
    if ( !hole_shift )
        return;

    printk(KERN_INFO "PFN compression on bits %u...%u\n",
           bottom_shift, bottom_shift + hole_shift - 1);

    pfn_pdx_hole_shift  = hole_shift;
    pfn_pdx_bottom_mask = (1UL << bottom_shift) - 1;
    ma_va_bottom_mask   = (PAGE_SIZE << bottom_shift) - 1;
    pfn_hole_mask       = ((1UL << hole_shift) - 1) << bottom_shift;
    pfn_top_mask        = ~(pfn_pdx_bottom_mask | pfn_hole_mask);
    ma_top_mask         = pfn_top_mask << PAGE_SHIFT;
}

void __init paging_init(void)
{
    unsigned long i, mpt_size, va;
    unsigned int n, memflags;
    l3_pgentry_t *l3_ro_mpt;
    l2_pgentry_t *l2_ro_mpt = NULL;
    struct page_info *l1_pg, *l2_pg, *l3_pg;

    /* Create user-accessible L2 directory to map the MPT for guests. */
    if ( (l3_pg = alloc_domheap_page(NULL, 0)) == NULL )
        goto nomem;
    l3_ro_mpt = page_to_virt(l3_pg);
    clear_page(l3_ro_mpt);
    l4e_write(&idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)],
              l4e_from_page(l3_pg, __PAGE_HYPERVISOR | _PAGE_USER));

    /*
     * Allocate and map the machine-to-phys table.
     * This also ensures L3 is present for fixmaps.
     */
    mpt_size  = (max_page * BYTES_PER_LONG) + (1UL << L2_PAGETABLE_SHIFT) - 1;
    mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
#define MFN(x) (((x) << L2_PAGETABLE_SHIFT) / sizeof(unsigned long))
#define CNT ((sizeof(*frame_table) & -sizeof(*frame_table)) / \
             sizeof(*machine_to_phys_mapping))
    BUILD_BUG_ON((sizeof(*frame_table) & ~sizeof(*frame_table)) % \
                 sizeof(*machine_to_phys_mapping));
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        BUILD_BUG_ON(RO_MPT_VIRT_START & ((1UL << L3_PAGETABLE_SHIFT) - 1));
        va = RO_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT);
        memflags = MEMF_node(phys_to_nid(i <<
            (L2_PAGETABLE_SHIFT - 3 + PAGE_SHIFT)));

        if ( cpu_has_page1gb &&
             !((unsigned long)l2_ro_mpt & ~PAGE_MASK) &&
             (mpt_size >> L3_PAGETABLE_SHIFT) > (i >> PAGETABLE_ORDER) )
        {
            unsigned int k, holes;

            for ( holes = k = 0; k < 1 << PAGETABLE_ORDER; ++k)
            {
                for ( n = 0; n < CNT; ++n)
                    if ( mfn_valid(MFN(i + k) + n * PDX_GROUP_COUNT) )
                        break;
                if ( n == CNT )
                    ++holes;
            }
            if ( k == holes )
            {
                i += (1UL << PAGETABLE_ORDER) - 1;
                continue;
            }
            if ( holes == 0 &&
                 (l1_pg = alloc_domheap_pages(NULL, 2 * PAGETABLE_ORDER,
                                              memflags)) != NULL )
            {
                map_pages_to_xen(
                    RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT),
                    page_to_mfn(l1_pg),
                    1UL << (2 * PAGETABLE_ORDER),
                    PAGE_HYPERVISOR);
                memset((void *)(RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT)),
                       0x77, 1UL << L3_PAGETABLE_SHIFT);

                ASSERT(!l2_table_offset(va));
                /* NB. Cannot be GLOBAL as shadow_mode_translate reuses this area. */
                l3e_write(&l3_ro_mpt[l3_table_offset(va)],
                    l3e_from_page(l1_pg,
                        /*_PAGE_GLOBAL|*/_PAGE_PSE|_PAGE_USER|_PAGE_PRESENT));
                i += (1UL << PAGETABLE_ORDER) - 1;
                continue;
            }
        }

        for ( n = 0; n < CNT; ++n)
            if ( mfn_valid(MFN(i) + n * PDX_GROUP_COUNT) )
                break;
        if ( n == CNT )
            l1_pg = NULL;
        else if ( (l1_pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER,
                                               memflags)) == NULL )
            goto nomem;
        else
        {
            map_pages_to_xen(
                RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT),
                page_to_mfn(l1_pg),
                1UL << PAGETABLE_ORDER,
                PAGE_HYPERVISOR);
            memset((void *)(RDWR_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT)),
                   0x55, 1UL << L2_PAGETABLE_SHIFT);
        }
        if ( !((unsigned long)l2_ro_mpt & ~PAGE_MASK) )
        {
            if ( (l2_pg = alloc_domheap_page(NULL, memflags)) == NULL )
                goto nomem;
            l2_ro_mpt = page_to_virt(l2_pg);
            clear_page(l2_ro_mpt);
            l3e_write(&l3_ro_mpt[l3_table_offset(va)],
                      l3e_from_page(l2_pg, __PAGE_HYPERVISOR | _PAGE_USER));
            ASSERT(!l2_table_offset(va));
        }
        /* NB. Cannot be GLOBAL as shadow_mode_translate reuses this area. */
        if ( l1_pg )
            l2e_write(l2_ro_mpt, l2e_from_page(
                l1_pg, /*_PAGE_GLOBAL|*/_PAGE_PSE|_PAGE_USER|_PAGE_PRESENT));
        l2_ro_mpt++;
    }
#undef CNT
#undef MFN

    /* Create user-accessible L2 directory to map the MPT for compat guests. */
    BUILD_BUG_ON(l4_table_offset(RDWR_MPT_VIRT_START) !=
                 l4_table_offset(HIRO_COMPAT_MPT_VIRT_START));
    l3_ro_mpt = l4e_to_l3e(idle_pg_table[l4_table_offset(
        HIRO_COMPAT_MPT_VIRT_START)]);
    if ( (l2_pg = alloc_domheap_page(NULL, 0)) == NULL )
        goto nomem;
    compat_idle_pg_table_l2 = l2_ro_mpt = page_to_virt(l2_pg);
    clear_page(l2_ro_mpt);
    l3e_write(&l3_ro_mpt[l3_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
              l3e_from_page(l2_pg, __PAGE_HYPERVISOR));
    l2_ro_mpt += l2_table_offset(HIRO_COMPAT_MPT_VIRT_START);
    /* Allocate and map the compatibility mode machine-to-phys table. */
    mpt_size = (mpt_size >> 1) + (1UL << (L2_PAGETABLE_SHIFT - 1));
    if ( mpt_size > RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START )
        mpt_size = RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START;
    mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
    if ( (m2p_compat_vstart + mpt_size) < MACH2PHYS_COMPAT_VIRT_END )
        m2p_compat_vstart = MACH2PHYS_COMPAT_VIRT_END - mpt_size;
#define MFN(x) (((x) << L2_PAGETABLE_SHIFT) / sizeof(unsigned int))
#define CNT ((sizeof(*frame_table) & -sizeof(*frame_table)) / \
             sizeof(*compat_machine_to_phys_mapping))
    BUILD_BUG_ON((sizeof(*frame_table) & ~sizeof(*frame_table)) % \
                 sizeof(*compat_machine_to_phys_mapping));
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++, l2_ro_mpt++ )
    {
        memflags = MEMF_node(phys_to_nid(i <<
            (L2_PAGETABLE_SHIFT - 2 + PAGE_SHIFT)));
        for ( n = 0; n < CNT; ++n)
            if ( mfn_valid(MFN(i) + n * PDX_GROUP_COUNT) )
                break;
        if ( n == CNT )
            continue;
        if ( (l1_pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER,
                                               memflags)) == NULL )
            goto nomem;
        map_pages_to_xen(
            RDWR_COMPAT_MPT_VIRT_START + (i << L2_PAGETABLE_SHIFT),
            page_to_mfn(l1_pg),
            1UL << PAGETABLE_ORDER,
            PAGE_HYPERVISOR);
        memset((void *)(RDWR_COMPAT_MPT_VIRT_START +
                        (i << L2_PAGETABLE_SHIFT)),
               0x55,
               1UL << L2_PAGETABLE_SHIFT);
        /* NB. Cannot be GLOBAL as the ptes get copied into per-VM space. */
        l2e_write(l2_ro_mpt, l2e_from_page(l1_pg, _PAGE_PSE|_PAGE_PRESENT));
    }
#undef CNT
#undef MFN

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
    BUG_ON(num_online_cpus() != 1);

    /* Remove aliased mapping of first 1:1 PML4 entry. */
    l4e_write(&idle_pg_table[0], l4e_empty());
    flush_local(FLUSH_TLB_GLOBAL);

    /* Replace with mapping of the boot trampoline only. */
    map_pages_to_xen(BOOT_TRAMPOLINE, BOOT_TRAMPOLINE >> PAGE_SHIFT,
                     0x10, __PAGE_HYPERVISOR);
}

int __cpuinit setup_compat_arg_xlat(unsigned int cpu, int node)
{
    unsigned int order = get_order_from_bytes(COMPAT_ARG_XLAT_SIZE);
    unsigned long sz = PAGE_SIZE << order;
    unsigned int memflags = node != NUMA_NO_NODE ? MEMF_node(node) : 0;
    struct page_info *pg;

    pg = alloc_domheap_pages(NULL, order, memflags);
    if ( !pg )
        return -ENOMEM;

    for ( ; (sz -= PAGE_SIZE) >= COMPAT_ARG_XLAT_SIZE; ++pg )
        free_domheap_page(pg);

    per_cpu(compat_arg_xlat, cpu) = page_to_virt(pg);

    return 0;
}

void __init subarch_init_memory(void)
{
    unsigned long i, n, v, m2p_start_mfn;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;

    BUILD_BUG_ON(RDWR_MPT_VIRT_START & ((1UL << L3_PAGETABLE_SHIFT) - 1));
    BUILD_BUG_ON(RDWR_MPT_VIRT_END   & ((1UL << L3_PAGETABLE_SHIFT) - 1));
    /* M2P table is mappable read-only by privileged domains. */
    for ( v  = RDWR_MPT_VIRT_START;
          v != RDWR_MPT_VIRT_END;
          v += n << PAGE_SHIFT )
    {
        n = L2_PAGETABLE_ENTRIES * L1_PAGETABLE_ENTRIES;
        l3e = l4e_to_l3e(idle_pg_table[l4_table_offset(v)])[
            l3_table_offset(v)];
        if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
            continue;
        if ( !(l3e_get_flags(l3e) & _PAGE_PSE) )
        {
            n = L1_PAGETABLE_ENTRIES;
            l2e = l3e_to_l2e(l3e)[l2_table_offset(v)];
            if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
                continue;
            m2p_start_mfn = l2e_get_pfn(l2e);
        }
        else
        {
            m2p_start_mfn = l3e_get_pfn(l3e);
        }

        for ( i = 0; i < n; i++ )
        {
            struct page_info *page = mfn_to_page(m2p_start_mfn + i);
            share_xen_page_with_privileged_guests(page, XENSHARE_readonly);
        }
    }

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

    if ( setup_compat_arg_xlat(smp_processor_id(),
                               apicid_to_node[boot_cpu_physical_apicid]) )
        panic("Could not setup argument translation area");
}

long subarch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct xen_machphys_mfn_list xmml;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;
    unsigned long v;
    xen_pfn_t mfn, last_mfn;
    unsigned int i;
    long rc = 0;

    switch ( op )
    {
    case XENMEM_machphys_mfn_list:
        if ( copy_from_guest(&xmml, arg, 1) )
            return -EFAULT;

        BUILD_BUG_ON(RDWR_MPT_VIRT_START & ((1UL << L3_PAGETABLE_SHIFT) - 1));
        BUILD_BUG_ON(RDWR_MPT_VIRT_END   & ((1UL << L3_PAGETABLE_SHIFT) - 1));
        for ( i = 0, v = RDWR_MPT_VIRT_START, last_mfn = 0;
              (i != xmml.max_extents) &&
              (v < (unsigned long)(machine_to_phys_mapping + max_page));
              i++, v += 1UL << L2_PAGETABLE_SHIFT )
        {
            l3e = l4e_to_l3e(idle_pg_table[l4_table_offset(v)])[
                l3_table_offset(v)];
            if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
                mfn = last_mfn;
            else if ( !(l3e_get_flags(l3e) & _PAGE_PSE) )
            {
                l2e = l3e_to_l2e(l3e)[l2_table_offset(v)];
                if ( l2e_get_flags(l2e) & _PAGE_PRESENT )
                    mfn = l2e_get_pfn(l2e);
                else
                    mfn = last_mfn;
            }
            else
            {
                mfn = l3e_get_pfn(l3e)
                    + (l2_table_offset(v) << PAGETABLE_ORDER);
            }
            ASSERT(mfn);
            if ( copy_to_guest_offset(xmml.extent_start, i, &mfn, 1) )
                return -EFAULT;
            last_mfn = mfn;
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
    unsigned int dpl;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /* Check and fix up the DPL. */
    dpl = (b >> 13) & 3;
    __fixup_guest_selector(dom, dpl);
    b = (b & ~_SEGMENT_DPL) | (dpl << 13);

    /* All code and data segments are okay. No base/limit checking. */
    if ( (b & _SEGMENT_S) )
    {
        if ( is_pv_32bit_domain(dom) )
        {
            unsigned long base, limit;

            if ( b & _SEGMENT_L )
                goto bad;

            /*
             * Older PAE Linux guests use segments which are limited to
             * 0xf6800000. Extend these to allow access to the larger read-only
             * M2P table available in 32on64 mode.
             */
            base = (b & (0xff << 24)) | ((b & 0xff) << 16) | (a >> 16);

            limit = (b & 0xf0000) | (a & 0xffff);
            limit++; /* We add one because limit is inclusive. */

            if ( (b & _SEGMENT_G) )
                limit <<= 12;

            if ( (base == 0) && (limit > HYPERVISOR_COMPAT_VIRT_START(dom)) )
            {
                a |= 0x0000ffff;
                b |= 0x000f0000;
            }
        }

        goto good;
    }

    /* Invalid type 0 is harmless. It is used for 2nd half of a call gate. */
    if ( (b & _SEGMENT_TYPE) == 0x000 )
        goto good;

    /* Everything but a call gate is discarded here. */
    if ( (b & _SEGMENT_TYPE) != 0xc00 )
        goto bad;

    /* Validate the target code selector. */
    cs = a >> 16;
    if ( !guest_gate_selector_okay(dom, cs) )
        goto bad;
    /*
     * Force DPL to zero, causing a GP fault with its error code indicating
     * the gate in use, allowing emulation. This is necessary because with
     * native guests (kernel in ring 3) call gates cannot be used directly
     * to transition from user to kernel mode (and whether a gate is used
     * to enter the kernel can only be determined when the gate is being
     * used), and with compat guests call gates cannot be used at all as
     * there are only 64-bit ones.
     * Store the original DPL in the selector's RPL field.
     */
    b &= ~_SEGMENT_DPL;
    cs = (cs & ~3) | dpl;
    a = (a & 0xffffU) | (cs << 16);

    /* Reserved bits must be zero. */
    if ( b & (is_pv_32bit_domain(dom) ? 0xe0 : 0xff) )
        goto bad;
        
 good:
    d->a = a;
    d->b = b;
    return 1;
 bad:
    return 0;
}

void domain_set_alloc_bitsize(struct domain *d)
{
    if ( !is_pv_32on64_domain(d) ||
         (MACH2PHYS_COMPAT_NR_ENTRIES(d) >= max_page) ||
         d->arch.physaddr_bitsize > 0 )
        return;
    d->arch.physaddr_bitsize =
        /* 2^n entries can be contained in guest's p2m mapping space */
        fls(MACH2PHYS_COMPAT_NR_ENTRIES(d)) - 1
        /* 2^n pages -> 2^(n+PAGE_SHIFT) bits */
        + PAGE_SHIFT;
}

unsigned int domain_clamp_alloc_bitsize(struct domain *d, unsigned int bits)
{
    if ( (d == NULL) || (d->arch.physaddr_bitsize == 0) )
        return bits;
    return min(d->arch.physaddr_bitsize, bits);
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
