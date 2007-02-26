/******************************************************************************
 * arch/x86/x86_32/mm.c
 * 
 * Modifications to Linux original are copyright (c) 2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <public/memory.h>

unsigned int PAGE_HYPERVISOR         = __PAGE_HYPERVISOR;
unsigned int PAGE_HYPERVISOR_NOCACHE = __PAGE_HYPERVISOR_NOCACHE;

static unsigned long mpt_size;

void *alloc_xen_pagetable(void)
{
    extern int early_boot;
    extern unsigned long xenheap_phys_start;
    unsigned long mfn;

    if ( !early_boot )
    {
        void *v = alloc_xenheap_page();
        BUG_ON(v == NULL);
        return v;
    }

    mfn = xenheap_phys_start >> PAGE_SHIFT;
    xenheap_phys_start += PAGE_SIZE;
    return mfn_to_virt(mfn);
}

void free_xen_pagetable(void *v)
{
    free_xenheap_page(v);
}

l2_pgentry_t *virt_to_xen_l2e(unsigned long v)
{
    return &idle_pg_table_l2[l2_linear_offset(v)];
}

void __init paging_init(void)
{
    void *ioremap_pt;
    unsigned long v;
    struct page_info *pg;
    int i;

#ifdef CONFIG_X86_PAE
    printk("PAE enabled, limit: %d GB\n", MACHPHYS_MBYTES);
#else
    printk("PAE disabled.\n");
#endif

    if ( cpu_has_pge )
    {
        /* Suitable Xen mapping can be GLOBAL. */
        set_in_cr4(X86_CR4_PGE);
        PAGE_HYPERVISOR         |= _PAGE_GLOBAL;
        PAGE_HYPERVISOR_NOCACHE |= _PAGE_GLOBAL;
        /* Transform early mappings (e.g., the frametable). */
        for ( v = HYPERVISOR_VIRT_START; v; v += (1 << L2_PAGETABLE_SHIFT) )
            if ( (l2e_get_flags(idle_pg_table_l2[l2_linear_offset(v)]) &
                  (_PAGE_PSE|_PAGE_PRESENT)) == (_PAGE_PSE|_PAGE_PRESENT) )
                l2e_add_flags(idle_pg_table_l2[l2_linear_offset(v)],
                              _PAGE_GLOBAL);
    }

    /*
     * Allocate and map the machine-to-phys table and create read-only mapping 
     * of MPT for guest-OS use.
     */
    mpt_size  = (max_page * BYTES_PER_LONG) + (1UL << L2_PAGETABLE_SHIFT) - 1;
    mpt_size &= ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        if ( (pg = alloc_domheap_pages(NULL, PAGETABLE_ORDER, 0)) == NULL )
            panic("Not enough memory to bootstrap Xen.\n");
        l2e_write(&idle_pg_table_l2[l2_linear_offset(RDWR_MPT_VIRT_START) + i],
                  l2e_from_page(pg, PAGE_HYPERVISOR | _PAGE_PSE));
        /* NB. Cannot be GLOBAL as shadow_mode_translate reuses this area. */
        l2e_write(&idle_pg_table_l2[l2_linear_offset(RO_MPT_VIRT_START) + i],
                  l2e_from_page(
                      pg, (__PAGE_HYPERVISOR | _PAGE_PSE) & ~_PAGE_RW));
    }

    /* Fill with an obvious debug pattern. */
    for ( i = 0; i < (mpt_size / BYTES_PER_LONG); i++)
        set_gpfn_from_mfn(i, 0x55555555);

    /* Create page tables for ioremap(). */
    for ( i = 0; i < (IOREMAP_MBYTES >> (L2_PAGETABLE_SHIFT - 20)); i++ )
    {
        ioremap_pt = alloc_xenheap_page();
        clear_page(ioremap_pt);
        l2e_write(&idle_pg_table_l2[l2_linear_offset(IOREMAP_VIRT_START) + i],
                  l2e_from_page(virt_to_page(ioremap_pt), __PAGE_HYPERVISOR));
    }
}

void __init setup_idle_pagetable(void)
{
    int i;

    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        l2e_write(&idle_pg_table_l2[l2_linear_offset(PERDOMAIN_VIRT_START)+i],
                  l2e_from_page(virt_to_page(idle_vcpu[0]->domain->
                                             arch.mm_perdomain_pt) + i,
                                __PAGE_HYPERVISOR));
}

void __init zap_low_mappings(l2_pgentry_t *base)
{
    int i;
    u32 addr;

    for ( i = 0; ; i++ )
    {
        addr = i << L2_PAGETABLE_SHIFT;
        if ( addr >= HYPERVISOR_VIRT_START )
            break;
        if ( l2e_get_paddr(base[i]) != addr )
            continue;
        l2e_write(&base[i], l2e_empty());
    }

    flush_tlb_all_pge();
}

void subarch_init_memory(void)
{
    unsigned long m2p_start_mfn;
    unsigned int i, j;

    /*
     * We are rather picky about the layout of 'struct page_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them. Also, just for sanity, we assert the size
     * of the structure here.
     */
    BUILD_BUG_ON(offsetof(struct page_info, u.inuse._domain) != 
                 (offsetof(struct page_info, count_info) + sizeof(u32)));
    BUILD_BUG_ON((offsetof(struct page_info, count_info) & 7) != 0);
    BUILD_BUG_ON(sizeof(struct page_info) != 24);

    /* M2P table is mappable read-only by privileged domains. */
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        m2p_start_mfn = l2e_get_pfn(
            idle_pg_table_l2[l2_linear_offset(RDWR_MPT_VIRT_START) + i]);
        for ( j = 0; j < L2_PAGETABLE_ENTRIES; j++ )
        {
            struct page_info *page = mfn_to_page(m2p_start_mfn + j);
            share_xen_page_with_privileged_guests(page, XENSHARE_readonly);
        }
    }

    if ( supervisor_mode_kernel )
    {
        /* Guest kernel runs in ring 0, not ring 1. */
        struct desc_struct *d;
        d = &gdt_table[(FLAT_RING1_CS >> 3) - FIRST_RESERVED_GDT_ENTRY];
        d[0].b &= ~_SEGMENT_DPL;
        d[1].b &= ~_SEGMENT_DPL;
    }
}

long subarch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct xen_machphys_mfn_list xmml;
    unsigned long mfn;
    unsigned int i, max;
    long rc = 0;

    switch ( op )
    {
    case XENMEM_machphys_mfn_list:
        if ( copy_from_guest(&xmml, arg, 1) )
            return -EFAULT;

        max = min_t(unsigned int, xmml.max_extents, mpt_size >> 21);

        for ( i = 0; i < max; i++ )
        {
            mfn = l2e_get_pfn(idle_pg_table_l2[l2_linear_offset(
                RDWR_MPT_VIRT_START + (i << 21))]) + l1_table_offset(i << 21);
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
    int nr = smp_processor_id();
    struct tss_struct *t = &init_tss[nr];

    fixup_guest_stack_selector(current->domain, ss);

    current->arch.guest_context.kernel_ss = ss;
    current->arch.guest_context.kernel_sp = esp;
    t->ss1  = ss;
    t->esp1 = esp;

    return 0;
}

/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(const struct domain *dom, struct desc_struct *d)
{
    unsigned long base, limit;
    u32 a = d->a, b = d->b;
    u16 cs;

    /* Let a ring0 guest kernel set any descriptor it wants to. */
    if ( supervisor_mode_kernel )
        return 1;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /*
     * We don't allow a DPL of zero. There is no legitimate reason for 
     * specifying DPL==0, and it gets rather dangerous if we also accept call 
     * gates (consider a call gate pointing at another kernel descriptor with 
     * DPL 0 -- this would get the OS ring-0 privileges).
     */
    if ( (b & _SEGMENT_DPL) < (GUEST_KERNEL_RPL(dom) << 13) )
        d->b = b = (b & ~_SEGMENT_DPL) | (GUEST_KERNEL_RPL(dom) << 13);

    if ( !(b & _SEGMENT_S) )
    {
        /*
         * System segment:
         *  1. Don't allow interrupt or trap gates as they belong in the IDT.
         *  2. Don't allow TSS descriptors or task gates as we don't
         *     virtualise x86 tasks.
         *  3. Don't allow LDT descriptors because they're unnecessary and
         *     I'm uneasy about allowing an LDT page to contain LDT
         *     descriptors. In any case, Xen automatically creates the
         *     required descriptor when reloading the LDT register.
         *  4. We allow call gates but they must not jump to a private segment.
         */

        /* Disallow everything but call gates. */
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
        
        /* No base/limit check is needed for a call gate. */
        goto good;
    }
    
    /* Check that base is at least a page away from Xen-private area. */
    base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    if ( base >= (GUEST_SEGMENT_MAX_ADDR - PAGE_SIZE) )
        goto bad;

    /* Check and truncate the limit if necessary. */
    limit = (b&0xf0000) | (a&0xffff);
    limit++; /* We add one because limit is inclusive. */
    if ( (b & _SEGMENT_G) )
        limit <<= 12;

    if ( (b & (_SEGMENT_CODE | _SEGMENT_EC)) == _SEGMENT_EC )
    {
        /*
         * DATA, GROWS-DOWN.
         * Grows-down limit check. 
         * NB. limit == 0xFFFFF provides no access      (if G=1).
         *     limit == 0x00000 provides 4GB-4kB access (if G=1).
         */
        if ( (base + limit) > base )
        {
            limit = -(base & PAGE_MASK);
            goto truncate;
        }
    }
    else
    {
        /*
         * DATA, GROWS-UP. 
         * CODE (CONFORMING AND NON-CONFORMING).
         * Grows-up limit check.
         * NB. limit == 0xFFFFF provides 4GB access (if G=1).
         *     limit == 0x00000 provides 4kB access (if G=1).
         */
        if ( ((base + limit) <= base) || 
             ((base + limit) > GUEST_SEGMENT_MAX_ADDR) )
        {
            limit = GUEST_SEGMENT_MAX_ADDR - base;
        truncate:
            if ( !(b & _SEGMENT_G) )
                goto bad; /* too dangerous; too hard to work out... */
            limit = (limit >> 12) - 1;
            d->a &= ~0x0ffff; d->a |= limit & 0x0ffff;
            d->b &= ~0xf0000; d->b |= limit & 0xf0000;
        }
    }

 good:
    return 1;
 bad:
    return 0;
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
