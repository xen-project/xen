/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * arch/x86/x86_64/mm.c
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
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/msr.h>

void *safe_page_alloc(void)
{
    extern int early_boot;
    if ( early_boot )
        return __va(alloc_boot_pages(PAGE_SIZE, PAGE_SIZE));
    return (void *)alloc_xenheap_page();
}

/* Map physical byte range (@p, @p+@s) at virt address @v in pagetable @pt. */
int map_pages(
    root_pgentry_t *pt,
    unsigned long v,
    unsigned long p,
    unsigned long s,
    unsigned long flags)
{
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    void         *newpg;

    while ( s != 0 )
    {
        pl4e = &pt[l4_table_offset(v)];
        if ( !(l4_pgentry_val(*pl4e) & _PAGE_PRESENT) )
        {
            newpg = safe_page_alloc();
            clear_page(newpg);
            *pl4e = mk_l4_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
        }

        pl3e = l4_pgentry_to_l3(*pl4e) + l3_table_offset(v);
        if ( !(l3_pgentry_val(*pl3e) & _PAGE_PRESENT) )
        {
            newpg = safe_page_alloc();
            clear_page(newpg);
            *pl3e = mk_l3_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
        }

        pl2e = l3_pgentry_to_l2(*pl3e) + l2_table_offset(v);

        if ( ((s|v|p) & ((1<<L2_PAGETABLE_SHIFT)-1)) == 0 )
        {
            /* Super-page mapping. */
            if ( (l2_pgentry_val(*pl2e) & _PAGE_PRESENT) )
                __flush_tlb_pge();
            *pl2e = mk_l2_pgentry(p|flags|_PAGE_PSE);

            v += 1 << L2_PAGETABLE_SHIFT;
            p += 1 << L2_PAGETABLE_SHIFT;
            s -= 1 << L2_PAGETABLE_SHIFT;
        }
        else
        {
            /* Normal page mapping. */
            if ( !(l2_pgentry_val(*pl2e) & _PAGE_PRESENT) )
            {
                newpg = safe_page_alloc();
                clear_page(newpg);
                *pl2e = mk_l2_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
            }
            pl1e = l2_pgentry_to_l1(*pl2e) + l1_table_offset(v);
            if ( (l1_pgentry_val(*pl1e) & _PAGE_PRESENT) )
                __flush_tlb_one(v);
            *pl1e = mk_l1_pgentry(p|flags);

            v += 1 << L1_PAGETABLE_SHIFT;
            p += 1 << L1_PAGETABLE_SHIFT;
            s -= 1 << L1_PAGETABLE_SHIFT;
        }
    }

    return 0;
}

void __set_fixmap(
    enum fixed_addresses idx, unsigned long p, unsigned long flags)
{
    if ( unlikely(idx >= __end_of_fixed_addresses) )
        BUG();
    map_pages(idle_pg_table, fix_to_virt(idx), p, PAGE_SIZE, flags);
}


void __init paging_init(void)
{
    void *newpt;
    unsigned long i, p, max;

    /* Map all of physical memory. */
    max = ((max_page + L1_PAGETABLE_ENTRIES - 1) & 
           ~(L1_PAGETABLE_ENTRIES - 1)) << PAGE_SHIFT;
    map_pages(idle_pg_table, PAGE_OFFSET, 0, max, PAGE_HYPERVISOR);

    /*
     * Allocate and map the machine-to-phys table.
     * This also ensures L3 is present for ioremap().
     */
    for ( i = 0; i < max_page; i += ((1UL << L2_PAGETABLE_SHIFT) / 8) )
    {
        p = alloc_boot_pages(1UL << L2_PAGETABLE_SHIFT,
                             1UL << L2_PAGETABLE_SHIFT);
        if ( p == 0 )
            panic("Not enough memory for m2p table\n");
        map_pages(idle_pg_table, RDWR_MPT_VIRT_START + i*8, p, 
                  1UL << L2_PAGETABLE_SHIFT, PAGE_HYPERVISOR);
        memset((void *)(RDWR_MPT_VIRT_START + i*8), 0x55,
               1UL << L2_PAGETABLE_SHIFT);
    }

    /* Create read-only mapping of MPT for guest-OS use. */
    newpt = (void *)alloc_xenheap_page();
    clear_page(newpt);
    idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)] =
        mk_l4_pgentry((__pa(newpt) | __PAGE_HYPERVISOR | _PAGE_USER) &
                      ~_PAGE_RW);
    /* Copy the L3 mappings from the RDWR_MPT area. */
    p  = l4_pgentry_val(idle_pg_table[l4_table_offset(RDWR_MPT_VIRT_START)]);
    p &= PAGE_MASK;
    p += l3_table_offset(RDWR_MPT_VIRT_START) * sizeof(l3_pgentry_t);
    newpt = (void *)((unsigned long)newpt +
                     (l3_table_offset(RO_MPT_VIRT_START) *
                      sizeof(l3_pgentry_t)));
    memcpy(newpt, __va(p),
           (RDWR_MPT_VIRT_END - RDWR_MPT_VIRT_START) >> L3_PAGETABLE_SHIFT);

    /* Set up linear page table mapping. */
    idle_pg_table[l4_table_offset(LINEAR_PT_VIRT_START)] =
        mk_l4_pgentry(__pa(idle_pg_table) | __PAGE_HYPERVISOR);
}

void __init zap_low_mappings(void)
{
    idle_pg_table[0] = mk_l4_pgentry(0);
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
    if ( (offsetof(struct pfn_info, u.inuse._domain) != 
          (offsetof(struct pfn_info, count_info) + sizeof(u32))) )
    {
        printk("Weird pfn_info layout (%ld,%ld,%d)\n",
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
        l3e = l4_pgentry_to_l3(idle_pg_table[l4_table_offset(v)])[
            l3_table_offset(v)];
        if ( !(l3_pgentry_val(l3e) & _PAGE_PRESENT) )
            continue;
        l2e = l3_pgentry_to_l2(l3e)[l2_table_offset(v)];
        if ( !(l2_pgentry_val(l2e) & _PAGE_PRESENT) )
            continue;
        m2p_start_mfn = l2_pgentry_to_pfn(l2e);

        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            frame_table[m2p_start_mfn+i].count_info = PGC_allocated | 1;
            /* gdt to make sure it's only mapped read-only by non-privileged
               domains. */
            frame_table[m2p_start_mfn+i].u.inuse.type_info = PGT_gdt_page | 1;
            page_set_owner(&frame_table[m2p_start_mfn+i], dom_xen);
        }
    }
}

/*
 * Allows shooting down of borrowed page-table use on specific CPUs.
 * Specifically, we borrow page tables when running the idle domain.
 */
static void __synchronise_pagetables(void *mask)
{
    struct exec_domain *ed = current;
    if ( ((unsigned long)mask & (1 << ed->processor)) &&
         is_idle_task(ed->domain) )
        write_ptbase(ed);
}
void synchronise_pagetables(unsigned long cpu_mask)
{
    __synchronise_pagetables((void *)cpu_mask);
    smp_call_function(__synchronise_pagetables, (void *)cpu_mask, 1, 1);
}

long do_stack_switch(unsigned long ss, unsigned long esp)
{
    if ( (ss & 3) != 3 )
        return -EPERM;
    current->arch.kernel_ss = ss;
    current->arch.kernel_sp = esp;
    return 0;
}

long do_set_segment_base(unsigned int which, unsigned long base)
{
    struct exec_domain *ed = current;

    switch ( which )
    {
    case SEGBASE_FS:
        ed->arch.user_ctxt.fs_base = base;
        wrmsr(MSR_FS_BASE, base, base>>32);
        break;

    case SEGBASE_GS_USER:
        ed->arch.user_ctxt.gs_base_user = base;
        wrmsr(MSR_SHADOW_GS_BASE, base, base>>32);
        break;

    case SEGBASE_GS_KERNEL:
        ed->arch.user_ctxt.gs_base_kernel = base;
        wrmsr(MSR_GS_BASE, base, base>>32);
        break;

    default:
        return -EINVAL;
    }

    return 0;
}


/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(struct desc_struct *d)
{
    u32 a = d->a, b = d->b;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /* The guest can only safely be executed in ring 3. */
    if ( (b & _SEGMENT_DPL) != 3 )
        goto bad;

    /* Any code or data segment is okay. No base/limit checking. */
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


#ifdef MEMORY_GUARD

#define ALLOC_PT(_level) \
do { \
    (_level) = (_level ## _pgentry_t *)heap_start; \
    heap_start = (void *)((unsigned long)heap_start + PAGE_SIZE); \
    clear_page(_level); \
} while ( 0 )
void *memguard_init(void *heap_start)
{
    l1_pgentry_t *l1 = NULL;
    l2_pgentry_t *l2 = NULL;
    l3_pgentry_t *l3 = NULL;
    l4_pgentry_t *l4 = &idle_pg_table[l4_table_offset(PAGE_OFFSET)];
    unsigned long i, j;

    /* Round the allocation pointer up to a page boundary. */
    heap_start = (void *)(((unsigned long)heap_start + (PAGE_SIZE-1)) & 
                          PAGE_MASK);

    /* Memory guarding is incompatible with super pages. */
    for ( i = 0; i < (xenheap_phys_end >> L2_PAGETABLE_SHIFT); i++ )
    {
        ALLOC_PT(l1);
        for ( j = 0; j < L1_PAGETABLE_ENTRIES; j++ )
            l1[j] = mk_l1_pgentry((i << L2_PAGETABLE_SHIFT) |
                                   (j << L1_PAGETABLE_SHIFT) | 
                                  __PAGE_HYPERVISOR);
        if ( !((unsigned long)l2 & (PAGE_SIZE-1)) )
        {
            ALLOC_PT(l2);
            if ( !((unsigned long)l3 & (PAGE_SIZE-1)) )
            {
                ALLOC_PT(l3);
                *l4++ = mk_l4_pgentry(virt_to_phys(l3) | __PAGE_HYPERVISOR);
            }
            *l3++ = mk_l3_pgentry(virt_to_phys(l2) | __PAGE_HYPERVISOR);
        }
        *l2++ = mk_l2_pgentry(virt_to_phys(l1) | __PAGE_HYPERVISOR);
    }

    return heap_start;
}

static void __memguard_change_range(void *p, unsigned long l, int guard)
{
    l1_pgentry_t *l1;
    l2_pgentry_t *l2;
    l3_pgentry_t *l3;
    l4_pgentry_t *l4;
    unsigned long _p = (unsigned long)p;
    unsigned long _l = (unsigned long)l;

    /* Ensure we are dealing with a page-aligned whole number of pages. */
    ASSERT((_p&PAGE_MASK) != 0);
    ASSERT((_l&PAGE_MASK) != 0);
    ASSERT((_p&~PAGE_MASK) == 0);
    ASSERT((_l&~PAGE_MASK) == 0);

    while ( _l != 0 )
    {
        l4 = &idle_pg_table[l4_table_offset(_p)];
        l3 = l4_pgentry_to_l3(*l4) + l3_table_offset(_p);
        l2 = l3_pgentry_to_l2(*l3) + l2_table_offset(_p);
        l1 = l2_pgentry_to_l1(*l2) + l1_table_offset(_p);
        if ( guard )
            *l1 = mk_l1_pgentry(l1_pgentry_val(*l1) & ~_PAGE_PRESENT);
        else
            *l1 = mk_l1_pgentry(l1_pgentry_val(*l1) | _PAGE_PRESENT);
        _p += PAGE_SIZE;
        _l -= PAGE_SIZE;
    }
}

void memguard_guard_stack(void *p)
{
    p = (void *)((unsigned long)p + PAGE_SIZE);
    memguard_guard_range(p, 2 * PAGE_SIZE);
}

void memguard_guard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 1);
    local_flush_tlb();
}

void memguard_unguard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 0);
}

#endif
