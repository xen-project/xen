/*
 * xen/arch/arm/mm.c
 *
 * MMU code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
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
 */

#include <xen/config.h>
#include <xen/compile.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/preempt.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <asm/page.h>
#include <asm/current.h>
#include <public/memory.h>
#include <xen/sched.h>

struct domain *dom_xen, *dom_io;

/* Static start-of-day pagetables that we use before the allocators are up */
lpae_t xen_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
lpae_t xen_second[LPAE_ENTRIES*4] __attribute__((__aligned__(4096*4)));
static lpae_t xen_fixmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
static lpae_t xen_xenmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));

/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t boot_httbr;

static paddr_t phys_offset;

/* Limits of the Xen heap */
unsigned long xenheap_mfn_start, xenheap_mfn_end;
unsigned long xenheap_virt_end;

unsigned long frametable_base_mfn;
unsigned long frametable_virt_end;

unsigned long max_page;

extern char __init_begin[], __init_end[];

void dump_pt_walk(lpae_t *first, paddr_t addr)
{
    lpae_t *second = NULL, *third = NULL;

    if ( first_table_offset(addr) >= LPAE_ENTRIES )
        return;

    printk("1ST[0x%llx] = 0x%"PRIpaddr"\n",
           first_table_offset(addr),
           first[first_table_offset(addr)].bits);
    if ( !first[first_table_offset(addr)].walk.valid ||
         !first[first_table_offset(addr)].walk.table )
        goto done;

    second = map_domain_page(first[first_table_offset(addr)].walk.base);
    printk("2ND[0x%llx] = 0x%"PRIpaddr"\n",
           second_table_offset(addr),
           second[second_table_offset(addr)].bits);
    if ( !second[second_table_offset(addr)].walk.valid ||
         !second[second_table_offset(addr)].walk.table )
        goto done;

    third = map_domain_page(second[second_table_offset(addr)].walk.base);
    printk("3RD[0x%llx] = 0x%"PRIpaddr"\n",
           third_table_offset(addr),
           third[third_table_offset(addr)].bits);

done:
    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);

}

void dump_hyp_walk(uint32_t addr)
{
    uint64_t httbr = READ_CP64(HTTBR);

    printk("Walking Hypervisor VA 0x%08"PRIx32" via HTTBR 0x%016"PRIx64"\n",
           addr, httbr);

    BUG_ON( (lpae_t *)(unsigned long)(httbr - phys_offset) != xen_pgtable );
    dump_pt_walk(xen_pgtable, addr);
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, unsigned long mfn, unsigned attributes)
{
    lpae_t pte = mfn_to_xen_entry(mfn);
    pte.pt.table = 1; /* 4k mappings always have this bit set */
    pte.pt.ai = attributes;
    pte.pt.xn = 1;
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_va(FIXMAP_ADDR(map));
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    lpae_t pte = {0};
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_va(FIXMAP_ADDR(map));
}

/* Map a page of domheap memory */
void *map_domain_page(unsigned long mfn)
{
    unsigned long flags;
    lpae_t *map = xen_second + second_linear_offset(DOMHEAP_VIRT_START);
    unsigned long slot_mfn = mfn & ~LPAE_ENTRY_MASK;
    uint32_t va;
    lpae_t pte;
    int i, slot;

    local_irq_save(flags);

    /* The map is laid out as an open-addressed hash table where each
     * entry is a 2MB superpage pte.  We use the available bits of each
     * PTE as a reference count; when the refcount is zero the slot can
     * be reused. */
    for ( slot = (slot_mfn >> LPAE_SHIFT) % DOMHEAP_ENTRIES, i = 0;
          i < DOMHEAP_ENTRIES;
          slot = (slot + 1) % DOMHEAP_ENTRIES, i++ )
    {
        if ( map[slot].pt.avail == 0 )
        {
            /* Commandeer this 2MB slot */
            pte = mfn_to_xen_entry(slot_mfn);
            pte.pt.avail = 1;
            write_pte(map + slot, pte);
            break;
        }
        else if ( map[slot].pt.avail < 0xf && map[slot].pt.base == slot_mfn )
        {
            /* This slot already points to the right place; reuse it */
            map[slot].pt.avail++;
            break;
        }
    }
    /* If the map fills up, the callers have misbehaved. */
    BUG_ON(i == DOMHEAP_ENTRIES);

#ifndef NDEBUG
    /* Searching the hash could get slow if the map starts filling up.
     * Cross that bridge when we come to it */
    {
        static int max_tries = 32;
        if ( i >= max_tries )
        {
            dprintk(XENLOG_WARNING, "Domheap map is filling: %i tries\n", i);
            max_tries *= 2;
        }
    }
#endif

    local_irq_restore(flags);

    va = (DOMHEAP_VIRT_START
          + (slot << SECOND_SHIFT)
          + ((mfn & LPAE_ENTRY_MASK) << THIRD_SHIFT));

    /*
     * We may not have flushed this specific subpage at map time,
     * since we only flush the 4k page not the superpage
     */
    flush_xen_data_tlb_va(va);

    return (void *)va;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *va)
{
    unsigned long flags;
    lpae_t *map = xen_second + second_linear_offset(DOMHEAP_VIRT_START);
    int slot = ((unsigned long) va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;

    local_irq_save(flags);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    map[slot].pt.avail--;

    local_irq_restore(flags);
}


/* Boot-time pagetable setup.
 * Changes here may need matching changes in head.S */
void __init setup_pagetables(unsigned long boot_phys_offset)
{
    paddr_t xen_paddr;
    unsigned long dest_va;
    lpae_t pte, *p;
    int i;

    xen_paddr = device_tree_get_xen_paddr();

    /* Map the destination in the boot misc area. */
    dest_va = BOOT_MISC_VIRT_START;
    pte = mfn_to_xen_entry(xen_paddr >> PAGE_SHIFT);
    write_pte(xen_second + second_table_offset(dest_va), pte);
    flush_xen_data_tlb_va(dest_va);

    /* Calculate virt-to-phys offset for the new location */
    phys_offset = xen_paddr - (unsigned long) _start;

    /* Copy */
    memcpy((void *) dest_va, _start, _end - _start);

    /* Beware!  Any state we modify between now and the PT switch may be
     * discarded when we switch over to the copy. */

    /* Update the copy of xen_pgtable to use the new paddrs */
    p = (void *) xen_pgtable + dest_va - (unsigned long) _start;
    for ( i = 0; i < 4; i++)
        p[i].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;
    p = (void *) xen_second + dest_va - (unsigned long) _start;
    if ( boot_phys_offset != 0 )
    {
        /* Remove the old identity mapping of the boot paddr */
        unsigned long va = (unsigned long)_start + boot_phys_offset;
        p[second_linear_offset(va)].bits = 0;
    }
    for ( i = 0; i < 4 * LPAE_ENTRIES; i++)
        if ( p[i].pt.valid )
                p[i].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;

    /* Change pagetables to the copy in the relocated Xen */
    boot_httbr = (unsigned long) xen_pgtable + phys_offset;
    asm volatile (
        STORE_CP64(0, HTTBR)          /* Change translation base */
        "dsb;"                        /* Ensure visibility of HTTBR update */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" (boot_httbr) : "memory");

    /* Undo the temporary map */
    pte.bits = 0;
    write_pte(xen_second + second_table_offset(dest_va), pte);
    flush_xen_text_tlb();

    /* Link in the fixmap pagetable */
    pte = mfn_to_xen_entry((((unsigned long) xen_fixmap) + phys_offset)
                           >> PAGE_SHIFT);
    pte.pt.table = 1;
    write_pte(xen_second + second_table_offset(FIXMAP_ADDR(0)), pte);
    /*
     * No flush required here. Individual flushes are done in
     * set_fixmap as entries are used.
     */

    /* Break up the Xen mapping into 4k pages and protect them separately. */
    for ( i = 0; i < LPAE_ENTRIES; i++ )
    {
        unsigned long mfn = paddr_to_pfn(xen_paddr) + i;
        unsigned long va = XEN_VIRT_START + (i << PAGE_SHIFT);
        if ( !is_kernel(va) )
            break;
        pte = mfn_to_xen_entry(mfn);
        pte.pt.table = 1; /* 4k mappings always have this bit set */
        if ( is_kernel_text(va) || is_kernel_inittext(va) )
        {
            pte.pt.xn = 0;
            pte.pt.ro = 1;
        }
        if ( is_kernel_rodata(va) )
            pte.pt.ro = 1;
        write_pte(xen_xenmap + i, pte);
        /* No flush required here as page table is not hooked in yet. */
    }
    pte = mfn_to_xen_entry((((unsigned long) xen_xenmap) + phys_offset)
                           >> PAGE_SHIFT);
    pte.pt.table = 1;
    write_pte(xen_second + second_linear_offset(XEN_VIRT_START), pte);
    /* Have changed a mapping used for .text. Flush everything for safety. */
    flush_xen_text_tlb();

    /* From now on, no mapping may be both writable and executable. */
    WRITE_CP32(READ_CP32(HSCTLR) | SCTLR_WXN, HSCTLR);
}

/* MMU setup for secondary CPUS (which already have paging enabled) */
void __cpuinit mmu_init_secondary_cpu(void)
{
    /* From now on, no mapping may be both writable and executable. */
    WRITE_CP32(READ_CP32(HSCTLR) | SCTLR_WXN, HSCTLR);
}

/* Create Xen's mappings of memory.
 * Base and virt must be 32MB aligned and size a multiple of 32MB. */
static void __init create_mappings(unsigned long virt,
                                   unsigned long base_mfn,
                                   unsigned long nr_mfns)
{
    unsigned long i, count;
    lpae_t pte, *p;

    ASSERT(!((virt >> PAGE_SHIFT) % (16 * LPAE_ENTRIES)));
    ASSERT(!(base_mfn % (16 * LPAE_ENTRIES)));
    ASSERT(!(nr_mfns % (16 * LPAE_ENTRIES)));

    count = nr_mfns / LPAE_ENTRIES;
    p = xen_second + second_linear_offset(virt);
    pte = mfn_to_xen_entry(base_mfn);
    pte.pt.hint = 1;  /* These maps are in 16-entry contiguous chunks. */
    for ( i = 0; i < count; i++ )
    {
        write_pte(p + i, pte);
        pte.pt.base += 1 << LPAE_SHIFT;
    }
    flush_xen_data_tlb();
}

/* Set up the xenheap: up to 1GB of contiguous, always-mapped memory. */
void __init setup_xenheap_mappings(unsigned long base_mfn,
                                   unsigned long nr_mfns)
{
    create_mappings(XENHEAP_VIRT_START, base_mfn, nr_mfns);

    /* Record where the xenheap is, for translation routines. */
    xenheap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
    xenheap_mfn_start = base_mfn;
    xenheap_mfn_end = base_mfn + nr_mfns;
}

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pages = (pe - ps) >> PAGE_SHIFT;
    unsigned long frametable_size = nr_pages * sizeof(struct page_info);
    unsigned long base_mfn;

    frametable_base_mfn = ps >> PAGE_SHIFT;

    /* Round up to 32M boundary */
    frametable_size = (frametable_size + 0x1ffffff) & ~0x1ffffff;
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 5);
    create_mappings(FRAMETABLE_VIRT_START, base_mfn, frametable_size >> PAGE_SHIFT);

    memset(&frame_table[0], 0, nr_pages * sizeof(struct page_info));
    memset(&frame_table[nr_pages], -1,
           frametable_size - (nr_pages * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pages * sizeof(struct page_info));
}

enum mg { mg_clear, mg_ro, mg_rw, mg_rx };
static void set_pte_flags_on_range(const char *p, unsigned long l, enum mg mg)
{
    lpae_t pte;
    int i;

    ASSERT(is_kernel(p) && is_kernel(p + l));

    /* Can only guard in page granularity */
    ASSERT(!((unsigned long) p & ~PAGE_MASK));
    ASSERT(!(l & ~PAGE_MASK));

    for ( i = (p - _start) / PAGE_SIZE; 
          i < (p + l - _start) / PAGE_SIZE; 
          i++ )
    {
        pte = xen_xenmap[i];
        switch ( mg )
        {
        case mg_clear:
            pte.pt.valid = 0;
            break;
        case mg_ro:
            pte.pt.valid = 1;
            pte.pt.pxn = 1;
            pte.pt.xn = 1;
            pte.pt.ro = 1;
            break;
        case mg_rw:
            pte.pt.valid = 1;
            pte.pt.pxn = 1;
            pte.pt.xn = 1;
            pte.pt.ro = 0;
            break;
        case mg_rx:
            pte.pt.valid = 1;
            pte.pt.pxn = 0;
            pte.pt.xn = 0;
            pte.pt.ro = 1;
            break;
        }
        write_pte(xen_xenmap + i, pte);
    }
    flush_xen_text_tlb();
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    paddr_t pa = virt_to_maddr(__init_begin);
    unsigned long len = __init_end - __init_begin;
    set_pte_flags_on_range(__init_begin, len, mg_rw);
    memset(__init_begin, 0xcc, len);
    set_pte_flags_on_range(__init_begin, len, mg_clear);
    init_domheap_pages(pa, pa + len);
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);
}

void arch_dump_shared_mem_info(void)
{
}

int donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    ASSERT(0);
    return -ENOSYS;
}

void share_xen_page_with_guest(struct page_info *page,
                          struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT((page->count_info & ~PGC_xen_heap) == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        page_list_add_tail(page, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

static int xenmem_add_to_physmap_once(
    struct domain *d,
    const struct xen_add_to_physmap *xatp)
{
    unsigned long mfn = 0;
    int rc;

    switch ( xatp->space )
    {
        case XENMAPSPACE_shared_info:
            if ( xatp->idx == 0 )
                mfn = virt_to_mfn(d->shared_info);
            break;
        default:
            return -ENOSYS;
    }

    domain_lock(d);

    /* Map at new location. */
    rc = guest_physmap_add_page(d, xatp->gpfn, mfn, 0);

    domain_unlock(d);

    return rc;
}

static int xenmem_add_to_physmap(struct domain *d,
                                 struct xen_add_to_physmap *xatp)
{
    return xenmem_add_to_physmap_once(d, xatp);
}

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    int rc;

    switch ( op )
    {
    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;
        struct domain *d;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(xatp.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = xenmem_add_to_physmap(d, &xatp);

        rcu_unlock_domain(d);

        return rc;
    }

    default:
        return -ENOSYS;
    }

    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
