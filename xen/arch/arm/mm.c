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
#include <asm/page.h>
#include <asm/current.h>

struct domain *dom_xen, *dom_io;

/* Static start-of-day pagetables that we use before the allocators are up */
lpae_t xen_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
lpae_t xen_second[LPAE_ENTRIES*4] __attribute__((__aligned__(4096*4)));
static lpae_t xen_fixmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
static lpae_t xen_xenmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));

/* Limits of the Xen heap */
unsigned long xenheap_mfn_start, xenheap_mfn_end;
unsigned long xenheap_virt_end;

unsigned long frametable_base_mfn;
unsigned long frametable_virt_end;

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, unsigned long mfn, unsigned attributes)
{
    lpae_t pte = mfn_to_xen_entry(mfn);
    pte.pt.table = 1; /* 4k mappings always have this bit set */
    pte.pt.ai = attributes;
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
    paddr_t xen_paddr, phys_offset;
    unsigned long dest_va;
    lpae_t pte, *p;
    int i;

    if ( boot_phys_offset != 0 )
    {
        /* Remove the old identity mapping of the boot paddr */
        pte.bits = 0;
        dest_va = (unsigned long)_start + boot_phys_offset;
        write_pte(xen_second + second_linear_offset(dest_va), pte);
    }

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
    for ( i = 0; i < 4 * LPAE_ENTRIES; i++)
        if ( p[i].pt.valid )
                p[i].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;

    /* Change pagetables to the copy in the relocated Xen */
    asm volatile (
        STORE_CP64(0, HTTBR)          /* Change translation base */
        "dsb;"                        /* Ensure visibility of HTTBR update */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" ((unsigned long) xen_pgtable + phys_offset) : "memory");

    /* Undo the temporary map */
    pte.bits = 0;
    write_pte(xen_second + second_table_offset(dest_va), pte);
    /*
     * Have removed a mapping previously used for .text. Flush everything
     * for safety.
     */
    asm volatile (
        "dsb;"                        /* Ensure visibility of PTE write */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" (i /*dummy*/) : "memory");

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
    asm volatile (
        "dsb;"                        /* Ensure visibility of PTE write */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" (i /*dummy*/) : "memory");

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

void arch_dump_shared_mem_info(void)
{
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
