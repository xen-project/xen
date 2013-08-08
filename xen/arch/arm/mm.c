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
#include <xen/grant_table.h>
#include <xen/softirq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <public/memory.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <xsm/xsm.h>
#include <xen/pfn.h>

struct domain *dom_xen, *dom_io, *dom_cow;

/* Static start-of-day pagetables that we use before the
 * allocators are up. These go on to become the boot CPU's real pagetables.
 */
lpae_t boot_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
#ifdef CONFIG_ARM_64
lpae_t boot_first[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
#endif

/*
 * xen_pgtable and xen_dommap are per-PCPU and are allocated before
 * bringing up each CPU. On 64-bit a first level table is also allocated.
 *
 * xen_second, xen_fixmap and xen_xenmap are shared between all PCPUs.
 */

/* Per-CPU pagetable pages */
/* xen_pgtable == root of the trie (zeroeth level on 64-bit, first on 32-bit) */
static DEFINE_PER_CPU(lpae_t *, xen_pgtable);
#define THIS_CPU_PGTABLE this_cpu(xen_pgtable)
/* xen_dommap == pages used by map_domain_page, these pages contain
 * the second level pagetables which mapp the domheap region
 * DOMHEAP_VIRT_START...DOMHEAP_VIRT_END in 2MB chunks. */
static DEFINE_PER_CPU(lpae_t *, xen_dommap);

/* Common pagetable leaves */
/* Second level page tables.
 *
 * The second-level table is 2 contiguous pages long, and covers all
 * addresses from 0 to 0x7fffffff. Offsets into it are calculated
 * with second_linear_offset(), not second_table_offset().
 *
 * Addresses 0x80000000 to 0xffffffff are covered by the per-cpu
 * xen_domheap mappings described above. However we allocate 4 pages
 * here for use in the boot page tables and the second two pages
 * become the boot CPUs xen_dommap pages.
 */
lpae_t xen_second[LPAE_ENTRIES*4] __attribute__((__aligned__(4096*4)));
/* First level page table used for fixmap */
lpae_t xen_fixmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
/* First level page table used to map Xen itself with the XN bit set
 * as appropriate. */
static lpae_t xen_xenmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));


/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t boot_ttbr;

static paddr_t phys_offset;

/* Limits of the Xen heap */
unsigned long xenheap_mfn_start __read_mostly;
unsigned long xenheap_mfn_end __read_mostly;
unsigned long xenheap_virt_end __read_mostly;

unsigned long frametable_base_mfn __read_mostly;
unsigned long frametable_virt_end __read_mostly;

unsigned long max_page;
unsigned long total_pages;

extern char __init_begin[], __init_end[];

/* Checking VA memory layout alignment. */
static inline void check_memory_layout_alignment_constraints(void) {
    /* 2MB aligned regions */
    BUILD_BUG_ON(XEN_VIRT_START & ~SECOND_MASK);
    BUILD_BUG_ON(FIXMAP_ADDR(0) & ~SECOND_MASK);
    BUILD_BUG_ON(BOOT_MISC_VIRT_START & ~SECOND_MASK);
    /* 1GB aligned regions */
    BUILD_BUG_ON(XENHEAP_VIRT_START & ~FIRST_MASK);
    BUILD_BUG_ON(DOMHEAP_VIRT_START & ~FIRST_MASK);
}

void dump_pt_walk(lpae_t *first, paddr_t addr)
{
    lpae_t *second = NULL, *third = NULL;

    if ( first_table_offset(addr) >= LPAE_ENTRIES )
        return;

    printk("1ST[0x%x] = 0x%"PRIpaddr"\n", first_table_offset(addr),
           first[first_table_offset(addr)].bits);
    if ( !first[first_table_offset(addr)].walk.valid ||
         !first[first_table_offset(addr)].walk.table )
        goto done;

    second = map_domain_page(first[first_table_offset(addr)].walk.base);
    printk("2ND[0x%x] = 0x%"PRIpaddr"\n", second_table_offset(addr),
           second[second_table_offset(addr)].bits);
    if ( !second[second_table_offset(addr)].walk.valid ||
         !second[second_table_offset(addr)].walk.table )
        goto done;

    third = map_domain_page(second[second_table_offset(addr)].walk.base);
    printk("3RD[0x%x] = 0x%"PRIpaddr"\n", third_table_offset(addr),
           third[third_table_offset(addr)].bits);

done:
    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);

}

void dump_hyp_walk(vaddr_t addr)
{
    uint64_t ttbr = READ_SYSREG64(TTBR0_EL2);
    lpae_t *pgtable = THIS_CPU_PGTABLE;

    printk("Walking Hypervisor VA 0x%"PRIvaddr" "
           "on CPU%d via TTBR 0x%016"PRIx64"\n",
           addr, smp_processor_id(), ttbr);

    if ( smp_processor_id() == 0 )
        BUG_ON( (lpae_t *)(unsigned long)(ttbr - phys_offset) != pgtable );
    else
        BUG_ON( virt_to_maddr(pgtable) != ttbr );
    dump_pt_walk(pgtable, addr);
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, unsigned long mfn, unsigned attributes)
{
    lpae_t pte = mfn_to_xen_entry(mfn);
    pte.pt.table = 1; /* 4k mappings always have this bit set */
    pte.pt.ai = attributes;
    pte.pt.xn = 1;
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_range_va(FIXMAP_ADDR(map), PAGE_SIZE);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    lpae_t pte = {0};
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_range_va(FIXMAP_ADDR(map), PAGE_SIZE);
}

void *map_domain_page_global(unsigned long mfn)
{
    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *va)
{
    vunmap(va);
}

/* Map a page of domheap memory */
void *map_domain_page(unsigned long mfn)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    unsigned long slot_mfn = mfn & ~LPAE_ENTRY_MASK;
    vaddr_t va;
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
    flush_xen_data_tlb_range_va(va, PAGE_SIZE);

    return (void *)va;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *va)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = ((unsigned long) va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;

    local_irq_save(flags);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    map[slot].pt.avail--;

    local_irq_restore(flags);
}

unsigned long domain_page_map_to_mfn(const void *va)
{
    lpae_t *map = this_cpu(xen_dommap);
    int slot = ((unsigned long) va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;
    unsigned long offset = ((unsigned long)va>>THIRD_SHIFT) & LPAE_ENTRY_MASK;

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    return map[slot].pt.base + offset;
}

void __init arch_init_memory(void)
{
    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = domain_create(DOMID_XEN, DOMCRF_dummy, 0);
    BUG_ON(IS_ERR(dom_xen));

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create(DOMID_IO, DOMCRF_dummy, 0);
    BUG_ON(IS_ERR(dom_io));

    /*
     * Initialise our COW domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create(DOMID_COW, DOMCRF_dummy, 0);
    BUG_ON(IS_ERR(dom_cow));
}

void __cpuinit setup_virt_paging(void)
{
    /* Setup Stage 2 address translation */
    /* SH0=00, ORGN0=IRGN0=01
     * SL0=01 (Level-1)
     * T0SZ=(1)1000 = -8 (40 bit physical addresses)
     */
    WRITE_SYSREG32(0x80002558, VTCR_EL2); isb();
}

/* This needs to be a macro to stop the compiler spilling to the stack
 * which will change when we change pagetables */
#define WRITE_TTBR(ttbr)                                                \
    flush_xen_text_tlb();                                               \
    WRITE_SYSREG64(ttbr, TTBR0_EL2);                                    \
    dsb(); /* ensure memory accesses do not cross over the TTBR0 write */ \
    /* flush_xen_text_tlb contains an initial isb which ensures the     \
     * write to TTBR0 has completed. */                                 \
    flush_xen_text_tlb()

/* Boot-time pagetable setup.
 * Changes here may need matching changes in head.S */
void __init setup_pagetables(unsigned long boot_phys_offset, paddr_t xen_paddr)
{
    unsigned long dest_va;
    lpae_t pte, *p;
    int i;

    /* Map the destination in the boot misc area. */
    dest_va = BOOT_MISC_VIRT_START;
    pte = mfn_to_xen_entry(xen_paddr >> PAGE_SHIFT);
    write_pte(xen_second + second_table_offset(dest_va), pte);
    flush_xen_data_tlb_range_va(dest_va, SECOND_SIZE);

    /* Calculate virt-to-phys offset for the new location */
    phys_offset = xen_paddr - (unsigned long) _start;

    /* Copy */
    memcpy((void *) dest_va, _start, _end - _start);

    /* Beware!  Any state we modify between now and the PT switch may be
     * discarded when we switch over to the copy. */

    /* Update the copy of boot_pgtable to use the new paddrs */
    p = (void *) boot_pgtable + dest_va - (unsigned long) _start;
#ifdef CONFIG_ARM_64
    p[0].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;
    p = (void *) boot_first + dest_va - (unsigned long) _start;
#endif
    for ( i = 0; i < 4; i++)
        p[i].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;

    p = (void *) xen_second + dest_va - (unsigned long) _start;
    if ( boot_phys_offset != 0 )
    {
        /* Remove the old identity mapping of the boot paddr */
        vaddr_t va = (vaddr_t)_start + boot_phys_offset;
        p[second_linear_offset(va)].bits = 0;
    }
    for ( i = 0; i < 4 * LPAE_ENTRIES; i++)
        if ( p[i].pt.valid )
            p[i].pt.base += (phys_offset - boot_phys_offset) >> PAGE_SHIFT;

    /* Change pagetables to the copy in the relocated Xen */
    boot_ttbr = (uintptr_t) boot_pgtable + phys_offset;
    flush_xen_dcache(boot_ttbr);
    flush_xen_dcache_va_range((void*)dest_va, _end - _start);

    WRITE_TTBR(boot_ttbr);

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
    /* TLBFLUSH and ISB would be needed here, but wait until we set WXN */

    /* From now on, no mapping may be both writable and executable. */
    WRITE_SYSREG32(READ_SYSREG32(SCTLR_EL2) | SCTLR_WXN, SCTLR_EL2);
    /* Flush everything after setting WXN bit. */
    flush_xen_text_tlb();

    per_cpu(xen_pgtable, 0) = boot_pgtable;
    per_cpu(xen_dommap, 0) = xen_second +
        second_linear_offset(DOMHEAP_VIRT_START);

    /* Some of these slots may have been used during start of day and/or
     * relocation. Make sure they are clear now. */
    memset(this_cpu(xen_dommap), 0, DOMHEAP_SECOND_PAGES*PAGE_SIZE);
    flush_xen_dcache_va_range(this_cpu(xen_dommap),
                              DOMHEAP_SECOND_PAGES*PAGE_SIZE);
}

int init_secondary_pagetables(int cpu)
{
    lpae_t *root, *first, *domheap, pte;
    int i;

    root = alloc_xenheap_page();
#ifdef CONFIG_ARM_64
    first = alloc_xenheap_page();
#else
    first = root; /* root == first level on 32-bit 3-level trie */
#endif
    domheap = alloc_xenheap_pages(get_order_from_pages(DOMHEAP_SECOND_PAGES), 0);

    if ( root == NULL || domheap == NULL || first == NULL )
    {
        printk("Not enough free memory for secondary CPU%d pagetables\n", cpu);
        free_xenheap_pages(domheap, get_order_from_pages(DOMHEAP_SECOND_PAGES));
#ifdef CONFIG_ARM_64
        free_xenheap_page(first);
#endif
        free_xenheap_page(root);
        return -ENOMEM;
    }

    /* Initialise root pagetable from root of boot tables */
    memcpy(root, boot_pgtable, PAGE_SIZE);

#ifdef CONFIG_ARM_64
    /* Initialise first pagetable from first level of boot tables, and
     * hook into the new root. */
    memcpy(first, boot_first, PAGE_SIZE);
    pte = mfn_to_xen_entry(virt_to_mfn(first));
    pte.pt.table = 1;
    write_pte(root, pte);
#endif

    /* Ensure the domheap has no stray mappings */
    memset(domheap, 0, DOMHEAP_SECOND_PAGES*PAGE_SIZE);

    /* Update the first level mapping to reference the local CPUs
     * domheap mapping pages. */
    for ( i = 0; i < DOMHEAP_SECOND_PAGES; i++ )
    {
        pte = mfn_to_xen_entry(virt_to_mfn(domheap+i*LPAE_ENTRIES));
        pte.pt.table = 1;
        write_pte(&first[first_table_offset(DOMHEAP_VIRT_START+i*FIRST_SIZE)], pte);
    }

    flush_xen_dcache_va_range(root, PAGE_SIZE);
#ifdef CONFIG_ARM_64
    flush_xen_dcache_va_range(first, PAGE_SIZE);
#endif
    flush_xen_dcache_va_range(domheap, DOMHEAP_SECOND_PAGES*PAGE_SIZE);

    per_cpu(xen_pgtable, cpu) = root;
    per_cpu(xen_dommap, cpu) = domheap;

    return 0;
}

/* MMU setup for secondary CPUS (which already have paging enabled) */
void __cpuinit mmu_init_secondary_cpu(void)
{
    uint64_t ttbr;

    /* Change to this CPU's pagetables */
    ttbr = (uintptr_t)virt_to_maddr(THIS_CPU_PGTABLE);
    WRITE_TTBR(ttbr);

    /* From now on, no mapping may be both writable and executable. */
    WRITE_SYSREG32(READ_SYSREG32(SCTLR_EL2) | SCTLR_WXN, SCTLR_EL2);
    flush_xen_text_tlb();
}

/* Create Xen's mappings of memory.
 * Base and virt must be 32MB aligned and size a multiple of 32MB.
 * second must be a contiguous set of second level page tables
 * covering the region starting at virt_offset. */
static void __init create_32mb_mappings(lpae_t *second,
                                        unsigned long virt_offset,
                                        unsigned long base_mfn,
                                        unsigned long nr_mfns)
{
    unsigned long i, count;
    lpae_t pte, *p;

    ASSERT(!((virt_offset >> PAGE_SHIFT) % (16 * LPAE_ENTRIES)));
    ASSERT(!(base_mfn % (16 * LPAE_ENTRIES)));
    ASSERT(!(nr_mfns % (16 * LPAE_ENTRIES)));

    count = nr_mfns / LPAE_ENTRIES;
    p = second + second_linear_offset(virt_offset);
    pte = mfn_to_xen_entry(base_mfn);
    pte.pt.contig = 1;  /* These maps are in 16-entry contiguous chunks. */
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
    create_32mb_mappings(xen_second, XENHEAP_VIRT_START, base_mfn, nr_mfns);

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
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));
    create_32mb_mappings(xen_second, FRAMETABLE_VIRT_START, base_mfn, frametable_size >> PAGE_SHIFT);

    memset(&frame_table[0], 0, nr_pages * sizeof(struct page_info));
    memset(&frame_table[nr_pages], -1,
           frametable_size - (nr_pages * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pages * sizeof(struct page_info));
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void *ioremap_attr(paddr_t pa, size_t len, unsigned int attributes)
{
    unsigned long pfn = PFN_DOWN(pa);
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);

    return (__vmap(&pfn, nr, 1, 1, attributes) + offs);
}

static int create_xen_table(lpae_t *entry)
{
    void *p;
    lpae_t pte;

    p = alloc_xenheap_page();
    if ( p == NULL )
        return -ENOMEM;
    clear_page(p);
    pte = mfn_to_xen_entry(virt_to_mfn(p));
    pte.pt.table = 1;
    write_pte(entry, pte);
    return 0;
}

enum xenmap_operation {
    INSERT,
    REMOVE
};

static int create_xen_entries(enum xenmap_operation op,
                              unsigned long virt,
                              unsigned long mfn,
                              unsigned long nr_mfns,
                              unsigned int ai)
{
    int rc;
    unsigned long addr = virt, addr_end = addr + nr_mfns * PAGE_SIZE;
    lpae_t pte;
    lpae_t *third = NULL;

    for(; addr < addr_end; addr += PAGE_SIZE, mfn++)
    {
        if ( !xen_second[second_linear_offset(addr)].pt.valid ||
             !xen_second[second_linear_offset(addr)].pt.table )
        {
            rc = create_xen_table(&xen_second[second_linear_offset(addr)]);
            if ( rc < 0 ) {
                printk("create_xen_entries: L2 failed\n");
                goto out;
            }
        }

        BUG_ON(!xen_second[second_linear_offset(addr)].pt.valid);

        third = __va(pfn_to_paddr(xen_second[second_linear_offset(addr)].pt.base));

        switch ( op ) {
            case INSERT:
                if ( third[third_table_offset(addr)].pt.valid )
                {
                    printk("create_xen_entries: trying to replace an existing mapping addr=%lx mfn=%lx\n",
                           addr, mfn);
                    return -EINVAL;
                }
                pte = mfn_to_xen_entry(mfn);
                pte.pt.table = 1;
                pte.pt.ai = ai;
                write_pte(&third[third_table_offset(addr)], pte);
                break;
            case REMOVE:
                if ( !third[third_table_offset(addr)].pt.valid )
                {
                    printk("create_xen_entries: trying to remove a non-existing mapping addr=%lx\n",
                           addr);
                    return -EINVAL;
                }
                pte.bits = 0;
                write_pte(&third[third_table_offset(addr)], pte);
                break;
            default:
                BUG();
        }
    }
    flush_xen_data_tlb_range_va(virt, PAGE_SIZE * nr_mfns);

    rc = 0;

out:
    return rc;
}

int map_pages_to_xen(unsigned long virt,
                     unsigned long mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    return create_xen_entries(INSERT, virt, mfn, nr_mfns, flags);
}
void destroy_xen_mappings(unsigned long v, unsigned long e)
{
    create_xen_entries(REMOVE, v, 0, (e - v) >> PAGE_SHIFT, 0);
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

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -1;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT(0);
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
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

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

static int xenmem_add_to_physmap_one(
    struct domain *d,
    uint16_t space,
    domid_t foreign_domid,
    unsigned long idx,
    xen_pfn_t gpfn)
{
    unsigned long mfn = 0;
    int rc;

    switch ( space )
    {
    case XENMAPSPACE_grant_table:
        spin_lock(&d->grant_table->lock);

        if ( d->grant_table->gt_version == 0 )
            d->grant_table->gt_version = 1;

        if ( d->grant_table->gt_version == 2 &&
                (idx & XENMAPIDX_grant_table_status) )
        {
            idx &= ~XENMAPIDX_grant_table_status;
            if ( idx < nr_status_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->status[idx]);
        }
        else
        {
            if ( (idx >= nr_grant_frames(d->grant_table)) &&
                    (idx < max_nr_grant_frames) )
                gnttab_grow_table(d, idx + 1);

            if ( idx < nr_grant_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->shared_raw[idx]);
        }
        
        d->arch.grant_table_gpfn[idx] = gpfn;

        spin_unlock(&d->grant_table->lock);
        break;
    case XENMAPSPACE_shared_info:
        if ( idx == 0 )
            mfn = virt_to_mfn(d->shared_info);
        break;
    case XENMAPSPACE_gmfn_foreign:
    {
        paddr_t maddr;
        struct domain *od;
        od = rcu_lock_domain_by_any_id(foreign_domid);
        if ( od == NULL )
            return -ESRCH;

        rc = xsm_map_gmfn_foreign(XSM_TARGET, d, od);
        if ( rc )
        {
            rcu_unlock_domain(od);
            return rc;
        }

        maddr = p2m_lookup(od, idx << PAGE_SHIFT);
        if ( maddr == INVALID_PADDR )
        {
            dump_p2m_lookup(od, idx << PAGE_SHIFT);
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        mfn = maddr >> PAGE_SHIFT;

        rcu_unlock_domain(od);
        break;
    }

    default:
        return -ENOSYS;
    }

    /* Map at new location. */
    rc = guest_physmap_add_page(d, gpfn, mfn, 0);

    return rc;
}

static int xenmem_add_to_physmap_range(struct domain *d,
                                       struct xen_add_to_physmap_range *xatpr)
{
    int rc;

    /* Process entries in reverse order to allow continuations */
    while ( xatpr->size > 0 )
    {
        xen_ulong_t idx;
        xen_pfn_t gpfn;

        rc = copy_from_guest_offset(&idx, xatpr->idxs, xatpr->size-1, 1);
        if ( rc < 0 )
            goto out;

        rc = copy_from_guest_offset(&gpfn, xatpr->gpfns, xatpr->size-1, 1);
        if ( rc < 0 )
            goto out;

        rc = xenmem_add_to_physmap_one(d, xatpr->space,
                                       xatpr->foreign_domid,
                                       idx, gpfn);

        rc = copy_to_guest_offset(xatpr->errs, xatpr->size-1, &rc, 1);
        if ( rc < 0 )
            goto out;

        xatpr->size--;

        /* Check for continuation if it's not the last interation */
        if ( xatpr->size > 0 && hypercall_preempt_check() )
        {
            rc = -EAGAIN;
            goto out;
        }
    }

    rc = 0;

out:
    return rc;

}

long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
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

        /* Foreign mapping is only supported by add_to_physmap_range */
        if ( xatp.space == XENMAPSPACE_gmfn_foreign )
            return -EINVAL;

        d = rcu_lock_domain_by_any_id(xatp.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_add_to_physmap(XSM_TARGET, current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap_one(d, xatp.space, DOMID_INVALID,
                                       xatp.idx, xatp.gpfn);

        rcu_unlock_domain(d);

        return rc;
    }

    case XENMEM_add_to_physmap_range:
    {
        struct xen_add_to_physmap_range xatpr;
        struct domain *d;

        if ( copy_from_guest(&xatpr, arg, 1) )
            return -EFAULT;

        /* This mapspace is redundant for this hypercall */
        if ( xatpr.space == XENMAPSPACE_gmfn_range )
            return -EINVAL;

        d = rcu_lock_domain_by_any_id(xatpr.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_add_to_physmap(XSM_TARGET, current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap_range(d, &xatpr);

        rcu_unlock_domain(d);

        if ( rc && copy_to_guest(arg, &xatpr, 1) )
            rc = -EFAULT;

        if ( rc == -EAGAIN )
            rc = hypercall_create_continuation(
                __HYPERVISOR_memory_op, "ih", op, arg);

        return rc;
    }
    /* XXX: memsharing not working yet */
    case XENMEM_get_sharing_shared_pages:
    case XENMEM_get_sharing_freed_pages:
        return 0;

    default:
        return -ENOSYS;
    }

    return 0;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + 1) & PGC_count_mask) <= 1) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    return page_get_owner(page);
}

void put_page(struct page_info *page)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) != 0);
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        free_domheap_page(page);
    }
}

int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( owner != NULL )
        put_page(page);

    return 0;
}

/* Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy. */
int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

void put_page_type(struct page_info *page)
{
    return;
}

void gnttab_clear_flag(unsigned long nr, uint16_t *addr)
{
    /*
     * Note that this cannot be clear_bit(), as the access must be
     * confined to the specified 2 bytes.
     */
    uint16_t mask = ~(1 << nr), old;

    do {
        old = *addr;
    } while (cmpxchg(addr, old, old & mask) != old);
}

void gnttab_mark_dirty(struct domain *d, unsigned long l)
{
    /* XXX: mark dirty */
    static int warning;
    if (!warning) {
        gdprintk(XENLOG_WARNING, "gnttab_mark_dirty not implemented yet\n");
        warning = 1;
    }
}

int create_grant_host_mapping(unsigned long addr, unsigned long frame,
                              unsigned int flags, unsigned int cache_flags)
{
    int rc;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    /* XXX: read only mappings */
    if ( flags & GNTMAP_readonly )
    {
        gdprintk(XENLOG_WARNING, "read only mappings not implemented yet\n");
        return GNTST_general_error;
    }

    rc = guest_physmap_add_page(current->domain,
                                 addr >> PAGE_SHIFT, frame, 0);
    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_host_mapping(unsigned long addr, unsigned long mfn,
        unsigned long new_addr, unsigned int flags)
{
    unsigned long gfn = (unsigned long)(addr >> PAGE_SHIFT);
    struct domain *d = current->domain;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    guest_physmap_remove_page(d, gfn, mfn, 0);

    return GNTST_okay;
}

int is_iomem_page(unsigned long mfn)
{
    if ( !mfn_valid(mfn) )
        return 1;
    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
