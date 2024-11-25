/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/mmu/smpboot.c
 *
 * MMU system secondary CPUs MM bringup code.
 */

#include <xen/domain_page.h>

#include <asm/setup.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

/*
 * Static start-of-day pagetables that we use before the allocators
 * are up. These are used by all CPUs during bringup before switching
 * to the CPUs own pagetables.
 *
 * These pagetables have a very simple structure. They include:
 *  - XEN_VIRT_SIZE worth of L3 mappings of xen at XEN_VIRT_START, boot_first
 *    and boot_second are used to populate the tables down to boot_third
 *    which contains the actual mapping.
 *  - a 1:1 mapping of xen at its current physical address. This uses a
 *    section mapping at whichever of boot_{pgtable,first,second}
 *    covers that physical address.
 *
 * For the boot CPU these mappings point to the address where Xen was
 * loaded by the bootloader. For secondary CPUs they point to the
 * relocated copy of Xen for the benefit of secondary CPUs.
 *
 * In addition to the above for the boot CPU the device-tree is
 * initially mapped in the boot misc slot. This mapping is not present
 * for secondary CPUs.
 *
 * Finally, if EARLY_PRINTK is enabled then xen_fixmap will be mapped
 * by the CPU once it has moved off the 1:1 mapping.
 */
DEFINE_BOOT_PAGE_TABLE(boot_pgtable);
#ifdef CONFIG_ARM_64
DEFINE_BOOT_PAGE_TABLE(boot_first);
DEFINE_BOOT_PAGE_TABLE(boot_first_id);
#endif
DEFINE_BOOT_PAGE_TABLE(boot_second_id);
DEFINE_BOOT_PAGE_TABLE(boot_third_id);
DEFINE_BOOT_PAGE_TABLE(boot_second);
DEFINE_BOOT_PAGE_TABLES(boot_third, XEN_NR_ENTRIES(2));

/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t __section(".data.idmap") init_ttbr;

/* Clear a translation table and clean & invalidate the cache */
static void clear_table(void *table)
{
    clear_page(table);
    clean_and_invalidate_dcache_va_range(table, PAGE_SIZE);
}

static void clear_boot_pagetables(void)
{
    /*
     * Clear the copy of the boot pagetables. Each secondary CPU
     * rebuilds these itself (see head.S).
     */
    clear_table(boot_pgtable);
#ifdef CONFIG_ARM_64
    clear_table(boot_first);
    clear_table(boot_first_id);
#endif
    clear_table(boot_second);
    clear_table(boot_third);
}

static void set_init_ttbr(lpae_t *root)
{
    /*
     * init_ttbr is part of the identity mapping which is read-only. So
     * we need to re-map the region so it can be updated.
     */
    void *ptr = map_domain_page(virt_to_mfn(&init_ttbr));

    ptr += PAGE_OFFSET(&init_ttbr);

    *(uint64_t *)ptr = virt_to_maddr(root);

    /*
     * init_ttbr will be accessed with the MMU off, so ensure the update
     * is visible by cleaning the cache.
     */
    clean_dcache_va_range(ptr, sizeof(uint64_t));

    unmap_domain_page(ptr);
}

#ifdef CONFIG_ARM_64
int prepare_secondary_mm(int cpu)
{
    clear_boot_pagetables();

    /*
     * Set init_ttbr for this CPU coming up. All CPUs share a single setof
     * pagetables, but rewrite it each time for consistency with 32 bit.
     */
    set_init_ttbr(xen_pgtable);

    return 0;
}
#else
int prepare_secondary_mm(int cpu)
{
    lpae_t *root = alloc_xenheap_page();

    if ( !root )
    {
        printk("CPU%u: Unable to allocate the root page-table\n", cpu);
        return -ENOMEM;
    }

    /* Initialise root pagetable from root of boot tables */
    memcpy(root, per_cpu(xen_pgtable, 0), PAGE_SIZE);
    per_cpu(xen_pgtable, cpu) = root;

    if ( !init_domheap_mappings(cpu) )
    {
        printk("CPU%u: Unable to prepare the domheap page-tables\n", cpu);
        per_cpu(xen_pgtable, cpu) = NULL;
        free_xenheap_page(root);
        return -ENOMEM;
    }

    clear_boot_pagetables();

    /* Set init_ttbr for this CPU coming up */
    set_init_ttbr(root);

    return 0;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
