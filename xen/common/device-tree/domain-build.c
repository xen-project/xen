/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/fdt-domain-build.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include <asm/p2m.h>

bool __init allocate_domheap_memory(struct domain *d, paddr_t tot_size,
                                    alloc_domheap_mem_cb cb, void *extra)
{
    unsigned int max_order = UINT_MAX;

    while ( tot_size > 0 )
    {
        unsigned int order = get_allocation_size(tot_size);
        struct page_info *pg;

        order = min(max_order, order);

        pg = alloc_domheap_pages(d, order, 0);
        if ( !pg )
        {
            /*
             * If we can't allocate one page, then it is unlikely to
             * succeed in the next iteration. So bail out.
             */
            if ( !order )
                return false;

            /*
             * If we can't allocate memory with order, then it is
             * unlikely to succeed in the next iteration.
             * Record the order - 1 to avoid re-trying.
             */
            max_order = order - 1;
            continue;
        }

        if ( !cb(d, pg, order, extra) )
            return false;

        tot_size -= (1ULL << (PAGE_SHIFT + order));
    }

    return true;
}

static bool __init guest_map_pages(struct domain *d, struct page_info *pg,
                                   unsigned int order, void *extra)
{
    gfn_t *sgfn = (gfn_t *)extra;
    int res;

    BUG_ON(!sgfn);
    res = guest_physmap_add_page(d, *sgfn, page_to_mfn(pg), order);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed map pages to DOMU: %d", res);
        return false;
    }

    *sgfn = gfn_add(*sgfn, 1UL << order);

    return true;
}

bool __init allocate_bank_memory(struct kernel_info *kinfo, gfn_t sgfn,
                                 paddr_t tot_size)
{
    struct membanks *mem = kernel_info_get_mem(kinfo);
    struct domain *d = kinfo->bd.d;
    struct membank *bank;

    /*
     * allocate_bank_memory can be called with a tot_size of zero for
     * the second memory bank. It is not an error and we can safely
     * avoid creating a zero-size memory bank.
     */
    if ( tot_size == 0 )
        return true;

    bank = &mem->bank[mem->nr_banks];
    bank->start = gfn_to_gaddr(sgfn);
    bank->size = tot_size;

    /*
     * Allocate pages from the heap until tot_size is zero and map them to the
     * guest using guest_map_pages, passing the starting gfn as extra parameter
     * for the map operation.
     */
    if ( !allocate_domheap_memory(d, tot_size, guest_map_pages, &sgfn) )
        return false;

    mem->nr_banks++;
    kinfo->unassigned_mem -= bank->size;

    return true;
}

static int __init add_hwdom_free_regions(unsigned long s_gfn,
                                         unsigned long e_gfn, void *data)
{
    struct membanks *free_regions = data;
    paddr_t start, size;
    paddr_t s = pfn_to_paddr(s_gfn);
    paddr_t e = pfn_to_paddr(e_gfn + 1) - 1;
    unsigned int i, j;

    if ( free_regions->nr_banks >= free_regions->max_banks )
        return 0;

    /*
     * Both start and size of the free region should be 2MB aligned to
     * potentially allow superpage mapping.
     */
    start = (s + SZ_2M - 1) & ~(SZ_2M - 1);
    if ( start > e )
        return 0;

    /*
     * e is actually "end-1" because it is called by rangeset functions
     * which are inclusive of the last address.
     */
    e += 1;
    size = (e - start) & ~(SZ_2M - 1);

    /* Find the insert position (descending order). */
    for ( i = 0; i < free_regions->nr_banks ; i++ )
        if ( size > free_regions->bank[i].size )
            break;

    /* Move the other banks to make space. */
    for ( j = free_regions->nr_banks; j > i ; j-- )
    {
        free_regions->bank[j].start = free_regions->bank[j - 1].start;
        free_regions->bank[j].size = free_regions->bank[j - 1].size;
    }

    free_regions->bank[i].start = start;
    free_regions->bank[i].size = size;
    free_regions->nr_banks++;

    return 0;
}

/*
 * Find unused regions of Host address space which can be exposed to domain
 * using the host memory layout. In order to calculate regions we exclude every
 * region passed in mem_banks from the Host RAM.
 */
int __init find_unallocated_memory(const struct kernel_info *kinfo,
                                   const struct membanks *mem_banks[],
                                   unsigned int nr_mem_banks,
                                   struct membanks *free_regions,
                                   int (*cb)(unsigned long s_gfn,
                                             unsigned long e_gfn,
                                             void *data))
{
    const struct membanks *mem = bootinfo_get_mem();
    struct rangeset *unalloc_mem;
    paddr_t start, end;
    unsigned int i, j;
    int res;

    ASSERT(domain_use_host_layout(kinfo->bd.d));

    unalloc_mem = rangeset_new(NULL, NULL, 0);
    if ( !unalloc_mem )
        return -ENOMEM;

    /* Start with all available RAM */
    for ( i = 0; i < mem->nr_banks; i++ )
    {
        start = mem->bank[i].start;
        end = mem->bank[i].start + mem->bank[i].size;
        res = rangeset_add_range(unalloc_mem, PFN_DOWN(start),
                                 PFN_DOWN(end - 1));
        if ( res )
        {
            printk(XENLOG_ERR "Failed to add: %#"PRIpaddr"->%#"PRIpaddr"\n",
                   start, end);
            goto out;
        }
    }

    /* Remove all regions listed in mem_banks */
    for ( i = 0; i < nr_mem_banks; i++ )
    {
        if ( !mem_banks[i] )
            continue;

        for ( j = 0; j < mem_banks[i]->nr_banks; j++ )
        {
            start = mem_banks[i]->bank[j].start;

            /* Shared memory banks can contain INVALID_PADDR as start */
            if ( INVALID_PADDR == start )
                continue;

            end = mem_banks[i]->bank[j].start + mem_banks[i]->bank[j].size;
            res = rangeset_remove_range(unalloc_mem, PFN_DOWN(start),
                                        PFN_DOWN(end - 1));
            if ( res )
            {
                printk(XENLOG_ERR
                       "Failed to add: %#"PRIpaddr"->%#"PRIpaddr", error %d\n",
                       start, end, res);
                goto out;
            }
        }
    }

    start = 0;
    end = (1ULL << p2m_ipa_bits) - 1;
    res = rangeset_report_ranges(unalloc_mem, PFN_DOWN(start), PFN_DOWN(end),
                                 cb, free_regions);
    if ( res )
        free_regions->nr_banks = 0;
    else if ( !free_regions->nr_banks )
        res = -ENOENT;

out:
    rangeset_destroy(unalloc_mem);

    return res;
}

void __init allocate_memory(struct domain *d, struct kernel_info *kinfo)
{
    struct membanks *mem = kernel_info_get_mem(kinfo);
    unsigned int i, nr_banks = GUEST_RAM_BANKS;
    struct membanks *hwdom_free_mem = NULL;

    printk(XENLOG_INFO "Allocating mappings totalling %ldMB for %pd:\n",
           /* Don't want format this as PRIpaddr (16 digit hex) */
           (unsigned long)(kinfo->unassigned_mem >> 20), d);

    mem->nr_banks = 0;
    /*
     * Use host memory layout for hwdom. Only case for this is when LLC coloring
     * is enabled.
     */
    if ( is_hardware_domain(d) )
    {
        struct membanks *gnttab =
            IS_ENABLED(CONFIG_GRANT_TABLE)
            ? membanks_xzalloc(1, MEMORY)
            : NULL;
        /*
         * Exclude the following regions:
         * 1) Remove reserved memory
         * 2) Grant table assigned to hwdom
         */
        const struct membanks *mem_banks[] = {
            bootinfo_get_reserved_mem(),
            gnttab,
        };

#ifdef CONFIG_GRANT_TABLE
        if ( !gnttab )
            goto fail;

        gnttab->nr_banks = 1;
        gnttab->bank[0].start = kinfo->gnttab_start;
        gnttab->bank[0].size = kinfo->gnttab_size;
#endif

        hwdom_free_mem = membanks_xzalloc(NR_MEM_BANKS, MEMORY);
        if ( !hwdom_free_mem )
            goto fail;

        if ( find_unallocated_memory(kinfo, mem_banks, ARRAY_SIZE(mem_banks),
                                     hwdom_free_mem, add_hwdom_free_regions) )
            goto fail;

        nr_banks = hwdom_free_mem->nr_banks;
        xfree(gnttab);
    }

    for ( i = 0; kinfo->unassigned_mem > 0 && nr_banks > 0; i++, nr_banks-- )
    {
        paddr_t bank_start, bank_size;

        if ( is_hardware_domain(d) )
        {
            bank_start = hwdom_free_mem->bank[i].start;
            bank_size = hwdom_free_mem->bank[i].size;
        }
        else
        {
            const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
            const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;

            if ( i >= GUEST_RAM_BANKS )
                goto fail;

            bank_start = bankbase[i];
            bank_size = banksize[i];
        }

        bank_size = MIN(bank_size, kinfo->unassigned_mem);
        if ( !allocate_bank_memory(kinfo, gaddr_to_gfn(bank_start), bank_size) )
            goto fail;
    }

    if ( kinfo->unassigned_mem )
        goto fail;

    for( i = 0; i < mem->nr_banks; i++ )
    {
        printk(XENLOG_INFO "%pd BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               d,
               i,
               mem->bank[i].start,
               mem->bank[i].start + mem->bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(mem->bank[i].size >> 20));
    }

    xfree(hwdom_free_mem);
    return;

  fail:
    panic("Failed to allocate requested domain memory."
          /* Don't want format this as PRIpaddr (16 digit hex) */
          " %ldKB unallocated. Fix the VMs configurations.\n",
          (unsigned long)kinfo->unassigned_mem >> 10);
}

void __init dtb_load(struct kernel_info *kinfo,
                     copy_to_guest_phys_cb cb)
{
    unsigned long left;

    printk("Loading %pd DTB to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->bd.d, kinfo->dtb_paddr,
           kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt));

    left = cb(kinfo->bd.d, kinfo->dtb_paddr,
              kinfo->fdt,
              fdt_totalsize(kinfo->fdt));

    if ( left != 0 )
        panic("Unable to copy the DTB to %pd memory (left = %lu bytes)\n",
              kinfo->bd.d, left);
    xfree(kinfo->fdt);
}

void __init initrd_load(struct kernel_info *kinfo,
                        copy_to_guest_phys_cb cb)
{
    const struct boot_module *mod = kinfo->bd.initrd;
    paddr_t load_addr = kinfo->initrd_paddr;
    paddr_t paddr, len;
    int node;
    int res;
    __be32 val[2];
    __be32 *cellp;
    void __iomem *initrd;

    if ( !mod || !mod->size )
        return;

    paddr = mod->start;
    len = mod->size;

    printk("Loading %pd initrd from %"PRIpaddr" to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->bd.d, paddr, load_addr, load_addr + len);

    /* Fix up linux,initrd-start and linux,initrd-end in /chosen */
    node = fdt_path_offset(kinfo->fdt, "/chosen");
    if ( node < 0 )
        panic("Cannot find the /chosen node\n");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-start",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-start\" property\n");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr + len);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-end",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-end\" property\n");

    initrd = ioremap_wc(paddr, len);
    if ( !initrd )
        panic("Unable to map the %pd initrd\n", kinfo->bd.d);

    res = cb(kinfo->bd.d, load_addr, initrd, len);
    if ( res != 0 )
        panic("Unable to copy the initrd in the %pd memory\n", kinfo->bd.d);

    iounmap(initrd);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
