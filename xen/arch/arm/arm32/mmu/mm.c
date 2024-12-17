/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt-xen.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/pfn.h>
#include <asm/fixmap.h>
#include <asm/setup.h>
#include <asm/static-memory.h>
#include <asm/static-shmem.h>

static unsigned long opt_xenheap_megabytes __initdata;
integer_param("xenheap_megabytes", opt_xenheap_megabytes);

/*
 * Set up the direct-mapped xenheap: up to 1GB of contiguous,
 * always-mapped memory. Base must be 32MB aligned and size a multiple of 32MB.
 */
static void __init setup_directmap_mappings(unsigned long base_mfn,
                                            unsigned long nr_mfns)
{
    int rc;

    rc = map_pages_to_xen(XENHEAP_VIRT_START, _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");

    /* Record where the directmap is, for translation routines. */
    directmap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
}

/*
 * Find a contiguous region that fits in the static heap region with
 * required size and alignment, and return the end address of the region
 * if found otherwise 0.
 */
static paddr_t __init fit_xenheap_in_static_heap(uint32_t size, paddr_t align)
{
    const struct membanks *reserved_mem = bootinfo_get_reserved_mem();
    unsigned int i;
    paddr_t end = 0, aligned_start, aligned_end;
    paddr_t bank_start, bank_size, bank_end;

    for ( i = 0 ; i < reserved_mem->nr_banks; i++ )
    {
        if ( reserved_mem->bank[i].type != MEMBANK_STATIC_HEAP )
            continue;

        bank_start = reserved_mem->bank[i].start;
        bank_size = reserved_mem->bank[i].size;
        bank_end = bank_start + bank_size;

        if ( bank_size < size )
            continue;

        aligned_end = bank_end & ~(align - 1);
        aligned_start = (aligned_end - size) & ~(align - 1);

        if ( aligned_start > bank_start )
            /*
             * Allocate the xenheap as high as possible to keep low-memory
             * available (assuming the admin supplied region below 4GB)
             * for other use (e.g. domain memory allocation).
             */
            end = max(end, aligned_end);
    }

    return end;
}

void __init setup_mm(void)
{
    const struct membanks *mem = bootinfo_get_mem();
    paddr_t ram_start, ram_end, ram_size, e, bank_start, bank_end, bank_size;
    paddr_t static_heap_end = 0, static_heap_size = 0;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned int i;
    const uint32_t ctr = READ_CP32(CTR);

    if ( !mem->nr_banks )
        panic("No memory bank\n");

    /* We only supports instruction caches implementing the IVIPT extension. */
    if ( ((ctr >> CTR_L1IP_SHIFT) & CTR_L1IP_MASK) == ICACHE_POLICY_AIVIVT )
        panic("AIVIVT instruction cache not supported\n");

    init_pdx();

    ram_start = mem->bank[0].start;
    ram_size  = mem->bank[0].size;
    ram_end   = ram_start + ram_size;

    for ( i = 1; i < mem->nr_banks; i++ )
    {
        bank_start = mem->bank[i].start;
        bank_size = mem->bank[i].size;
        bank_end = bank_start + bank_size;

        ram_size  = ram_size + bank_size;
        ram_start = min(ram_start,bank_start);
        ram_end   = max(ram_end,bank_end);
    }

    total_pages = ram_size >> PAGE_SHIFT;

    if ( using_static_heap )
    {
        const struct membanks *reserved_mem = bootinfo_get_reserved_mem();

        for ( i = 0 ; i < reserved_mem->nr_banks; i++ )
        {
            if ( reserved_mem->bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            bank_start = reserved_mem->bank[i].start;
            bank_size = reserved_mem->bank[i].size;
            bank_end = bank_start + bank_size;

            static_heap_size += bank_size;
            static_heap_end = max(static_heap_end, bank_end);
        }

        heap_pages = static_heap_size >> PAGE_SHIFT;
    }
    else
        heap_pages = total_pages;

    /*
     * If the user has not requested otherwise via the command line
     * then locate the xenheap using these constraints:
     *
     *  - must be contiguous
     *  - must be 32 MiB aligned
     *  - must not include Xen itself or the boot modules
     *  - must be at most 1GB or 1/32 the total RAM in the system (or static
          heap if enabled) if less
     *  - must be at least 32M
     *
     * We try to allocate the largest xenheap possible within these
     * constraints.
     */
    if ( opt_xenheap_megabytes )
        xenheap_pages = opt_xenheap_megabytes << (20-PAGE_SHIFT);
    else
    {
        xenheap_pages = (heap_pages/32 + 0x1fffUL) & ~0x1fffUL;
        xenheap_pages = max(xenheap_pages, 32UL<<(20-PAGE_SHIFT));
        xenheap_pages = min(xenheap_pages, 1UL<<(30-PAGE_SHIFT));
    }

    do
    {
        e = using_static_heap ?
            fit_xenheap_in_static_heap(pfn_to_paddr(xenheap_pages), MB(32)) :
            consider_modules(ram_start, ram_end,
                             pfn_to_paddr(xenheap_pages),
                             32<<20, 0);
        if ( e )
            break;

        xenheap_pages >>= 1;
    } while ( !opt_xenheap_megabytes && xenheap_pages > 32<<(20-PAGE_SHIFT) );

    if ( ! e )
        panic("Not enough space for xenheap\n");

    domheap_pages = heap_pages - xenheap_pages;

    printk("Xen heap: %"PRIpaddr"-%"PRIpaddr" (%lu pages%s)\n",
           e - (pfn_to_paddr(xenheap_pages)), e, xenheap_pages,
           opt_xenheap_megabytes ? ", from command-line" : "");
    printk("Dom heap: %lu pages\n", domheap_pages);

    /*
     * We need some memory to allocate the page-tables used for the
     * directmap mappings. So populate the boot allocator first.
     *
     * This requires us to set directmap_mfn_{start, end} first so the
     * direct-mapped Xenheap region can be avoided.
     */
    directmap_mfn_start = _mfn((e >> PAGE_SHIFT) - xenheap_pages);
    directmap_mfn_end = mfn_add(directmap_mfn_start, xenheap_pages);

    populate_boot_allocator();

    setup_directmap_mappings(mfn_x(directmap_mfn_start), xenheap_pages);

    /* Frame table covers all of RAM region, including holes */
    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    /*
     * The allocators may need to use map_domain_page() (such as for
     * scrubbing pages). So we need to prepare the domheap area first.
     */
    if ( !init_domheap_mappings(smp_processor_id()) )
        panic("CPU%u: Unable to prepare the domheap page-tables\n",
              smp_processor_id());

    /* Add xenheap memory that was not already added to the boot allocator. */
    init_xenheap_pages(mfn_to_maddr(directmap_mfn_start),
                       mfn_to_maddr(directmap_mfn_end));

    init_staticmem_pages();
    init_sharedmem_pages();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
