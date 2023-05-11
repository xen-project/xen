/* SPDX-License-Identifier: GPL-2.0 */
#include <xen/init.h>
#include <xen/compile.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/irq.h>
#include <asm/regs.h>
#include <xen/errno.h>
#include <xen/err.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <xen/acpi.h>
#include <xen/vmap.h>
#include <xen/warning.h>
#include <acpi/actables.h>
#include <asm/device.h>
#include <asm/kernel.h>
#include <asm/setup.h>
#include <asm/tee/tee.h>
#include <asm/platform.h>
#include <asm/psci.h>
#include <asm/setup.h>
#include <asm/cpufeature.h>
#include <asm/domain_build.h>
#include <xen/event.h>

#include <xen/irq.h>
#include <xen/grant_table.h>
#include <xen/serial.h>

#define STATIC_EVTCHN_NODE_SIZE_CELLS 2

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

/*
 * If true, the extended regions support is enabled for dom0 and
 * dom0less domUs.
 */
static bool __initdata opt_ext_regions = true;
boolean_param("ext_regions", opt_ext_regions);

static u64 __initdata dom0_mem;
static bool __initdata dom0_mem_set;

static int __init parse_dom0_mem(const char *s)
{
    dom0_mem_set = true;

    dom0_mem = parse_size_and_unit(s, &s);

    return *s ? -EINVAL : 0;
}
custom_param("dom0_mem", parse_dom0_mem);

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

//#define DEBUG_11_ALLOCATION
#ifdef DEBUG_11_ALLOCATION
# define D11PRINT(fmt, args...) printk(XENLOG_DEBUG fmt, ##args)
#else
# define D11PRINT(fmt, args...) do {} while ( 0 )
#endif

/*
 * Amount of extra space required to dom0's device tree.  No new nodes
 * are added (yet) but one terminating reserve map entry (16 bytes) is
 * added.
 */
#define DOM0_FDT_EXTRA_SIZE (128 + sizeof(struct fdt_reserve_entry))

unsigned int __init dom0_max_vcpus(void)
{
    if ( opt_dom0_max_vcpus == 0 )
    {
        ASSERT(cpupool0);
        opt_dom0_max_vcpus = cpumask_weight(cpupool_valid_cpus(cpupool0));
    }
    if ( opt_dom0_max_vcpus > MAX_VIRT_CPUS )
        opt_dom0_max_vcpus = MAX_VIRT_CPUS;

    return opt_dom0_max_vcpus;
}

struct vcpu *__init alloc_dom0_vcpu0(struct domain *dom0)
{
    return vcpu_create(dom0, 0);
}

static unsigned int __init get_allocation_size(paddr_t size)
{
    /*
     * get_order_from_bytes returns the order greater than or equal to
     * the given size, but we need less than or equal. Adding one to
     * the size pushes an evenly aligned size into the next order, so
     * we can then unconditionally subtract 1 from the order which is
     * returned.
     */
    return get_order_from_bytes(size + 1) - 1;
}

/*
 * Insert the given pages into a memory bank, banks are ordered by address.
 *
 * Returns false if the memory would be below bank 0 or we have run
 * out of banks. In this case it will free the pages.
 */
static bool __init insert_11_bank(struct domain *d,
                                  struct kernel_info *kinfo,
                                  struct page_info *pg,
                                  unsigned int order)
{
    unsigned int i;
    int res;
    mfn_t smfn;
    paddr_t start, size;

    smfn = page_to_mfn(pg);
    start = mfn_to_maddr(smfn);
    size = pfn_to_paddr(1UL << order);

    D11PRINT("Allocated %#"PRIpaddr"-%#"PRIpaddr" (%ldMB/%ldMB, order %d)\n",
             start, start + size,
             1UL << (order + PAGE_SHIFT - 20),
             /* Don't want format this as PRIpaddr (16 digit hex) */
             (unsigned long)(kinfo->unassigned_mem >> 20),
             order);

    if ( kinfo->mem.nr_banks > 0 &&
         size < MB(128) &&
         start + size < kinfo->mem.bank[0].start )
    {
        D11PRINT("Allocation below bank 0 is too small, not using\n");
        goto fail;
    }

    res = guest_physmap_add_page(d, _gfn(mfn_x(smfn)), smfn, order);
    if ( res )
        panic("Failed map pages to DOM0: %d\n", res);

    kinfo->unassigned_mem -= size;

    if ( kinfo->mem.nr_banks == 0 )
    {
        kinfo->mem.bank[0].start = start;
        kinfo->mem.bank[0].size = size;
        kinfo->mem.nr_banks = 1;
        return true;
    }

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        struct membank *bank = &kinfo->mem.bank[i];

        /* If possible merge new memory into the start of the bank */
        if ( bank->start == start+size )
        {
            bank->start = start;
            bank->size += size;
            return true;
        }

        /* If possible merge new memory onto the end of the bank */
        if ( start == bank->start + bank->size )
        {
            bank->size += size;
            return true;
        }

        /*
         * Otherwise if it is below this bank insert new memory in a
         * new bank before this one. If there was a lower bank we
         * could have inserted the memory into/before we would already
         * have done so, so this must be the right place.
         */
        if ( start + size < bank->start && kinfo->mem.nr_banks < NR_MEM_BANKS )
        {
            memmove(bank + 1, bank,
                    sizeof(*bank) * (kinfo->mem.nr_banks - i));
            kinfo->mem.nr_banks++;
            bank->start = start;
            bank->size = size;
            return true;
        }
    }

    if ( i == kinfo->mem.nr_banks && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        struct membank *bank = &kinfo->mem.bank[kinfo->mem.nr_banks];

        bank->start = start;
        bank->size = size;
        kinfo->mem.nr_banks++;
        return true;
    }

    /* If we get here then there are no more banks to fill. */

fail:
    free_domheap_pages(pg, order);
    return false;
}

/*
 * This is all pretty horrible.
 *
 * Requirements:
 *
 * 1. The dom0 kernel should be loaded within the first 128MB of RAM. This
 *    is necessary at least for Linux zImage kernels, which are all we
 *    support today.
 * 2. We want to put the dom0 kernel, ramdisk and DTB in the same
 *    bank. Partly this is just easier for us to deal with, but also
 *    the ramdisk and DTB must be placed within a certain proximity of
 *    the kernel within RAM.
 * 3. For dom0 we want to place as much of the RAM as we reasonably can
 *    below 4GB, so that it can be used by non-LPAE enabled kernels (32-bit).
 * 4. Some devices assigned to dom0 can only do 32-bit DMA access or
 *    even be more restricted. We want to allocate as much of the RAM
 *    as we reasonably can that can be accessed from all the devices..
 * 5. For 32-bit dom0 the kernel must be located below 4GB.
 * 6. We want to have a few largers banks rather than many smaller ones.
 *
 * For the first two requirements we need to make sure that the lowest
 * bank is sufficiently large.
 *
 * For convenience we also sort the banks by physical address.
 *
 * The memory allocator does not really give us the flexibility to
 * meet these requirements directly. So instead of proceed as follows:
 *
 * We first allocate the largest allocation we can as low as we
 * can. This then becomes the first bank. This bank must be at least
 * 128MB (or dom0_mem if that is smaller).
 *
 * Then we start allocating more memory, trying to allocate the
 * largest possible size and trying smaller sizes until we
 * successfully allocate something.
 *
 * We then try and insert this memory in to the list of banks. If it
 * can be merged into an existing bank then this is trivial.
 *
 * If the new memory is before the first bank (and cannot be merged into it)
 * and is at least 128M then we allow it, otherwise we give up. Since the
 * allocator prefers to allocate high addresses first and the first bank has
 * already been allocated to be as low as possible this likely means we
 * wouldn't have been able to allocate much more memory anyway.
 *
 * Otherwise we insert a new bank. If we've reached MAX_NR_BANKS then
 * we give up.
 *
 * For 32-bit domain we require that the initial allocation for the
 * first bank is part of the low mem. For 64-bit, the first bank is preferred
 * to be allocated in the low mem. Then for subsequent allocation, we
 * initially allocate memory only from low mem. Once that runs out out
 * (as described above) we allow higher allocations and continue until
 * that runs out (or we have allocated sufficient dom0 memory).
 */
static void __init allocate_memory_11(struct domain *d,
                                      struct kernel_info *kinfo)
{
    const unsigned int min_low_order =
        get_order_from_bytes(min_t(paddr_t, dom0_mem, MB(128)));
    const unsigned int min_order = get_order_from_bytes(MB(4));
    struct page_info *pg;
    unsigned int order = get_allocation_size(kinfo->unassigned_mem);
    unsigned int i;

    bool lowmem = true;
    unsigned int lowmem_bitsize = min(32U, arch_get_dma_bitsize());
    unsigned int bits;

    /*
     * TODO: Implement memory bank allocation when DOM0 is not direct
     * mapped
     */
    BUG_ON(!is_domain_direct_mapped(d));

    printk("Allocating 1:1 mappings totalling %ldMB for dom0:\n",
           /* Don't want format this as PRIpaddr (16 digit hex) */
           (unsigned long)(kinfo->unassigned_mem >> 20));

    kinfo->mem.nr_banks = 0;

    /*
     * First try and allocate the largest thing we can as low as
     * possible to be bank 0.
     */
    while ( order >= min_low_order )
    {
        for ( bits = order ; bits <= lowmem_bitsize; bits++ )
        {
            pg = alloc_domheap_pages(d, order, MEMF_bits(bits));
            if ( pg != NULL )
            {
                if ( !insert_11_bank(d, kinfo, pg, order) )
                    BUG(); /* Cannot fail for first bank */

                goto got_bank0;
            }
        }
        order--;
    }

    /* Failed to allocate bank0 in the lowmem region. */
    if ( is_32bit_domain(d) )
        panic("Unable to allocate first memory bank\n");

    /* Try to allocate memory from above the lowmem region */
    printk(XENLOG_INFO "No bank has been allocated below %u-bit.\n",
           lowmem_bitsize);
    lowmem = false;

 got_bank0:

    /*
     * If we failed to allocate bank0 in the lowmem region,
     * continue allocating from above the lowmem and fill in banks.
     */
    order = get_allocation_size(kinfo->unassigned_mem);
    while ( kinfo->unassigned_mem && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        pg = alloc_domheap_pages(d, order,
                                 lowmem ? MEMF_bits(lowmem_bitsize) : 0);
        if ( !pg )
        {
            order --;

            if ( lowmem && order < min_low_order)
            {
                D11PRINT("Failed at min_low_order, allow high allocations\n");
                order = get_allocation_size(kinfo->unassigned_mem);
                lowmem = false;
                continue;
            }
            if ( order >= min_order )
                continue;

            /* No more we can do */
            break;
        }

        if ( !insert_11_bank(d, kinfo, pg, order) )
        {
            if ( kinfo->mem.nr_banks == NR_MEM_BANKS )
                /* Nothing more we can do. */
                break;

            if ( lowmem )
            {
                D11PRINT("Allocation below bank 0, allow high allocations\n");
                order = get_allocation_size(kinfo->unassigned_mem);
                lowmem = false;
                continue;
            }
            else
            {
                D11PRINT("Allocation below bank 0\n");
                break;
            }
        }

        /*
         * Success, next time around try again to get the largest order
         * allocation possible.
         */
        order = get_allocation_size(kinfo->unassigned_mem);
    }

    if ( kinfo->unassigned_mem )
        /* Don't want format this as PRIpaddr (16 digit hex) */
        panic("Failed to allocate requested dom0 memory. %ldMB unallocated\n",
              (unsigned long)kinfo->unassigned_mem >> 20);

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        printk("BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               i,
               kinfo->mem.bank[i].start,
               kinfo->mem.bank[i].start + kinfo->mem.bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(kinfo->mem.bank[i].size >> 20));
    }
}

static bool __init allocate_bank_memory(struct domain *d,
                                        struct kernel_info *kinfo,
                                        gfn_t sgfn,
                                        paddr_t tot_size)
{
    int res;
    struct page_info *pg;
    struct membank *bank;
    unsigned int max_order = ~0;

    /*
     * allocate_bank_memory can be called with a tot_size of zero for
     * the second memory bank. It is not an error and we can safely
     * avoid creating a zero-size memory bank.
     */
    if ( tot_size == 0 )
        return true;

    bank = &kinfo->mem.bank[kinfo->mem.nr_banks];
    bank->start = gfn_to_gaddr(sgfn);
    bank->size = tot_size;

    while ( tot_size > 0 )
    {
        unsigned int order = get_allocation_size(tot_size);

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

        res = guest_physmap_add_page(d, sgfn, page_to_mfn(pg), order);
        if ( res )
        {
            dprintk(XENLOG_ERR, "Failed map pages to DOMU: %d", res);
            return false;
        }

        sgfn = gfn_add(sgfn, 1UL << order);
        tot_size -= (1ULL << (PAGE_SHIFT + order));
    }

    kinfo->mem.nr_banks++;
    kinfo->unassigned_mem -= bank->size;

    return true;
}

static void __init allocate_memory(struct domain *d, struct kernel_info *kinfo)
{
    unsigned int i;
    paddr_t bank_size;

    printk(XENLOG_INFO "Allocating mappings totalling %ldMB for %pd:\n",
           /* Don't want format this as PRIpaddr (16 digit hex) */
           (unsigned long)(kinfo->unassigned_mem >> 20), d);

    kinfo->mem.nr_banks = 0;
    bank_size = MIN(GUEST_RAM0_SIZE, kinfo->unassigned_mem);
    if ( !allocate_bank_memory(d, kinfo, gaddr_to_gfn(GUEST_RAM0_BASE),
                               bank_size) )
        goto fail;

    bank_size = MIN(GUEST_RAM1_SIZE, kinfo->unassigned_mem);
    if ( !allocate_bank_memory(d, kinfo, gaddr_to_gfn(GUEST_RAM1_BASE),
                               bank_size) )
        goto fail;

    if ( kinfo->unassigned_mem )
        goto fail;

    for( i = 0; i < kinfo->mem.nr_banks; i++ )
    {
        printk(XENLOG_INFO "%pd BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               d,
               i,
               kinfo->mem.bank[i].start,
               kinfo->mem.bank[i].start + kinfo->mem.bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(kinfo->mem.bank[i].size >> 20));
    }

    return;

fail:
    panic("Failed to allocate requested domain memory."
          /* Don't want format this as PRIpaddr (16 digit hex) */
          " %ldKB unallocated. Fix the VMs configurations.\n",
          (unsigned long)kinfo->unassigned_mem >> 10);
}

#ifdef CONFIG_STATIC_MEMORY
static bool __init append_static_memory_to_bank(struct domain *d,
                                                struct membank *bank,
                                                mfn_t smfn,
                                                paddr_t size)
{
    int res;
    unsigned int nr_pages = PFN_DOWN(size);
    gfn_t sgfn;

    /*
     * For direct-mapped domain, the GFN match the MFN.
     * Otherwise, this is inferred on what has already been allocated
     * in the bank.
     */
    if ( !is_domain_direct_mapped(d) )
        sgfn = gaddr_to_gfn(bank->start + bank->size);
    else
        sgfn = gaddr_to_gfn(mfn_to_maddr(smfn));

    res = guest_physmap_add_pages(d, sgfn, smfn, nr_pages);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed to map pages to DOMU: %d", res);
        return false;
    }

    bank->size = bank->size + size;

    return true;
}

static mfn_t __init acquire_static_memory_bank(struct domain *d,
                                               const __be32 **cell,
                                               u32 addr_cells, u32 size_cells,
                                               paddr_t *pbase, paddr_t *psize)
{
    mfn_t smfn;
    int res;

    device_tree_get_reg(cell, addr_cells, size_cells, pbase, psize);
    ASSERT(IS_ALIGNED(*pbase, PAGE_SIZE) && IS_ALIGNED(*psize, PAGE_SIZE));
    if ( PFN_DOWN(*psize) > UINT_MAX )
    {
        printk(XENLOG_ERR "%pd: static memory size too large: %#"PRIpaddr,
               d, *psize);
        return INVALID_MFN;
    }

    smfn = maddr_to_mfn(*pbase);
    res = acquire_domstatic_pages(d, smfn, PFN_DOWN(*psize), 0);
    if ( res )
    {
        printk(XENLOG_ERR
               "%pd: failed to acquire static memory: %d.\n", d, res);
        return INVALID_MFN;
    }

    return smfn;
}

static int __init parse_static_mem_prop(const struct dt_device_node *node,
                                        u32 *addr_cells, u32 *size_cells,
                                        int *length, const __be32 **cell)
{
    const struct dt_property *prop;

    prop = dt_find_property(node, "xen,static-mem", NULL);

    *addr_cells = dt_n_addr_cells(node);
    *size_cells = dt_n_size_cells(node);

    *cell = (const __be32 *)prop->value;
    *length = prop->length;

    return 0;
}

/* Allocate memory from static memory as RAM for one specific domain d. */
static void __init allocate_static_memory(struct domain *d,
                                          struct kernel_info *kinfo,
                                          const struct dt_device_node *node)
{
    u32 addr_cells, size_cells, reg_cells;
    unsigned int nr_banks, gbank, bank = 0;
    const uint64_t rambase[] = GUEST_RAM_BANK_BASES;
    const uint64_t ramsize[] = GUEST_RAM_BANK_SIZES;
    const __be32 *cell;
    u64 tot_size = 0;
    paddr_t pbase, psize, gsize;
    mfn_t smfn;
    int length;

    if ( parse_static_mem_prop(node, &addr_cells, &size_cells, &length, &cell) )
        goto fail;
    reg_cells = addr_cells + size_cells;

    /*
     * The static memory will be mapped in the guest at the usual guest memory
     * addresses (GUEST_RAM0_BASE, GUEST_RAM1_BASE) defined by
     * xen/include/public/arch-arm.h.
     */
    gbank = 0;
    gsize = ramsize[gbank];
    kinfo->mem.bank[gbank].start = rambase[gbank];
    nr_banks = length / (reg_cells * sizeof (u32));

    for ( ; bank < nr_banks; bank++ )
    {
        smfn = acquire_static_memory_bank(d, &cell, addr_cells, size_cells,
                                          &pbase, &psize);
        if ( mfn_eq(smfn, INVALID_MFN) )
            goto fail;

        printk(XENLOG_INFO "%pd: STATIC BANK[%u] %#"PRIpaddr"-%#"PRIpaddr"\n",
               d, bank, pbase, pbase + psize);

        while ( 1 )
        {
            /* Map as much as possible the static range to the guest bank */
            if ( !append_static_memory_to_bank(d, &kinfo->mem.bank[gbank], smfn,
                                               min(psize, gsize)) )
                goto fail;

            /*
             * The current physical bank is fully mapped.
             * Handle the next physical bank.
             */
            if ( gsize >= psize )
            {
                gsize = gsize - psize;
                break;
            }
            /*
             * When current guest bank is not enough to map, exhaust
             * the current one and seek to the next.
             * Before seeking to the next, check if we still have available
             * guest bank.
             */
            else if ( (gbank + 1) >= GUEST_RAM_BANKS )
            {
                printk(XENLOG_ERR "Exhausted all possible guest banks.\n");
                goto fail;
            }
            else
            {
                psize = psize - gsize;
                smfn = mfn_add(smfn, gsize >> PAGE_SHIFT);
                /* Update to the next guest bank. */
                gbank++;
                gsize = ramsize[gbank];
                kinfo->mem.bank[gbank].start = rambase[gbank];
            }
        }

        tot_size += psize;
    }

    kinfo->mem.nr_banks = ++gbank;

    kinfo->unassigned_mem -= tot_size;
    /*
     * The property 'memory' should match the amount of memory given to the
     * guest.
     * Currently, it is only possible to either acquire static memory or let
     * Xen allocate. *Mixing* is not supported.
     */
    if ( kinfo->unassigned_mem )
    {
        printk(XENLOG_ERR
               "Size of \"memory\" property doesn't match up with the sum-up of \"xen,static-mem\". Unsupported configuration.\n");
        goto fail;
    }

    return;

 fail:
    panic("Failed to allocate requested static memory for domain %pd.", d);
}

/*
 * Allocate static memory as RAM for one specific domain d.
 * The static memory will be directly mapped in the guest(Guest Physical
 * Address == Physical Address).
 */
static void __init assign_static_memory_11(struct domain *d,
                                           struct kernel_info *kinfo,
                                           const struct dt_device_node *node)
{
    u32 addr_cells, size_cells, reg_cells;
    unsigned int nr_banks, bank = 0;
    const __be32 *cell;
    paddr_t pbase, psize;
    mfn_t smfn;
    int length;

    if ( parse_static_mem_prop(node, &addr_cells, &size_cells, &length, &cell) )
    {
        printk(XENLOG_ERR
               "%pd: failed to parse \"xen,static-mem\" property.\n", d);
        goto fail;
    }
    reg_cells = addr_cells + size_cells;
    nr_banks = length / (reg_cells * sizeof(u32));

    if ( nr_banks > NR_MEM_BANKS )
    {
        printk(XENLOG_ERR
               "%pd: exceed max number of supported guest memory banks.\n", d);
        goto fail;
    }

    for ( ; bank < nr_banks; bank++ )
    {
        smfn = acquire_static_memory_bank(d, &cell, addr_cells, size_cells,
                                          &pbase, &psize);
        if ( mfn_eq(smfn, INVALID_MFN) )
            goto fail;

        printk(XENLOG_INFO "%pd: STATIC BANK[%u] %#"PRIpaddr"-%#"PRIpaddr"\n",
               d, bank, pbase, pbase + psize);

        /* One guest memory bank is matched with one physical memory bank. */
        kinfo->mem.bank[bank].start = pbase;
        if ( !append_static_memory_to_bank(d, &kinfo->mem.bank[bank],
                                           smfn, psize) )
            goto fail;

        kinfo->unassigned_mem -= psize;
    }

    kinfo->mem.nr_banks = nr_banks;

    /*
     * The property 'memory' should match the amount of memory given to
     * the guest.
     * Currently, it is only possible to either acquire static memory or
     * let Xen allocate. *Mixing* is not supported.
     */
    if ( kinfo->unassigned_mem != 0 )
    {
        printk(XENLOG_ERR
               "Size of \"memory\" property doesn't match up with the sum-up of \"xen,static-mem\".\n");
        goto fail;
    }

    return;

 fail:
    panic("Failed to assign requested static memory for direct-map domain %pd.",
          d);
}

#ifdef CONFIG_STATIC_SHM
static int __init acquire_nr_borrower_domain(struct domain *d,
                                             paddr_t pbase, paddr_t psize,
                                             unsigned long *nr_borrowers)
{
    unsigned int bank;

    /* Iterate reserved memory to find requested shm bank. */
    for ( bank = 0 ; bank < bootinfo.reserved_mem.nr_banks; bank++ )
    {
        paddr_t bank_start = bootinfo.reserved_mem.bank[bank].start;
        paddr_t bank_size = bootinfo.reserved_mem.bank[bank].size;

        if ( (pbase == bank_start) && (psize == bank_size) )
            break;
    }

    if ( bank == bootinfo.reserved_mem.nr_banks )
        return -ENOENT;

    *nr_borrowers = bootinfo.reserved_mem.bank[bank].nr_shm_borrowers;

    return 0;
}

/*
 * This function checks whether the static shared memory region is
 * already allocated to dom_io.
 */
static bool __init is_shm_allocated_to_domio(paddr_t pbase)
{
    struct page_info *page;
    struct domain *d;

    page = maddr_to_page(pbase);
    d = page_get_owner_and_reference(page);
    if ( d == NULL )
        return false;
    put_page(page);

    if ( d != dom_io )
    {
        printk(XENLOG_ERR
               "shm memory node has already been allocated to a specific owner %pd, Please check your configuration\n",
               d);
        return false;
    }

    return true;
}

static mfn_t __init acquire_shared_memory_bank(struct domain *d,
                                               paddr_t pbase, paddr_t psize)
{
    mfn_t smfn;
    unsigned long nr_pfns;
    int res;

    /*
     * Pages of statically shared memory shall be included
     * into domain_tot_pages().
     */
    nr_pfns = PFN_DOWN(psize);
    if ( (UINT_MAX - d->max_pages) < nr_pfns )
    {
        printk(XENLOG_ERR "%pd: Over-allocation for d->max_pages: %lu.\n",
               d, nr_pfns);
        return INVALID_MFN;
    }
    d->max_pages += nr_pfns;

    smfn = maddr_to_mfn(pbase);
    res = acquire_domstatic_pages(d, smfn, nr_pfns, 0);
    if ( res )
    {
        printk(XENLOG_ERR
               "%pd: failed to acquire static memory: %d.\n", d, res);
        d->max_pages -= nr_pfns;
        return INVALID_MFN;
    }

    return smfn;
}

static int __init assign_shared_memory(struct domain *d,
                                       uint32_t addr_cells, uint32_t size_cells,
                                       paddr_t pbase, paddr_t psize,
                                       paddr_t gbase)
{
    mfn_t smfn;
    int ret = 0;
    unsigned long nr_pages, nr_borrowers, i;
    struct page_info *page;

    printk("%pd: allocate static shared memory BANK %#"PRIpaddr"-%#"PRIpaddr".\n",
           d, pbase, pbase + psize);

    smfn = acquire_shared_memory_bank(d, pbase, psize);
    if ( mfn_eq(smfn, INVALID_MFN) )
        return -EINVAL;

    /*
     * DOMID_IO is not auto-translated (i.e. it sees RAM 1:1). So we do not need
     * to create mapping in the P2M.
     */
    nr_pages = PFN_DOWN(psize);
    if ( d != dom_io )
    {
        ret = guest_physmap_add_pages(d, gaddr_to_gfn(gbase), smfn,
                                      PFN_DOWN(psize));
        if ( ret )
        {
            printk(XENLOG_ERR "Failed to map shared memory to %pd.\n", d);
            return ret;
        }
    }

    /*
     * Get the right amount of references per page, which is the number of
     * borrower domains.
     */
    ret = acquire_nr_borrower_domain(d, pbase, psize, &nr_borrowers);
    if ( ret )
        return ret;

    /*
     * Instead of letting borrower domain get a page ref, we add as many
     * additional reference as the number of borrowers when the owner
     * is allocated, since there is a chance that owner is created
     * after borrower.
     * So if the borrower is created first, it will cause adding pages
     * in the P2M without reference.
     */
    page = mfn_to_page(smfn);
    for ( i = 0; i < nr_pages; i++ )
    {
        if ( !get_page_nr(page + i, d, nr_borrowers) )
        {
            printk(XENLOG_ERR
                   "Failed to add %lu references to page %"PRI_mfn".\n",
                   nr_borrowers, mfn_x(smfn) + i);
            goto fail;
        }
    }

    return 0;

 fail:
    while ( --i >= 0 )
        put_page_nr(page + i, nr_borrowers);
    return ret;
}

static int __init append_shm_bank_to_domain(struct kernel_info *kinfo,
                                            paddr_t start, paddr_t size,
                                            const char *shm_id)
{
    if ( kinfo->shm_mem.nr_banks >= NR_MEM_BANKS )
        return -ENOMEM;

    kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].start = start;
    kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].size = size;
    safe_strcpy(kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].shm_id, shm_id);
    kinfo->shm_mem.nr_banks++;

    return 0;
}

static int __init process_shm(struct domain *d, struct kernel_info *kinfo,
                              const struct dt_device_node *node)
{
    struct dt_device_node *shm_node;

    dt_for_each_child_node(node, shm_node)
    {
        const struct dt_property *prop;
        const __be32 *cells;
        uint32_t addr_cells, size_cells;
        paddr_t gbase, pbase, psize;
        int ret = 0;
        unsigned int i;
        const char *role_str;
        const char *shm_id;
        bool owner_dom_io = true;

        if ( !dt_device_is_compatible(shm_node, "xen,domain-shared-memory-v1") )
            continue;

        /*
         * xen,shared-mem = <pbase, gbase, size>;
         * TODO: pbase is optional.
         */
        addr_cells = dt_n_addr_cells(shm_node);
        size_cells = dt_n_size_cells(shm_node);
        prop = dt_find_property(shm_node, "xen,shared-mem", NULL);
        BUG_ON(!prop);
        cells = (const __be32 *)prop->value;
        device_tree_get_reg(&cells, addr_cells, addr_cells, &pbase, &gbase);
        psize = dt_read_number(cells, size_cells);
        if ( !IS_ALIGNED(pbase, PAGE_SIZE) || !IS_ALIGNED(gbase, PAGE_SIZE) )
        {
            printk("%pd: physical address 0x%"PRIpaddr", or guest address 0x%"PRIpaddr" is not suitably aligned.\n",
                   d, pbase, gbase);
            return -EINVAL;
        }
        if ( !IS_ALIGNED(psize, PAGE_SIZE) )
        {
            printk("%pd: size 0x%"PRIpaddr" is not suitably aligned\n",
                   d, psize);
            return -EINVAL;
        }

        for ( i = 0; i < PFN_DOWN(psize); i++ )
            if ( !mfn_valid(mfn_add(maddr_to_mfn(pbase), i)) )
            {
                printk("%pd: invalid physical address 0x%"PRI_mfn"\n",
                       d, mfn_x(mfn_add(maddr_to_mfn(pbase), i)));
                return -EINVAL;
            }

        /*
         * "role" property is optional and if it is defined explicitly,
         * then the owner domain is not the default "dom_io" domain.
         */
        if ( dt_property_read_string(shm_node, "role", &role_str) == 0 )
            owner_dom_io = false;

        if ( dt_property_read_string(shm_node, "xen,shm-id", &shm_id) )
        {
            printk("%pd: invalid \"xen,shm-id\" property", d);
            return -EINVAL;
        }
        BUG_ON((strlen(shm_id) <= 0) || (strlen(shm_id) >= MAX_SHM_ID_LENGTH));

        /*
         * DOMID_IO is a fake domain and is not described in the Device-Tree.
         * Therefore when the owner of the shared region is DOMID_IO, we will
         * only find the borrowers.
         */
        if ( (owner_dom_io && !is_shm_allocated_to_domio(pbase)) ||
             (!owner_dom_io && strcmp(role_str, "owner") == 0) )
        {
            /*
             * We found the first borrower of the region, the owner was not
             * specified, so they should be assigned to dom_io.
             */
            ret = assign_shared_memory(owner_dom_io ? dom_io : d,
                                       addr_cells, size_cells,
                                       pbase, psize, gbase);
            if ( ret )
                return ret;
        }

        if ( owner_dom_io || (strcmp(role_str, "borrower") == 0) )
        {
            /* Set up P2M foreign mapping for borrower domain. */
            ret = map_regions_p2mt(d, _gfn(PFN_UP(gbase)), PFN_DOWN(psize),
                                   _mfn(PFN_UP(pbase)), p2m_map_foreign_rw);
            if ( ret )
                return ret;
        }

        /*
         * Record static shared memory region info for later setting
         * up shm-node in guest device tree.
         */
        ret = append_shm_bank_to_domain(kinfo, gbase, psize, shm_id);
        if ( ret )
            return ret;
    }

    return 0;
}
#endif /* CONFIG_STATIC_SHM */
#else
static void __init allocate_static_memory(struct domain *d,
                                          struct kernel_info *kinfo,
                                          const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}

static void __init assign_static_memory_11(struct domain *d,
                                           struct kernel_info *kinfo,
                                           const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}
#endif

/*
 * When PCI passthrough is available we want to keep the
 * "linux,pci-domain" in sync for every host bridge.
 *
 * Xen may not have a driver for all the host bridges. So we have
 * to write an heuristic to detect whether a device node describes
 * a host bridge.
 *
 * The current heuristic assumes that a device is a host bridge
 * if the type is "pci" and then parent type is not "pci".
 */
static int __init handle_linux_pci_domain(struct kernel_info *kinfo,
                                          const struct dt_device_node *node)
{
    uint16_t segment;
    int res;

    if ( !is_pci_passthrough_enabled() )
        return 0;

    if ( !dt_device_type_is_equal(node, "pci") )
        return 0;

    if ( node->parent && dt_device_type_is_equal(node->parent, "pci") )
        return 0;

    if ( dt_find_property(node, "linux,pci-domain", NULL) )
        return 0;

    /* Allocate and create the linux,pci-domain */
    res = pci_get_host_bridge_segment(node, &segment);
    if ( res < 0 )
    {
        res = pci_get_new_domain_nr();
        if ( res < 0 )
        {
            printk(XENLOG_DEBUG "Can't assign PCI segment to %s\n",
                   node->full_name);
            return -FDT_ERR_NOTFOUND;
        }

        segment = res;
        printk(XENLOG_DEBUG "Assigned segment %d to %s\n",
               segment, node->full_name);
    }

    return fdt_property_cell(kinfo->fdt, "linux,pci-domain", segment);
}

static int __init write_properties(struct domain *d, struct kernel_info *kinfo,
                                   const struct dt_device_node *node)
{
    const char *bootargs = NULL;
    const struct dt_property *prop, *status = NULL;
    int res = 0;
    int had_dom0_bootargs = 0;
    struct dt_device_node *iommu_node;

    if ( kinfo->cmdline && kinfo->cmdline[0] )
        bootargs = &kinfo->cmdline[0];

    /*
     * We always skip the IOMMU device when creating DT for hwdom if there is
     * an appropriate driver for it in Xen (device_get_class(iommu_node)
     * returns DEVICE_IOMMU).
     * We should also skip the IOMMU specific properties of the master device
     * behind that IOMMU in order to avoid exposing an half complete IOMMU
     * bindings to hwdom.
     * Use "iommu_node" as an indicator of the master device which properties
     * should be skipped.
     */
    iommu_node = dt_parse_phandle(node, "iommus", 0);
    if ( iommu_node && device_get_class(iommu_node) != DEVICE_IOMMU )
        iommu_node = NULL;

    dt_for_each_property_node (node, prop)
    {
        const void *prop_data = prop->value;
        u32 prop_len = prop->length;

        /*
         * In chosen node:
         *
         * * remember xen,dom0-bootargs if we don't already have
         *   bootargs (from module #1, above).
         * * remove bootargs,  xen,dom0-bootargs, xen,xen-bootargs,
         *   linux,initrd-start and linux,initrd-end.
         * * remove stdout-path.
         * * remove bootargs, linux,uefi-system-table,
         *   linux,uefi-mmap-start, linux,uefi-mmap-size,
         *   linux,uefi-mmap-desc-size, and linux,uefi-mmap-desc-ver
         *   (since EFI boot is not currently supported in dom0).
         */
        if ( dt_node_path_is_equal(node, "/chosen") )
        {
            if ( dt_property_name_is_equal(prop, "xen,xen-bootargs") ||
                 dt_property_name_is_equal(prop, "linux,initrd-start") ||
                 dt_property_name_is_equal(prop, "linux,initrd-end") ||
                 dt_property_name_is_equal(prop, "stdout-path") ||
                 dt_property_name_is_equal(prop, "linux,uefi-system-table") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-start") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-size") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-desc-size") ||
                 dt_property_name_is_equal(prop, "linux,uefi-mmap-desc-ver"))
                continue;

            if ( dt_property_name_is_equal(prop, "xen,dom0-bootargs") )
            {
                had_dom0_bootargs = 1;
                bootargs = prop->value;
                continue;
            }
            if ( dt_property_name_is_equal(prop, "bootargs") )
            {
                if ( !bootargs  && !had_dom0_bootargs )
                    bootargs = prop->value;
                continue;
            }
        }

        /* Don't expose the property "xen,passthrough" to the guest */
        if ( dt_property_name_is_equal(prop, "xen,passthrough") )
            continue;

        /* Remember and skip the status property as Xen may modify it later */
        if ( dt_property_name_is_equal(prop, "status") )
        {
            status = prop;
            continue;
        }

        if ( iommu_node )
        {
            /* Don't expose IOMMU specific properties to hwdom */
            if ( dt_property_name_is_equal(prop, "iommus") )
                continue;

            if ( dt_property_name_is_equal(prop, "iommu-map") )
                continue;

            if ( dt_property_name_is_equal(prop, "iommu-map-mask") )
                continue;
        }

        res = fdt_property(kinfo->fdt, prop->name, prop_data, prop_len);

        if ( res )
            return res;
    }

    res = handle_linux_pci_domain(kinfo, node);

    if ( res )
        return res;

    /*
     * Override the property "status" to disable the device when it's
     * marked for passthrough.
     */
    if ( dt_device_for_passthrough(node) )
        res = fdt_property_string(kinfo->fdt, "status", "disabled");
    else if ( status )
        res = fdt_property(kinfo->fdt, "status", status->value,
                           status->length);

    if ( res )
        return res;

    if ( dt_node_path_is_equal(node, "/chosen") )
    {
        const struct bootmodule *initrd = kinfo->initrd_bootmodule;

        if ( bootargs )
        {
            res = fdt_property(kinfo->fdt, "bootargs", bootargs,
                               strlen(bootargs) + 1);
            if ( res )
                return res;
        }

        /*
         * If the bootloader provides an initrd, we must create a placeholder
         * for the initrd properties. The values will be replaced later.
         */
        if ( initrd && initrd->size )
        {
            u64 a = 0;
            res = fdt_property(kinfo->fdt, "linux,initrd-start", &a, sizeof(a));
            if ( res )
                return res;

            res = fdt_property(kinfo->fdt, "linux,initrd-end", &a, sizeof(a));
            if ( res )
                return res;
        }
    }

    return 0;
}

/*
 * Helper to write an interrupts with the GIC format
 * This code is assuming the irq is an PPI.
 */

typedef __be32 gic_interrupt_t[3];

static void __init set_interrupt(gic_interrupt_t interrupt,
                                 unsigned int irq,
                                 unsigned int cpumask,
                                 unsigned int level)
{
    __be32 *cells = interrupt;
    bool is_ppi = !!(irq < 32);

    BUG_ON(irq < 16);
    irq -= (is_ppi) ? 16: 32; /* PPIs start at 16, SPIs at 32 */

    /* See linux Documentation/devicetree/bindings/interrupt-controller/arm,gic.txt */
    dt_set_cell(&cells, 1, is_ppi); /* is a PPI? */
    dt_set_cell(&cells, 1, irq);
    dt_set_cell(&cells, 1, (cpumask << 8) | level);
}

/*
 * Helper to set interrupts for a node in the flat device tree.
 * It needs 2 property:
 *  "interrupts": contains the list of interrupts
 *  "interrupt-parent": link to the GIC
 */
static int __init fdt_property_interrupts(const struct kernel_info *kinfo,
                                          gic_interrupt_t *intr,
                                          unsigned int num_irq)
{
    int res;

    res = fdt_property(kinfo->fdt, "interrupts",
                       intr, sizeof(intr[0]) * num_irq);
    if ( res )
        return res;

    res = fdt_property_cell(kinfo->fdt, "interrupt-parent",
                            kinfo->phandle_gic);

    return res;
}

/*
 * Wrapper to convert physical address from paddr_t to uint64_t and
 * invoke fdt_begin_node(). This is required as the physical address
 * provided as part of node name should not contain any leading
 * zeroes. Thus, one should use PRIx64 (instead of PRIpaddr) to append
 * unit (which contains the physical address) with name to generate a
 * node name.
 */
static int __init domain_fdt_begin_node(void *fdt, const char *name,
                                        uint64_t unit)
{
    /*
     * The size of the buffer to hold the longest possible string (i.e.
     * interrupt-controller@ + a 64-bit number + \0).
     */
    char buf[38];
    int ret;

    /* ePAPR 3.4 */
    ret = snprintf(buf, sizeof(buf), "%s@%"PRIx64, name, unit);

    if ( ret >= sizeof(buf) )
    {
        printk(XENLOG_ERR
               "Insufficient buffer. Minimum size required is %d\n",
               (ret + 1));

        return -FDT_ERR_TRUNCATED;
    }

    return fdt_begin_node(fdt, buf);
}

static int __init make_memory_node(const struct domain *d,
                                   void *fdt,
                                   int addrcells, int sizecells,
                                   struct meminfo *mem)
{
    unsigned int i;
    int res, reg_size = addrcells + sizecells;
    int nr_cells = 0;
    __be32 reg[NR_MEM_BANKS * 4 /* Worst case addrcells + sizecells */];
    __be32 *cells;

    if ( mem->nr_banks == 0 )
        return -ENOENT;

    /* find the first memory range that is reserved for device (or firmware) */
    for ( i = 0; i < mem->nr_banks &&
                 (mem->bank[i].type != MEMBANK_DEFAULT); i++ )
        ;

    if ( i == mem->nr_banks )
        return 0;

    dt_dprintk("Create memory node\n");

    res = domain_fdt_begin_node(fdt, "memory", mem->bank[i].start);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "device_type", "memory");
    if ( res )
        return res;

    cells = &reg[0];
    for ( ; i < mem->nr_banks; i++ )
    {
        u64 start = mem->bank[i].start;
        u64 size = mem->bank[i].size;

        if ( mem->bank[i].type == MEMBANK_STATIC_DOMAIN )
            continue;

        dt_dprintk("  Bank %d: %#"PRIx64"->%#"PRIx64"\n",
                   i, start, start + size);

        nr_cells += reg_size;
        BUG_ON(nr_cells >= ARRAY_SIZE(reg));
        dt_child_set_range(&cells, addrcells, sizecells, start, size);
    }

    dt_dprintk("(reg size %d, nr cells %d)\n", reg_size, nr_cells);

    res = fdt_property(fdt, "reg", reg, nr_cells * sizeof(*reg));
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

#ifdef CONFIG_STATIC_SHM
static int __init make_shm_memory_node(const struct domain *d,
                                       void *fdt,
                                       int addrcells, int sizecells,
                                       const struct meminfo *mem)
{
    unsigned int i = 0;
    int res = 0;

    if ( mem->nr_banks == 0 )
        return -ENOENT;

    /*
     * For each shared memory region, a range is exposed under
     * the /reserved-memory node as a child node. Each range sub-node is
     * named xen-shmem@<address>.
     */
    dt_dprintk("Create xen-shmem node\n");

    for ( ; i < mem->nr_banks; i++ )
    {
        uint64_t start = mem->bank[i].start;
        uint64_t size = mem->bank[i].size;
        const char compat[] = "xen,shared-memory-v1";
        /* Worst case addrcells + sizecells */
        __be32 reg[GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS];
        __be32 *cells;
        unsigned int len = (addrcells + sizecells) * sizeof(__be32);

        res = domain_fdt_begin_node(fdt, "xen-shmem", mem->bank[i].start);
        if ( res )
            return res;

        res = fdt_property(fdt, "compatible", compat, sizeof(compat));
        if ( res )
            return res;

        cells = reg;
        dt_child_set_range(&cells, addrcells, sizecells, start, size);

        res = fdt_property(fdt, "reg", reg, len);
        if ( res )
            return res;

        dt_dprintk("Shared memory bank %u: %#"PRIx64"->%#"PRIx64"\n",
                   i, start, start + size);

        res = fdt_property_string(fdt, "xen,id", mem->bank[i].shm_id);
        if ( res )
            return res;

        /*
         * TODO:
         * - xen,offset: (borrower VMs only)
         *   64 bit integer offset within the owner virtual machine's shared
         *   memory region used for the mapping in the borrower VM
         */
        res = fdt_property_u64(fdt, "xen,offset", 0);
        if ( res )
            return res;

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    return res;
}
#else
static int __init make_shm_memory_node(const struct domain *d,
                                       void *fdt,
                                       int addrcells, int sizecells,
                                       const struct meminfo *mem)
{
    ASSERT_UNREACHABLE();
    return -EOPNOTSUPP;
}
#endif

static int __init make_resv_memory_node(const struct domain *d,
                                        void *fdt,
                                        int addrcells, int sizecells,
                                        const struct meminfo *mem)
{
    int res = 0;
    /* Placeholder for reserved-memory\0 */
    const char resvbuf[16] = "reserved-memory";

    if ( mem->nr_banks == 0 )
        /* No shared memory provided. */
        return 0;

    dt_dprintk("Create reserved-memory node\n");

    res = fdt_begin_node(fdt, resvbuf);
    if ( res )
        return res;

    res = fdt_property(fdt, "ranges", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", addrcells);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", sizecells);
    if ( res )
        return res;

    res = make_shm_memory_node(d, fdt, addrcells, sizecells, mem);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int __init add_ext_regions(unsigned long s, unsigned long e, void *data)
{
    struct meminfo *ext_regions = data;
    paddr_t start, size;

    if ( ext_regions->nr_banks >= ARRAY_SIZE(ext_regions->bank) )
        return 0;

    /*
     * Both start and size of the extended region should be 2MB aligned to
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

    /*
     * Reasonable size. Not too little to pick up small ranges which are
     * not quite useful but increase bookkeeping and not too large
     * to skip a large proportion of unused address space.
     */
    if ( size < MB(64) )
        return 0;

    ext_regions->bank[ext_regions->nr_banks].start = start;
    ext_regions->bank[ext_regions->nr_banks].size = size;
    ext_regions->nr_banks++;

    return 0;
}

/*
 * Find unused regions of Host address space which can be exposed to Dom0
 * as extended regions for the special memory mappings. In order to calculate
 * regions we exclude every region assigned to Dom0 from the Host RAM:
 * - domain RAM
 * - reserved-memory
 * - grant table space
 */
static int __init find_unallocated_memory(const struct kernel_info *kinfo,
                                          struct meminfo *ext_regions)
{
    const struct meminfo *assign_mem = &kinfo->mem;
    struct rangeset *unalloc_mem;
    paddr_t start, end;
    unsigned int i;
    int res;

    dt_dprintk("Find unallocated memory for extended regions\n");

    unalloc_mem = rangeset_new(NULL, NULL, 0);
    if ( !unalloc_mem )
        return -ENOMEM;

    /* Start with all available RAM */
    for ( i = 0; i < bootinfo.mem.nr_banks; i++ )
    {
        start = bootinfo.mem.bank[i].start;
        end = bootinfo.mem.bank[i].start + bootinfo.mem.bank[i].size;
        res = rangeset_add_range(unalloc_mem, start, end - 1);
        if ( res )
        {
            printk(XENLOG_ERR "Failed to add: %#"PRIpaddr"->%#"PRIpaddr"\n",
                   start, end);
            goto out;
        }
    }

    /* Remove RAM assigned to Dom0 */
    for ( i = 0; i < assign_mem->nr_banks; i++ )
    {
        start = assign_mem->bank[i].start;
        end = assign_mem->bank[i].start + assign_mem->bank[i].size;
        res = rangeset_remove_range(unalloc_mem, start, end - 1);
        if ( res )
        {
            printk(XENLOG_ERR "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr"\n",
                   start, end);
            goto out;
        }
    }

    /* Remove reserved-memory regions */
    for ( i = 0; i < bootinfo.reserved_mem.nr_banks; i++ )
    {
        start = bootinfo.reserved_mem.bank[i].start;
        end = bootinfo.reserved_mem.bank[i].start +
            bootinfo.reserved_mem.bank[i].size;
        res = rangeset_remove_range(unalloc_mem, start, end - 1);
        if ( res )
        {
            printk(XENLOG_ERR "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr"\n",
                   start, end);
            goto out;
        }
    }

    /* Remove grant table region */
    start = kinfo->gnttab_start;
    end = kinfo->gnttab_start + kinfo->gnttab_size;
    res = rangeset_remove_range(unalloc_mem, start, end - 1);
    if ( res )
    {
        printk(XENLOG_ERR "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr"\n",
               start, end);
        goto out;
    }

    start = 0;
    end = (1ULL << p2m_ipa_bits) - 1;
    res = rangeset_report_ranges(unalloc_mem, start, end,
                                 add_ext_regions, ext_regions);
    if ( res )
        ext_regions->nr_banks = 0;
    else if ( !ext_regions->nr_banks )
        res = -ENOENT;

out:
    rangeset_destroy(unalloc_mem);

    return res;
}

static int __init handle_pci_range(const struct dt_device_node *dev,
                                   u64 addr, u64 len, void *data)
{
    struct rangeset *mem_holes = data;
    paddr_t start, end;
    int res;

    start = addr & PAGE_MASK;
    end = PAGE_ALIGN(addr + len);
    res = rangeset_remove_range(mem_holes, start, end - 1);
    if ( res )
    {
        printk(XENLOG_ERR "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr"\n",
               start, end);
        return res;
    }

    return 0;
}

/*
 * Find the holes in the Host DT which can be exposed to Dom0 as extended
 * regions for the special memory mappings. In order to calculate regions
 * we exclude every addressable memory region described by "reg" and "ranges"
 * properties from the maximum possible addressable physical memory range:
 * - MMIO
 * - Host RAM
 * - PCI aperture
 */
static int __init find_memory_holes(const struct kernel_info *kinfo,
                                    struct meminfo *ext_regions)
{
    struct dt_device_node *np;
    struct rangeset *mem_holes;
    paddr_t start, end;
    unsigned int i;
    int res;

    dt_dprintk("Find memory holes for extended regions\n");

    mem_holes = rangeset_new(NULL, NULL, 0);
    if ( !mem_holes )
        return -ENOMEM;

    /* Start with maximum possible addressable physical memory range */
    start = 0;
    end = (1ULL << p2m_ipa_bits) - 1;
    res = rangeset_add_range(mem_holes, start, end);
    if ( res )
    {
        printk(XENLOG_ERR "Failed to add: %#"PRIpaddr"->%#"PRIpaddr"\n",
               start, end);
        goto out;
    }

    /*
     * Remove regions described by "reg" and "ranges" properties where
     * the memory is addressable (MMIO, RAM, PCI BAR, etc).
     */
    dt_for_each_device_node( dt_host, np )
    {
        unsigned int naddr;
        u64 addr, size;

        naddr = dt_number_of_address(np);

        for ( i = 0; i < naddr; i++ )
        {
            res = dt_device_get_address(np, i, &addr, &size);
            if ( res )
            {
                printk(XENLOG_ERR "Unable to retrieve address %u for %s\n",
                       i, dt_node_full_name(np));
                goto out;
            }

            start = addr & PAGE_MASK;
            end = PAGE_ALIGN(addr + size);
            res = rangeset_remove_range(mem_holes, start, end - 1);
            if ( res )
            {
                printk(XENLOG_ERR "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr"\n",
                       start, end);
                goto out;
            }
        }

        if ( dt_device_type_is_equal(np, "pci") )
        {
            /*
             * The ranges property in this context describes the PCI host
             * bridge aperture. It shall be absent if no addresses are mapped
             * through the bridge.
             */
            if ( !dt_get_property(np, "ranges", NULL) )
                continue;

            res = dt_for_each_range(np, &handle_pci_range, mem_holes);
            if ( res )
                goto out;
        }
    }

    start = 0;
    end = (1ULL << p2m_ipa_bits) - 1;
    res = rangeset_report_ranges(mem_holes, start, end,
                                 add_ext_regions,  ext_regions);
    if ( res )
        ext_regions->nr_banks = 0;
    else if ( !ext_regions->nr_banks )
        res = -ENOENT;

out:
    rangeset_destroy(mem_holes);

    return res;
}

static int __init find_domU_holes(const struct kernel_info *kinfo,
                                  struct meminfo *ext_regions)
{
    unsigned int i;
    uint64_t bankend;
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
    const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;
    int res = -ENOENT;

    for ( i = 0; i < GUEST_RAM_BANKS; i++ )
    {
        struct membank *ext_bank = &(ext_regions->bank[ext_regions->nr_banks]);

        ext_bank->start = ROUNDUP(bankbase[i] + kinfo->mem.bank[i].size, SZ_2M);

        bankend = ~0ULL >> (64 - p2m_ipa_bits);
        bankend = min(bankend, bankbase[i] + banksize[i] - 1);
        if ( bankend > ext_bank->start )
            ext_bank->size = bankend - ext_bank->start + 1;

        /* 64MB is the minimum size of an extended region */
        if ( ext_bank->size < MB(64) )
            continue;
        ext_regions->nr_banks++;
        res = 0;
    }

    return res;
}

static int __init make_hypervisor_node(struct domain *d,
                                       const struct kernel_info *kinfo,
                                       int addrcells, int sizecells)
{
    const char compat[] =
        "xen,xen-" XEN_VERSION_STRING "\0"
        "xen,xen";
    __be32 *reg, *cells;
    gic_interrupt_t intr;
    int res;
    void *fdt = kinfo->fdt;
    struct meminfo *ext_regions = NULL;
    unsigned int i, nr_ext_regions;

    dt_dprintk("Create hypervisor node\n");

    /*
     * Sanity-check address sizes, since addresses and sizes which do
     * not take up exactly 4 or 8 bytes are not supported.
     */
    if ((addrcells != 1 && addrcells != 2) ||
        (sizecells != 1 && sizecells != 2))
        panic("Cannot cope with this size\n");

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    res = fdt_begin_node(fdt, "hypervisor");
    if ( res )
        return res;

    /* Cannot use fdt_property_string due to embedded nulls */
    res = fdt_property(fdt, "compatible", compat, sizeof(compat));
    if ( res )
        return res;

    if ( !opt_ext_regions )
    {
        printk(XENLOG_INFO "%pd: extended regions support is disabled\n", d);
        nr_ext_regions = 0;
    }
    else if ( is_32bit_domain(d) )
    {
        printk(XENLOG_WARNING
               "%pd: extended regions not supported for 32-bit guests\n", d);
        nr_ext_regions = 0;
    }
    else
    {
        ext_regions = xzalloc(struct meminfo);
        if ( !ext_regions )
            return -ENOMEM;

        if ( is_domain_direct_mapped(d) )
        {
            if ( !is_iommu_enabled(d) )
                res = find_unallocated_memory(kinfo, ext_regions);
            else
                res = find_memory_holes(kinfo, ext_regions);
        }
        else
        {
            res = find_domU_holes(kinfo, ext_regions);
        }

        if ( res )
            printk(XENLOG_WARNING "%pd: failed to allocate extended regions\n",
                   d);
        nr_ext_regions = ext_regions->nr_banks;
    }

    reg = xzalloc_array(__be32, (nr_ext_regions + 1) * (addrcells + sizecells));
    if ( !reg )
    {
        xfree(ext_regions);
        return -ENOMEM;
    }

    /* reg 0 is grant table space */
    cells = &reg[0];
    dt_child_set_range(&cells, addrcells, sizecells,
                       kinfo->gnttab_start, kinfo->gnttab_size);
    /* reg 1...N are extended regions */
    for ( i = 0; i < nr_ext_regions; i++ )
    {
        u64 start = ext_regions->bank[i].start;
        u64 size = ext_regions->bank[i].size;

        printk("%pd: extended region %d: %#"PRIx64"->%#"PRIx64"\n",
               d, i, start, start + size);

        dt_child_set_range(&cells, addrcells, sizecells, start, size);
    }

    res = fdt_property(fdt, "reg", reg,
                       dt_cells_to_size(addrcells + sizecells) *
                       (nr_ext_regions + 1));
    xfree(ext_regions);
    xfree(reg);

    if ( res )
        return res;

    BUG_ON(d->arch.evtchn_irq == 0);

    /*
     * Interrupt event channel upcall:
     *  - Active-low level-sensitive
     *  - All CPUs
     *  TODO: Handle properly the cpumask;
     */
    set_interrupt(intr, d->arch.evtchn_irq, 0xf, DT_IRQ_TYPE_LEVEL_LOW);
    res = fdt_property_interrupts(kinfo, &intr, 1);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int __init make_psci_node(void *fdt)
{
    int res;
    const char compat[] =
        "arm,psci-1.0""\0"
        "arm,psci-0.2""\0"
        "arm,psci";

    dt_dprintk("Create PSCI node\n");

    /* See linux Documentation/devicetree/bindings/arm/psci.txt */
    res = fdt_begin_node(fdt, "psci");
    if ( res )
        return res;

    res = fdt_property(fdt, "compatible", compat, sizeof(compat));
    if ( res )
        return res;

    res = fdt_property_string(fdt, "method", "hvc");
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "cpu_off", PSCI_cpu_off);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "cpu_on", PSCI_cpu_on);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int __init make_cpus_node(const struct domain *d, void *fdt)
{
    int res;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *npcpu;
    unsigned int cpu;
    const void *compatible = NULL;
    u32 len;
    /* Placeholder for cpu@ + a 32-bit hexadecimal number + \0 */
    char buf[13];
    u32 clock_frequency;
    /* Keep the compiler happy with -Og */
    bool clock_valid = false;
    uint64_t mpidr_aff;

    dt_dprintk("Create cpus node\n");

    if ( !cpus )
    {
        dprintk(XENLOG_ERR, "Missing /cpus node in the device tree?\n");
        return -ENOENT;
    }

    /*
     * Get the compatible property of CPUs from the device tree.
     * We are assuming that all CPUs are the same so we are just look
     * for the first one.
     * TODO: Handle compatible per VCPU
     */
    dt_for_each_child_node(cpus, npcpu)
    {
        if ( dt_device_type_is_equal(npcpu, "cpu") )
        {
            compatible = dt_get_property(npcpu, "compatible", &len);
            clock_valid = dt_property_read_u32(npcpu, "clock-frequency",
                                            &clock_frequency);
            break;
        }
    }

    if ( !compatible )
    {
        dprintk(XENLOG_ERR, "Can't find cpu in the device tree?\n");
        return -ENOENT;
    }

    /* See Linux Documentation/devicetree/booting-without-of.txt
     * section III.5.b
     */
    res = fdt_begin_node(fdt, "cpus");
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 1);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", 0);
    if ( res )
        return res;

    for ( cpu = 0; cpu < d->max_vcpus; cpu++ )
    {
        /*
         * According to ARM CPUs bindings, the reg field should match
         * the MPIDR's affinity bits. We will use AFF0 and AFF1 when
         * constructing the reg value of the guest at the moment, for it
         * is enough for the current max vcpu number.
         *
         * We only deal with AFF{0, 1, 2} stored in bits [23:0] at the
         * moment.
         */
        mpidr_aff = vcpuid_to_vaffinity(cpu);
        if ( (mpidr_aff & ~GENMASK_ULL(23, 0)) != 0 )
        {
            printk(XENLOG_ERR "Unable to handle MPIDR AFFINITY 0x%"PRIx64"\n",
                   mpidr_aff);
            return -EINVAL;
        }

        dt_dprintk("Create cpu@%"PRIx64" (logical CPUID: %d) node\n",
                   mpidr_aff, cpu);

        /*
         * We use PRIx64 because mpidr_aff is a 64bit integer. However,
         * only bits [23:0] are used, thus, we are sure it will fit in
         * buf.
         */
        snprintf(buf, sizeof(buf), "cpu@%"PRIx64, mpidr_aff);
        res = fdt_begin_node(fdt, buf);
        if ( res )
            return res;

        res = fdt_property(fdt, "compatible", compatible, len);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "device_type", "cpu");
        if ( res )
            return res;

        res = fdt_property_cell(fdt, "reg", mpidr_aff);
        if ( res )
            return res;

        if ( clock_valid )
        {
            res = fdt_property_cell(fdt, "clock-frequency", clock_frequency);
            if ( res )
                return res;
        }

        if ( is_64bit_domain(d) )
        {
            res = fdt_property_string(fdt, "enable-method", "psci");
            if ( res )
                return res;
        }

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    res = fdt_end_node(fdt);

    return res;
}

static int __init make_gic_node(const struct domain *d, void *fdt,
                                const struct dt_device_node *node)
{
    const struct dt_device_node *gic = dt_interrupt_controller;
    int res = 0;
    const void *addrcells, *sizecells;
    u32 addrcells_len, sizecells_len;

    /*
     * Xen currently supports only a single GIC. Discard any secondary
     * GIC entries.
     */
    if ( node != dt_interrupt_controller )
    {
        dt_dprintk("  Skipping (secondary GIC)\n");
        return 0;
    }

    dt_dprintk("Create gic node\n");

    res = fdt_begin_node(fdt, "interrupt-controller");
    if ( res )
        return res;

    /*
     * The value of the property "phandle" in the property "interrupts"
     * to know on which interrupt controller the interrupt is wired.
     */
    if ( gic->phandle )
    {
        dt_dprintk("  Set phandle = 0x%x\n", gic->phandle);
        res = fdt_property_cell(fdt, "phandle", gic->phandle);
        if ( res )
            return res;
    }

    addrcells = dt_get_property(gic, "#address-cells", &addrcells_len);
    if ( addrcells )
    {
        res = fdt_property(fdt, "#address-cells", addrcells, addrcells_len);
        if ( res )
            return res;
    }

    sizecells = dt_get_property(gic, "#size-cells", &sizecells_len);
    if ( sizecells )
    {
        res = fdt_property(fdt, "#size-cells", sizecells, sizecells_len);
        if ( res )
            return res;
    }

    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    res = gic_make_hwdom_dt_node(d, node, fdt);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int __init make_timer_node(const struct kernel_info *kinfo)
{
    void *fdt = kinfo->fdt;
    static const struct dt_device_match timer_ids[] __initconst =
    {
        DT_MATCH_TIMER,
        { /* sentinel */ },
    };
    struct dt_device_node *dev;
    int res;
    unsigned int irq[MAX_TIMER_PPI];
    gic_interrupt_t intrs[3];
    u32 clock_frequency;
    bool clock_valid;

    dt_dprintk("Create timer node\n");

    dev = dt_find_matching_node(NULL, timer_ids);
    if ( !dev )
    {
        dprintk(XENLOG_ERR, "Missing timer node in the device tree?\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_begin_node(fdt, "timer");
    if ( res )
        return res;

    if ( !is_64bit_domain(kinfo->d) )
        res = fdt_property_string(fdt, "compatible", "arm,armv7-timer");
    else
        res = fdt_property_string(fdt, "compatible", "arm,armv8-timer");
    if ( res )
        return res;

    /*
     * The timer IRQ is emulated by Xen.
     * It always exposes an active-low level-sensitive interrupt.
     */

    if ( is_hardware_domain(kinfo->d) )
    {
        irq[TIMER_PHYS_SECURE_PPI] = timer_get_irq(TIMER_PHYS_SECURE_PPI);
        irq[TIMER_PHYS_NONSECURE_PPI] =
                                    timer_get_irq(TIMER_PHYS_NONSECURE_PPI);
        irq[TIMER_VIRT_PPI] = timer_get_irq(TIMER_VIRT_PPI);
    }
    else
    {
        irq[TIMER_PHYS_SECURE_PPI] = GUEST_TIMER_PHYS_S_PPI;
        irq[TIMER_PHYS_NONSECURE_PPI] = GUEST_TIMER_PHYS_NS_PPI;
        irq[TIMER_VIRT_PPI] = GUEST_TIMER_VIRT_PPI;
    }
    dt_dprintk("  Secure interrupt %u\n", irq[TIMER_PHYS_SECURE_PPI]);
    set_interrupt(intrs[0], irq[TIMER_PHYS_SECURE_PPI],
                  0xf, DT_IRQ_TYPE_LEVEL_LOW);
    dt_dprintk("  Non secure interrupt %u\n", irq[TIMER_PHYS_NONSECURE_PPI]);
    set_interrupt(intrs[1], irq[TIMER_PHYS_NONSECURE_PPI],
                  0xf, DT_IRQ_TYPE_LEVEL_LOW);
    dt_dprintk("  Virt interrupt %u\n", irq[TIMER_VIRT_PPI]);
    set_interrupt(intrs[2], irq[TIMER_VIRT_PPI], 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    res = fdt_property_interrupts(kinfo, intrs, 3);
    if ( res )
        return res;

    clock_valid = dt_property_read_u32(dev, "clock-frequency",
                                       &clock_frequency);
    if ( clock_valid )
    {
        res = fdt_property_cell(fdt, "clock-frequency", clock_frequency);
        if ( res )
            return res;
    }

    res = fdt_end_node(fdt);

    return res;
}

/*
 * This function is used as part of the device tree generation for Dom0
 * on ACPI systems, and DomUs started directly from Xen based on device
 * tree information.
 */
int __init make_chosen_node(const struct kernel_info *kinfo)
{
    int res;
    const char *bootargs = NULL;
    const struct bootmodule *mod = kinfo->kernel_bootmodule;
    void *fdt = kinfo->fdt;

    dt_dprintk("Create chosen node\n");
    res = fdt_begin_node(fdt, "chosen");
    if ( res )
        return res;

    if ( kinfo->cmdline && kinfo->cmdline[0] )
    {
        bootargs = &kinfo->cmdline[0];
        res = fdt_property(fdt, "bootargs", bootargs, strlen(bootargs) + 1);
        if ( res )
           return res;
    }

    /*
     * If the bootloader provides an initrd, we must create a placeholder
     * for the initrd properties. The values will be replaced later.
     */
    if ( mod && mod->size )
    {
        u64 a = 0;
        res = fdt_property(kinfo->fdt, "linux,initrd-start", &a, sizeof(a));
        if ( res )
            return res;

        res = fdt_property(kinfo->fdt, "linux,initrd-end", &a, sizeof(a));
        if ( res )
            return res;
    }

    res = fdt_end_node(fdt);

    return res;
}

int __init map_irq_to_domain(struct domain *d, unsigned int irq,
                             bool need_mapping, const char *devname)
{
    int res;

    res = irq_permit_access(d, irq);
    if ( res )
    {
        printk(XENLOG_ERR "Unable to permit to dom%u access to IRQ %u\n",
               d->domain_id, irq);
        return res;
    }

    if ( need_mapping )
    {
        /*
         * Checking the return of vgic_reserve_virq is not
         * necessary. It should not fail except when we try to map
         * the IRQ twice. This can legitimately happen if the IRQ is shared
         */
        vgic_reserve_virq(d, irq);

        res = route_irq_to_guest(d, irq, irq, devname);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map IRQ%"PRId32" to dom%d\n",
                   irq, d->domain_id);
            return res;
        }
    }

    dt_dprintk("  - IRQ: %u\n", irq);
    return 0;
}

static int __init map_dt_irq_to_domain(const struct dt_device_node *dev,
                                       const struct dt_irq *dt_irq,
                                       void *data)
{
    struct map_range_data *mr_data = data;
    struct domain *d = mr_data->d;
    unsigned int irq = dt_irq->irq;
    int res;

    if ( irq < NR_LOCAL_IRQS )
    {
        printk(XENLOG_ERR "%s: IRQ%"PRId32" is not a SPI\n",
               dt_node_name(dev), irq);
        return -EINVAL;
    }

    /* Setup the IRQ type */
    res = irq_set_spi_type(irq, dt_irq->type);
    if ( res )
    {
        printk(XENLOG_ERR
               "%s: Unable to setup IRQ%"PRId32" to dom%d\n",
               dt_node_name(dev), irq, d->domain_id);
        return res;
    }

    res = map_irq_to_domain(d, irq, !mr_data->skip_mapping, dt_node_name(dev));

    return res;
}

int __init map_range_to_domain(const struct dt_device_node *dev,
                               u64 addr, u64 len, void *data)
{
    struct map_range_data *mr_data = data;
    struct domain *d = mr_data->d;
    int res;

    /*
     * reserved-memory regions are RAM carved out for a special purpose.
     * They are not MMIO and therefore a domain should not be able to
     * manage them via the IOMEM interface.
     */
    if ( strncasecmp(dt_node_full_name(dev), "/reserved-memory/",
                     strlen("/reserved-memory/")) != 0 )
    {
        res = iomem_permit_access(d, paddr_to_pfn(addr),
                paddr_to_pfn(PAGE_ALIGN(addr + len - 1)));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                    " 0x%"PRIx64" - 0x%"PRIx64"\n",
                    d->domain_id,
                    addr & PAGE_MASK, PAGE_ALIGN(addr + len) - 1);
            return res;
        }
    }

    if ( !mr_data->skip_mapping )
    {
        res = map_regions_p2mt(d,
                               gaddr_to_gfn(addr),
                               PFN_UP(len),
                               maddr_to_mfn(addr),
                               mr_data->p2mt);

        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map 0x%"PRIx64
                   " - 0x%"PRIx64" in domain %d\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + len) - 1,
                   d->domain_id);
            return res;
        }
    }

    dt_dprintk("  - MMIO: %010"PRIx64" - %010"PRIx64" P2MType=%x\n",
               addr, addr + len, mr_data->p2mt);

    return 0;
}

/*
 * For a node which describes a discoverable bus (such as a PCI bus)
 * then we may need to perform additional mappings in order to make
 * the child resources available to domain 0.
 */
static int __init map_device_children(const struct dt_device_node *dev,
                                      struct map_range_data *mr_data)
{
    if ( dt_device_type_is_equal(dev, "pci") )
    {
        int ret;

        dt_dprintk("Mapping children of %s to guest\n",
                   dt_node_full_name(dev));

        ret = dt_for_each_irq_map(dev, &map_dt_irq_to_domain, mr_data);
        if ( ret < 0 )
            return ret;

        ret = dt_for_each_range(dev, &map_range_to_domain, mr_data);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * handle_device_interrupts retrieves the interrupts configuration from
 * a device tree node and maps those interrupts to the target domain.
 *
 * Returns:
 *   < 0 error
 *   0   success
 */
static int __init handle_device_interrupts(struct domain *d,
                                           struct dt_device_node *dev,
                                           bool need_mapping)
{
    unsigned int i, nirq;
    int res;
    struct dt_raw_irq rirq;

    nirq = dt_number_of_irq(dev);

    /* Give permission and map IRQs */
    for ( i = 0; i < nirq; i++ )
    {
        res = dt_device_get_raw_irq(dev, i, &rirq);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        /*
         * Don't map IRQ that have no physical meaning
         * ie: IRQ whose controller is not the GIC
         */
        if ( rirq.controller != dt_interrupt_controller )
        {
            dt_dprintk("irq %u not connected to primary controller. Connected to %s\n",
                      i, dt_node_full_name(rirq.controller));
            continue;
        }

        res = platform_get_irq(dev, i);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to get irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        res = map_irq_to_domain(d, res, need_mapping, dt_node_name(dev));
        if ( res )
            return res;
    }

    return 0;
}

/*
 * For a given device node:
 *  - Give permission to the guest to manage IRQ and MMIO range
 *  - Retrieve the IRQ configuration (i.e edge/level) from device tree
 * When the device is not marked for guest passthrough:
 *  - Try to call iommu_add_dt_device to protect the device by an IOMMU
 *  - Assign the device to the guest if it's protected by an IOMMU
 *  - Map the IRQs and iomem regions to DOM0
 */
static int __init handle_device(struct domain *d, struct dt_device_node *dev,
                                p2m_type_t p2mt)
{
    unsigned int naddr;
    unsigned int i;
    int res;
    u64 addr, size;
    bool own_device = !dt_device_for_passthrough(dev);
    /*
     * We want to avoid mapping the MMIO in dom0 for the following cases:
     *   - The device is owned by dom0 (i.e. it has been flagged for
     *     passthrough).
     *   - PCI host bridges with driver in Xen. They will later be mapped by
     *     pci_host_bridge_mappings().
     */
    struct map_range_data mr_data = {
        .d = d,
        .p2mt = p2mt,
        .skip_mapping = !own_device ||
                        (is_pci_passthrough_enabled() &&
                        (device_get_class(dev) == DEVICE_PCI_HOSTBRIDGE))
    };

    naddr = dt_number_of_address(dev);

    dt_dprintk("%s passthrough = %d naddr = %u\n",
               dt_node_full_name(dev), own_device, naddr);

    if ( own_device )
    {
        dt_dprintk("Check if %s is behind the IOMMU and add it\n",
                   dt_node_full_name(dev));

        res = iommu_add_dt_device(dev);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Failed to add %s to the IOMMU\n",
                   dt_node_full_name(dev));
            return res;
        }

        if ( dt_device_is_protected(dev) )
        {
            dt_dprintk("%s setup iommu\n", dt_node_full_name(dev));
            res = iommu_assign_dt_device(d, dev);
            if ( res )
            {
                printk(XENLOG_ERR "Failed to setup the IOMMU for %s\n",
                       dt_node_full_name(dev));
                return res;
            }
        }
    }

    res = handle_device_interrupts(d, dev, own_device);
    if ( res < 0 )
        return res;

    /* Give permission and map MMIOs */
    for ( i = 0; i < naddr; i++ )
    {
        res = dt_device_get_address(dev, i, &addr, &size);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve address %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        res = map_range_to_domain(dev, addr, size, &mr_data);
        if ( res )
            return res;
    }

    res = map_device_children(dev, &mr_data);
    if ( res )
        return res;

    return 0;
}

static int __init handle_node(struct domain *d, struct kernel_info *kinfo,
                              struct dt_device_node *node,
                              p2m_type_t p2mt)
{
    static const struct dt_device_match skip_matches[] __initconst =
    {
        DT_MATCH_COMPATIBLE("xen,xen"),
        DT_MATCH_COMPATIBLE("xen,multiboot-module"),
        DT_MATCH_COMPATIBLE("multiboot,module"),
        DT_MATCH_COMPATIBLE("arm,psci"),
        DT_MATCH_COMPATIBLE("arm,psci-0.2"),
        DT_MATCH_COMPATIBLE("arm,psci-1.0"),
        DT_MATCH_COMPATIBLE("arm,cortex-a7-pmu"),
        DT_MATCH_COMPATIBLE("arm,cortex-a15-pmu"),
        DT_MATCH_COMPATIBLE("arm,cortex-a53-edac"),
        DT_MATCH_COMPATIBLE("arm,armv8-pmuv3"),
        DT_MATCH_PATH("/cpus"),
        DT_MATCH_TYPE("memory"),
        /* The memory mapped timer is not supported by Xen. */
        DT_MATCH_COMPATIBLE("arm,armv7-timer-mem"),
        { /* sentinel */ },
    };
    static const struct dt_device_match timer_matches[] __initconst =
    {
        DT_MATCH_TIMER,
        { /* sentinel */ },
    };
    static const struct dt_device_match reserved_matches[] __initconst =
    {
        DT_MATCH_PATH("/psci"),
        DT_MATCH_PATH("/memory"),
        DT_MATCH_PATH("/hypervisor"),
        { /* sentinel */ },
    };
    struct dt_device_node *child;
    int res, i, nirq, irq_id;
    const char *name;
    const char *path;

    path = dt_node_full_name(node);

    dt_dprintk("handle %s\n", path);

    /* Skip theses nodes and the sub-nodes */
    if ( dt_match_node(skip_matches, node) )
    {
        dt_dprintk("  Skip it (matched)\n");
        return 0;
    }
    if ( platform_device_is_blacklisted(node) )
    {
        dt_dprintk("  Skip it (blacklisted)\n");
        return 0;
    }

    /*
     * Replace these nodes with our own. Note that the original may be
     * used_by DOMID_XEN so this check comes first.
     */
    if ( device_get_class(node) == DEVICE_GIC )
        return make_gic_node(d, kinfo->fdt, node);
    if ( dt_match_node(timer_matches, node) )
        return make_timer_node(kinfo);

    /* Skip nodes used by Xen */
    if ( dt_device_used_by(node) == DOMID_XEN )
    {
        dt_dprintk("  Skip it (used by Xen)\n");
        return 0;
    }

    /*
     * Even if the IOMMU device is not used by Xen, it should not be
     * passthrough to DOM0
     */
    if ( device_get_class(node) == DEVICE_IOMMU )
    {
        dt_dprintk(" IOMMU, skip it\n");
        return 0;
    }

    /*
     * The vGIC does not support routing hardware PPIs to guest. So
     * we need to skip any node using PPIs.
     */
    nirq = dt_number_of_irq(node);

    for ( i = 0 ; i < nirq ; i++ )
    {
        irq_id = platform_get_irq(node, i);

        /* PPIs ranges from ID 16 to 31 */
        if ( irq_id >= 16 && irq_id < 32 )
        {
            dt_dprintk(" Skip it (using PPIs)\n");
            return 0;
        }
    }

    /*
     * Xen is using some path for its own purpose. Warn if a node
     * already exists with the same path.
     */
    if ( dt_match_node(reserved_matches, node) )
        printk(XENLOG_WARNING
               "WARNING: Path %s is reserved, skip the node as we may re-use the path.\n",
               path);

    res = handle_device(d, node, p2mt);
    if ( res)
        return res;

    /*
     * The property "name" is used to have a different name on older FDT
     * version. We want to keep the name retrieved during the tree
     * structure creation, that is store in the node path.
     */
    name = strrchr(path, '/');
    name = name ? name + 1 : path;

    res = fdt_begin_node(kinfo->fdt, name);
    if ( res )
        return res;

    res = write_properties(d, kinfo, node);
    if ( res )
        return res;

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        res = handle_node(d, kinfo, child, p2mt);
        if ( res )
            return res;
    }

    if ( node == dt_host )
    {
        int addrcells = dt_child_n_addr_cells(node);
        int sizecells = dt_child_n_size_cells(node);

        /*
         * It is safe to allocate the event channel here because all the
         * PPIs used by the hardware domain have been registered.
         */
        evtchn_allocate(d);

        /*
         * The hypervisor node should always be created after all nodes
         * from the host DT have been parsed.
         */
        res = make_hypervisor_node(d, kinfo, addrcells, sizecells);
        if ( res )
            return res;

        res = make_psci_node(kinfo->fdt);
        if ( res )
            return res;

        res = make_cpus_node(d, kinfo->fdt);
        if ( res )
            return res;

        res = make_memory_node(d, kinfo->fdt, addrcells, sizecells, &kinfo->mem);
        if ( res )
            return res;

        /*
         * Create a second memory node to store the ranges covering
         * reserved-memory regions.
         */
        if ( bootinfo.reserved_mem.nr_banks > 0 )
        {
            res = make_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                   &bootinfo.reserved_mem);
            if ( res )
                return res;
        }

        res = make_resv_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                    &kinfo->shm_mem);
        if ( res )
            return res;
    }

    res = fdt_end_node(kinfo->fdt);

    return res;
}

static int __init make_gicv2_domU_node(struct kernel_info *kinfo)
{
    void *fdt = kinfo->fdt;
    int res = 0;
    __be32 reg[(GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) * 2];
    __be32 *cells;
    const struct domain *d = kinfo->d;

    res = domain_fdt_begin_node(fdt, "interrupt-controller",
                                vgic_dist_base(&d->arch.vgic));
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", "arm,gic-400");
    if ( res )
        return res;

    cells = &reg[0];
    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                       vgic_dist_base(&d->arch.vgic), GUEST_GICD_SIZE);
    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                       vgic_cpu_base(&d->arch.vgic), GUEST_GICC_SIZE);

    res = fdt_property(fdt, "reg", reg, sizeof(reg));
    if (res)
        return res;

    res = fdt_property_cell(fdt, "linux,phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_end_node(fdt);

    return res;
}

#ifdef CONFIG_GICV3
static int __init make_gicv3_domU_node(struct kernel_info *kinfo)
{
    void *fdt = kinfo->fdt;
    int res = 0;
    __be32 *reg, *cells;
    const struct domain *d = kinfo->d;
    unsigned int i, len = 0;

    res = domain_fdt_begin_node(fdt, "interrupt-controller",
                                vgic_dist_base(&d->arch.vgic));
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", "arm,gic-v3");
    if ( res )
        return res;

    /* reg specifies all re-distributors and Distributor. */
    len = (GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
          (d->arch.vgic.nr_regions + 1) * sizeof(__be32);
    reg = xmalloc_bytes(len);
    if ( reg == NULL )
        return -ENOMEM;
    cells = reg;

    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                       vgic_dist_base(&d->arch.vgic), GUEST_GICV3_GICD_SIZE);

    for ( i = 0; i < d->arch.vgic.nr_regions; i++ )
        dt_child_set_range(&cells,
                           GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                           d->arch.vgic.rdist_regions[i].base,
                           d->arch.vgic.rdist_regions[i].size);

    res = fdt_property(fdt, "reg", reg, len);
    xfree(reg);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "linux,phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_end_node(fdt);

    return res;
}
#endif

static int __init make_gic_domU_node(struct kernel_info *kinfo)
{
    switch ( kinfo->d->arch.vgic.version )
    {
#ifdef CONFIG_GICV3
    case GIC_V3:
        return make_gicv3_domU_node(kinfo);
#endif
    case GIC_V2:
        return make_gicv2_domU_node(kinfo);
    default:
        panic("Unsupported GIC version\n");
    }
}

#ifdef CONFIG_SBSA_VUART_CONSOLE
static int __init make_vpl011_uart_node(struct kernel_info *kinfo)
{
    void *fdt = kinfo->fdt;
    int res;
    gic_interrupt_t intr;
    __be32 reg[GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS];
    __be32 *cells;
    struct domain *d = kinfo->d;

    res = domain_fdt_begin_node(fdt, "sbsa-uart", d->arch.vpl011.base_addr);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", "arm,sbsa-uart");
    if ( res )
        return res;

    cells = &reg[0];
    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS,
                       GUEST_ROOT_SIZE_CELLS, d->arch.vpl011.base_addr,
                       GUEST_PL011_SIZE);

    res = fdt_property(fdt, "reg", reg, sizeof(reg));
    if ( res )
        return res;

    set_interrupt(intr, d->arch.vpl011.virq, 0xf, DT_IRQ_TYPE_LEVEL_HIGH);

    res = fdt_property(fdt, "interrupts", intr, sizeof (intr));
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "interrupt-parent",
                            kinfo->phandle_gic);
    if ( res )
        return res;

    /* Use a default baud rate of 115200. */
    fdt_property_u32(fdt, "current-speed", 115200);

    res = fdt_end_node(fdt);
    if ( res )
        return res;

    return 0;
}
#endif

/*
 * Scan device tree properties for passthrough specific information.
 * Returns < 0 on error
 *         0 on success
 */
static int __init handle_passthrough_prop(struct kernel_info *kinfo,
                                          const struct fdt_property *xen_reg,
                                          const struct fdt_property *xen_path,
                                          bool xen_force,
                                          uint32_t address_cells, uint32_t size_cells)
{
    const __be32 *cell;
    unsigned int i, len;
    struct dt_device_node *node;
    int res;
    paddr_t mstart, size, gstart;

    /* xen,reg specifies where to map the MMIO region */
    cell = (const __be32 *)xen_reg->data;
    len = fdt32_to_cpu(xen_reg->len) / ((address_cells * 2 + size_cells) *
                                        sizeof(uint32_t));

    for ( i = 0; i < len; i++ )
    {
        device_tree_get_reg(&cell, address_cells, size_cells,
                            &mstart, &size);
        gstart = dt_next_cell(address_cells, &cell);

        if ( gstart & ~PAGE_MASK || mstart & ~PAGE_MASK || size & ~PAGE_MASK )
        {
            printk(XENLOG_ERR
                    "DomU passthrough config has not page aligned addresses/sizes\n");
            return -EINVAL;
        }

        res = iomem_permit_access(kinfo->d, paddr_to_pfn(mstart),
                                  paddr_to_pfn(PAGE_ALIGN(mstart + size - 1)));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                   " 0x%"PRIx64" - 0x%"PRIx64"\n",
                   kinfo->d->domain_id,
                   mstart & PAGE_MASK, PAGE_ALIGN(mstart + size) - 1);
            return res;
        }

        res = map_regions_p2mt(kinfo->d,
                               gaddr_to_gfn(gstart),
                               PFN_DOWN(size),
                               maddr_to_mfn(mstart),
                               p2m_mmio_direct_dev);
        if ( res < 0 )
        {
            printk(XENLOG_ERR
                   "Failed to map %"PRIpaddr" to the guest at%"PRIpaddr"\n",
                   mstart, gstart);
            return -EFAULT;
        }
    }

    /*
     * If xen_force, we let the user assign a MMIO region with no
     * associated path.
     */
    if ( xen_path == NULL )
        return xen_force ? 0 : -EINVAL;

    /*
     * xen,path specifies the corresponding node in the host DT.
     * Both interrupt mappings and IOMMU settings are based on it,
     * as they are done based on the corresponding host DT node.
     */
    node = dt_find_node_by_path(xen_path->data);
    if ( node == NULL )
    {
        printk(XENLOG_ERR "Couldn't find node %s in host_dt!\n",
               (char *)xen_path->data);
        return -EINVAL;
    }

    res = handle_device_interrupts(kinfo->d, node, true);
    if ( res < 0 )
        return res;

    res = iommu_add_dt_device(node);
    if ( res < 0 )
        return res;

    /* If xen_force, we allow assignment of devices without IOMMU protection. */
    if ( xen_force && !dt_device_is_protected(node) )
        return 0;

    return iommu_assign_dt_device(kinfo->d, node);
}

static int __init handle_prop_pfdt(struct kernel_info *kinfo,
                                   const void *pfdt, int nodeoff,
                                   uint32_t address_cells, uint32_t size_cells,
                                   bool scan_passthrough_prop)
{
    void *fdt = kinfo->fdt;
    int propoff, nameoff, res;
    const struct fdt_property *prop, *xen_reg = NULL, *xen_path = NULL;
    const char *name;
    bool found, xen_force = false;

    for ( propoff = fdt_first_property_offset(pfdt, nodeoff);
          propoff >= 0;
          propoff = fdt_next_property_offset(pfdt, propoff) )
    {
        if ( !(prop = fdt_get_property_by_offset(pfdt, propoff, NULL)) )
            return -FDT_ERR_INTERNAL;

        found = false;
        nameoff = fdt32_to_cpu(prop->nameoff);
        name = fdt_string(pfdt, nameoff);

        if ( scan_passthrough_prop )
        {
            if ( dt_prop_cmp("xen,reg", name) == 0 )
            {
                xen_reg = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,path", name) == 0 )
            {
                xen_path = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,force-assign-without-iommu",
                                  name) == 0 )
            {
                xen_force = true;
                found = true;
            }
        }

        /*
         * Copy properties other than the ones above: xen,reg, xen,path,
         * and xen,force-assign-without-iommu.
         */
        if ( !found )
        {
            res = fdt_property(fdt, name, prop->data, fdt32_to_cpu(prop->len));
            if ( res )
                return res;
        }
    }

    /*
     * Only handle passthrough properties if both xen,reg and xen,path
     * are present, or if xen,force-assign-without-iommu is specified.
     */
    if ( xen_reg != NULL && (xen_path != NULL || xen_force) )
    {
        res = handle_passthrough_prop(kinfo, xen_reg, xen_path, xen_force,
                                      address_cells, size_cells);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Failed to assign device to %pd\n", kinfo->d);
            return res;
        }
    }
    else if ( (xen_path && !xen_reg) || (xen_reg && !xen_path && !xen_force) )
    {
        printk(XENLOG_ERR "xen,reg or xen,path missing for %pd\n",
               kinfo->d);
        return -EINVAL;
    }

    /* FDT_ERR_NOTFOUND => There is no more properties for this node */
    return ( propoff != -FDT_ERR_NOTFOUND ) ? propoff : 0;
}

static int __init scan_pfdt_node(struct kernel_info *kinfo, const void *pfdt,
                                 int nodeoff,
                                 uint32_t address_cells, uint32_t size_cells,
                                 bool scan_passthrough_prop)
{
    int rc = 0;
    void *fdt = kinfo->fdt;
    int node_next;

    rc = fdt_begin_node(fdt, fdt_get_name(pfdt, nodeoff, NULL));
    if ( rc )
        return rc;

    rc = handle_prop_pfdt(kinfo, pfdt, nodeoff, address_cells, size_cells,
                          scan_passthrough_prop);
    if ( rc )
        return rc;

    address_cells = device_tree_get_u32(pfdt, nodeoff, "#address-cells",
                                        DT_ROOT_NODE_ADDR_CELLS_DEFAULT);
    size_cells = device_tree_get_u32(pfdt, nodeoff, "#size-cells",
                                     DT_ROOT_NODE_SIZE_CELLS_DEFAULT);

    node_next = fdt_first_subnode(pfdt, nodeoff);
    while ( node_next > 0 )
    {
        scan_pfdt_node(kinfo, pfdt, node_next, address_cells, size_cells,
                       scan_passthrough_prop);
        node_next = fdt_next_subnode(pfdt, node_next);
    }

    return fdt_end_node(fdt);
}

static int __init check_partial_fdt(void *pfdt, size_t size)
{
    int res;

    if ( fdt_magic(pfdt) != FDT_MAGIC )
    {
        dprintk(XENLOG_ERR, "Partial FDT is not a valid Flat Device Tree");
        return -EINVAL;
    }

    res = fdt_check_header(pfdt);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed to check the partial FDT (%d)", res);
        return -EINVAL;
    }

    if ( fdt_totalsize(pfdt) > size )
    {
        dprintk(XENLOG_ERR, "Partial FDT totalsize is too big");
        return -EINVAL;
    }

    return 0;
}

static int __init domain_handle_dtb_bootmodule(struct domain *d,
                                               struct kernel_info *kinfo)
{
    void *pfdt;
    int res, node_next;

    pfdt = ioremap_cache(kinfo->dtb_bootmodule->start,
                         kinfo->dtb_bootmodule->size);
    if ( pfdt == NULL )
        return -EFAULT;

    res = check_partial_fdt(pfdt, kinfo->dtb_bootmodule->size);
    if ( res < 0 )
        return res;

    for ( node_next = fdt_first_subnode(pfdt, 0); 
          node_next > 0;
          node_next = fdt_next_subnode(pfdt, node_next) )
    {
        const char *name = fdt_get_name(pfdt, node_next, NULL);

        if ( name == NULL )
            continue;

        /*
         * Only scan /gic /aliases /passthrough, ignore the rest.
         * They don't have to be parsed in order.
         *
         * Take the GIC phandle value from the special /gic node in the
         * DTB fragment.
         */
        if ( dt_node_cmp(name, "gic") == 0 )
        {
            kinfo->phandle_gic = fdt_get_phandle(pfdt, node_next);
            continue;
        }

        if ( dt_node_cmp(name, "aliases") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 false);
            if ( res )
                return res;
            continue;
        }
        if ( dt_node_cmp(name, "passthrough") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 true);
            if ( res )
                return res;
            continue;
        }
    }

    iounmap(pfdt);

    return res;
}

/*
 * The max size for DT is 2MB. However, the generated DT is small, 4KB
 * are enough for now, but we might have to increase it in the future.
 */
#define DOMU_DTB_SIZE 4096
static int __init prepare_dtb_domU(struct domain *d, struct kernel_info *kinfo)
{
    int addrcells, sizecells;
    int ret;

    kinfo->phandle_gic = GUEST_PHANDLE_GIC;
    kinfo->gnttab_start = GUEST_GNTTAB_BASE;
    kinfo->gnttab_size = GUEST_GNTTAB_SIZE;

    addrcells = GUEST_ROOT_ADDRESS_CELLS;
    sizecells = GUEST_ROOT_SIZE_CELLS;

    kinfo->fdt = xmalloc_bytes(DOMU_DTB_SIZE);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, DOMU_DTB_SIZE);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish_reservemap(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_begin_node(kinfo->fdt, "");
    if ( ret < 0 )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#address-cells", addrcells);
    if ( ret )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#size-cells", sizecells);
    if ( ret )
        goto err;

    ret = make_chosen_node(kinfo);
    if ( ret )
        goto err;

    ret = make_psci_node(kinfo->fdt);
    if ( ret )
        goto err;

    ret = make_cpus_node(d, kinfo->fdt);
    if ( ret )
        goto err;

    ret = make_memory_node(d, kinfo->fdt, addrcells, sizecells, &kinfo->mem);
    if ( ret )
        goto err;

    ret = make_resv_memory_node(d, kinfo->fdt, addrcells, sizecells,
                                &kinfo->shm_mem);
    if ( ret )
        goto err;

    /*
     * domain_handle_dtb_bootmodule has to be called before the rest of
     * the device tree is generated because it depends on the value of
     * the field phandle_gic.
     */
    if ( kinfo->dtb_bootmodule )
    {
        ret = domain_handle_dtb_bootmodule(d, kinfo);
        if ( ret )
            return ret;
    }

    ret = make_gic_domU_node(kinfo);
    if ( ret )
        goto err;

    ret = make_timer_node(kinfo);
    if ( ret )
        goto err;

    if ( kinfo->vpl011 )
    {
        ret = -EINVAL;
#ifdef CONFIG_SBSA_VUART_CONSOLE
        ret = make_vpl011_uart_node(kinfo);
#endif
        if ( ret )
            goto err;
    }

    if ( kinfo->dom0less_feature & DOM0LESS_ENHANCED_NO_XS )
    {
        ret = make_hypervisor_node(d, kinfo, addrcells, sizecells);
        if ( ret )
            goto err;
    }

    ret = fdt_end_node(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);

    return -EINVAL;
}

static int __init prepare_dtb_hwdom(struct domain *d, struct kernel_info *kinfo)
{
    const p2m_type_t default_p2mt = p2m_mmio_direct_c;
    const void *fdt;
    int new_size;
    int ret;

    ASSERT(dt_host && (dt_host->sibling == NULL));

    kinfo->phandle_gic = dt_interrupt_controller->phandle;
    fdt = device_tree_flattened;

    new_size = fdt_totalsize(fdt) + DOM0_FDT_EXTRA_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    fdt_finish_reservemap(kinfo->fdt);

    ret = handle_node(d, kinfo, dt_host, default_p2mt);
    if ( ret )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);
    return -EINVAL;
}

static void __init dtb_load(struct kernel_info *kinfo)
{
    unsigned long left;

    printk("Loading %pd DTB to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->d, kinfo->dtb_paddr,
           kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt));

    left = copy_to_guest_phys_flush_dcache(kinfo->d, kinfo->dtb_paddr,
                                           kinfo->fdt,
                                           fdt_totalsize(kinfo->fdt));

    if ( left != 0 )
        panic("Unable to copy the DTB to %pd memory (left = %lu bytes)\n",
              kinfo->d, left);
    xfree(kinfo->fdt);
}

static void __init initrd_load(struct kernel_info *kinfo)
{
    const struct bootmodule *mod = kinfo->initrd_bootmodule;
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
           kinfo->d, paddr, load_addr, load_addr + len);

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
        panic("Unable to map the hwdom initrd\n");

    res = copy_to_guest_phys_flush_dcache(kinfo->d, load_addr,
                                          initrd, len);
    if ( res != 0 )
        panic("Unable to copy the initrd in the hwdom memory\n");

    iounmap(initrd);
}

/*
 * Allocate the event channel PPIs and setup the HVM_PARAM_CALLBACK_IRQ.
 * The allocated IRQ will be found in d->arch.evtchn_irq.
 *
 * Note that this should only be called once all PPIs used by the
 * hardware domain have been registered.
 */
void __init evtchn_allocate(struct domain *d)
{
    int res;
    u64 val;

    res = vgic_allocate_ppi(d);
    if ( res < 0 )
        panic("Unable to allocate a PPI for the event channel interrupt\n");

    d->arch.evtchn_irq = res;

    printk("Allocating PPI %u for event channel interrupt\n",
           d->arch.evtchn_irq);

    /* Set the value of domain param HVM_PARAM_CALLBACK_IRQ */
    val = MASK_INSR(HVM_PARAM_CALLBACK_TYPE_PPI,
                    HVM_PARAM_CALLBACK_IRQ_TYPE_MASK);
    /* Active-low level-sensitive  */
    val |= MASK_INSR(HVM_PARAM_CALLBACK_TYPE_PPI_FLAG_LOW_LEVEL,
                     HVM_PARAM_CALLBACK_TYPE_PPI_FLAG_MASK);
    val |= d->arch.evtchn_irq;
    d->arch.hvm.params[HVM_PARAM_CALLBACK_IRQ] = val;
}

static int __init get_evtchn_dt_property(const struct dt_device_node *np,
                                         uint32_t *port, uint32_t *phandle)
{
    const __be32 *prop = NULL;
    uint32_t len;

    prop = dt_get_property(np, "xen,evtchn", &len);
    if ( !prop )
    {
        printk(XENLOG_ERR "xen,evtchn property should not be empty.\n");
        return -EINVAL;
    }

    if ( !len || len < dt_cells_to_size(STATIC_EVTCHN_NODE_SIZE_CELLS) )
    {
        printk(XENLOG_ERR "xen,evtchn property value is not valid.\n");
        return -EINVAL;
    }

    *port = dt_next_cell(1, &prop);
    *phandle = dt_next_cell(1, &prop);

    return 0;
}

static int __init alloc_domain_evtchn(struct dt_device_node *node)
{
    int rc;
    uint32_t domU1_port, domU2_port, remote_phandle;
    struct dt_device_node *remote_node;
    const struct dt_device_node *p1_node, *p2_node;
    struct evtchn_alloc_unbound alloc_unbound;
    struct evtchn_bind_interdomain bind_interdomain;
    struct domain *d1 = NULL, *d2 = NULL;

    if ( !dt_device_is_compatible(node, "xen,evtchn-v1") )
        return 0;

    /*
     * Event channel is already created while parsing the other side of
     * evtchn node.
     */
    if ( dt_device_static_evtchn_created(node) )
        return 0;

    rc = get_evtchn_dt_property(node, &domU1_port, &remote_phandle);
    if ( rc )
        return rc;

    remote_node = dt_find_node_by_phandle(remote_phandle);
    if ( !remote_node )
    {
        printk(XENLOG_ERR
                "evtchn: could not find remote evtchn phandle\n");
        return -EINVAL;
    }

    rc = get_evtchn_dt_property(remote_node, &domU2_port, &remote_phandle);
    if ( rc )
        return rc;

    if ( node->phandle != remote_phandle )
    {
        printk(XENLOG_ERR "xen,evtchn property is not setup correctly.\n");
        return -EINVAL;
    }

    p1_node = dt_get_parent(node);
    if ( !p1_node )
    {
        printk(XENLOG_ERR "evtchn: evtchn parent node is NULL\n" );
        return -EINVAL;
    }

    p2_node = dt_get_parent(remote_node);
    if ( !p2_node )
    {
        printk(XENLOG_ERR "evtchn: remote parent node is NULL\n" );
        return -EINVAL;
    }

    d1 = get_domain_by_id(p1_node->used_by);
    d2 = get_domain_by_id(p2_node->used_by);

    if ( !d1 || !d2 )
    {
        printk(XENLOG_ERR "evtchn: could not find domains\n" );
        return -EINVAL;
    }

    alloc_unbound.dom = d1->domain_id;
    alloc_unbound.remote_dom = d2->domain_id;

    rc = evtchn_alloc_unbound(&alloc_unbound, domU1_port);
    if ( rc < 0 )
    {
        printk(XENLOG_ERR
                "evtchn_alloc_unbound() failure (Error %d) \n", rc);
        return rc;
    }

    bind_interdomain.remote_dom  = d1->domain_id;
    bind_interdomain.remote_port = domU1_port;

    rc = evtchn_bind_interdomain(&bind_interdomain, d2, domU2_port);
    if ( rc < 0 )
    {
        printk(XENLOG_ERR
                "evtchn_bind_interdomain() failure (Error %d) \n", rc);
        return rc;
    }

    dt_device_set_static_evtchn_created(node);
    dt_device_set_static_evtchn_created(remote_node);

    return 0;
}

void __init alloc_static_evtchn(void)
{
    struct dt_device_node *node, *evtchn_node;
    struct dt_device_node *chosen = dt_find_node_by_path("/chosen");

    BUG_ON(chosen == NULL);

    if ( hardware_domain )
        dt_device_set_used_by(chosen, hardware_domain->domain_id);

    dt_for_each_child_node(chosen, node)
    {
        if ( hardware_domain )
        {
            if ( alloc_domain_evtchn(node) != 0 )
                panic("Could not set up domains evtchn\n");
        }

        dt_for_each_child_node(node, evtchn_node)
        {
            if ( alloc_domain_evtchn(evtchn_node) != 0 )
                panic("Could not set up domains evtchn\n");
        }
    }
}

static void __init find_gnttab_region(struct domain *d,
                                      struct kernel_info *kinfo)
{
    /*
     * The region used by Xen on the memory will never be mapped in DOM0
     * memory layout. Therefore it can be used for the grant table.
     *
     * Only use the text section as it's always present and will contain
     * enough space for a large grant table
     */
    kinfo->gnttab_start = __pa(_stext);
    kinfo->gnttab_size = gnttab_dom0_frames() << PAGE_SHIFT;

#ifdef CONFIG_ARM_32
    /*
     * The gnttab region must be under 4GB in order to work with DOM0
     * using short page table.
     * In practice it's always the case because Xen is always located
     * below 4GB, but be safe.
     */
    BUG_ON((kinfo->gnttab_start + kinfo->gnttab_size) > GB(4));
#endif

    printk("Grant table range: %#"PRIpaddr"-%#"PRIpaddr"\n",
           kinfo->gnttab_start, kinfo->gnttab_start + kinfo->gnttab_size);
}

static unsigned long __init domain_p2m_pages(unsigned long maxmem_kb,
                                             unsigned int smp_cpus)
{
    /*
     * Keep in sync with libxl__get_required_paging_memory().
     * 256 pages (1MB) per vcpu, plus 1 page per MiB of RAM for the P2M map,
     * plus 128 pages to cover extended regions.
     */
    unsigned long memkb = 4 * (256 * smp_cpus + (maxmem_kb / 1024) + 128);

    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);

    return DIV_ROUND_UP(memkb, 1024) << (20 - PAGE_SHIFT);
}

static int __init construct_domain(struct domain *d, struct kernel_info *kinfo)
{
    unsigned int i;
    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

#ifdef CONFIG_ARM_64
    /* if aarch32 mode is not supported at EL1 do not allow 32-bit domain */
    if ( !(cpu_has_el1_32) && kinfo->type == DOMAIN_32BIT )
    {
        printk("Platform does not support 32-bit domain\n");
        return -EINVAL;
    }

    if ( is_64bit_domain(d) )
        vcpu_switch_to_aarch64_mode(v);

#endif

    /*
     * kernel_load will determine the placement of the kernel as well
     * as the initrd & fdt in RAM, so call it first.
     */
    kernel_load(kinfo);
    /* initrd_load will fix up the fdt, so call it before dtb_load */
    initrd_load(kinfo);
    dtb_load(kinfo);

    memset(regs, 0, sizeof(*regs));

    regs->pc = (register_t)kinfo->entry;

    if ( is_32bit_domain(d) )
    {
        regs->cpsr = PSR_GUEST32_INIT;

        /* FROM LINUX head.S
         *
         * Kernel startup entry point.
         * ---------------------------
         *
         * This is normally called from the decompressor code.  The requirements
         * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
         * r1 = machine nr, r2 = atags or dtb pointer.
         *...
         */
        regs->r0 = 0; /* SBZ */
        regs->r1 = 0xffffffff; /* We use DTB therefore no machine id */
        regs->r2 = kinfo->dtb_paddr;
    }
#ifdef CONFIG_ARM_64
    else
    {
        regs->cpsr = PSR_GUEST64_INIT;
        /* From linux/Documentation/arm64/booting.txt */
        regs->x0 = kinfo->dtb_paddr;
        regs->x1 = 0; /* Reserved for future use */
        regs->x2 = 0; /* Reserved for future use */
        regs->x3 = 0; /* Reserved for future use */
    }
#endif

    for ( i = 1; i < d->max_vcpus; i++ )
    {
        if ( vcpu_create(d, i) == NULL )
        {
            printk("Failed to allocate d%dv%d\n", d->domain_id, i);
            break;
        }

        if ( is_64bit_domain(d) )
            vcpu_switch_to_aarch64_mode(d->vcpu[i]);
    }

    domain_update_node_affinity(d);

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
}

static int __init alloc_xenstore_evtchn(struct domain *d)
{
    evtchn_alloc_unbound_t alloc;
    int rc;

    alloc.dom = d->domain_id;
    alloc.remote_dom = hardware_domain->domain_id;
    rc = evtchn_alloc_unbound(&alloc, 0);
    if ( rc )
    {
        printk("Failed allocating event channel for domain\n");
        return rc;
    }

    d->arch.hvm.params[HVM_PARAM_STORE_EVTCHN] = alloc.port;

    return 0;
}

static int __init construct_domU(struct domain *d,
                                 const struct dt_device_node *node)
{
    struct kernel_info kinfo = {};
    const char *dom0less_enhanced;
    int rc;
    u64 mem;
    u32 p2m_mem_mb;
    unsigned long p2m_pages;

    rc = dt_property_read_u64(node, "memory", &mem);
    if ( !rc )
    {
        printk("Error building DomU: cannot read \"memory\" property\n");
        return -EINVAL;
    }
    kinfo.unassigned_mem = (paddr_t)mem * SZ_1K;

    rc = dt_property_read_u32(node, "xen,domain-p2m-mem-mb", &p2m_mem_mb);
    /* If xen,domain-p2m-mem-mb is not specified, use the default value. */
    p2m_pages = rc ?
                p2m_mem_mb << (20 - PAGE_SHIFT) :
                domain_p2m_pages(mem, d->max_vcpus);

    spin_lock(&d->arch.paging.lock);
    rc = p2m_set_allocation(d, p2m_pages, NULL);
    spin_unlock(&d->arch.paging.lock);
    if ( rc != 0 )
        return rc;

    printk("*** LOADING DOMU cpus=%u memory=%#"PRIx64"KB ***\n",
           d->max_vcpus, mem);

    kinfo.vpl011 = dt_property_read_bool(node, "vpl011");

    rc = dt_property_read_string(node, "xen,enhanced", &dom0less_enhanced);
    if ( rc == -EILSEQ ||
         rc == -ENODATA ||
         (rc == 0 && !strcmp(dom0less_enhanced, "enabled")) )
    {
        if ( hardware_domain )
            kinfo.dom0less_feature = DOM0LESS_ENHANCED;
        else
            panic("At the moment, Xenstore support requires dom0 to be present\n");
    }
    else if ( rc == 0 && !strcmp(dom0less_enhanced, "no-xenstore") )
        kinfo.dom0less_feature = DOM0LESS_ENHANCED_NO_XS;

    if ( vcpu_create(d, 0) == NULL )
        return -ENOMEM;

    d->max_pages = ((paddr_t)mem * SZ_1K) >> PAGE_SHIFT;

    kinfo.d = d;

    rc = kernel_probe(&kinfo, node);
    if ( rc < 0 )
        return rc;

#ifdef CONFIG_ARM_64
    /* type must be set before allocate memory */
    d->arch.type = kinfo.type;
#endif
    if ( !dt_find_property(node, "xen,static-mem", NULL) )
        allocate_memory(d, &kinfo);
    else if ( !is_domain_direct_mapped(d) )
        allocate_static_memory(d, &kinfo, node);
    else
        assign_static_memory_11(d, &kinfo, node);

#ifdef CONFIG_STATIC_SHM
    rc = process_shm(d, &kinfo, node);
    if ( rc < 0 )
        return rc;
#endif

    /*
     * Base address and irq number are needed when creating vpl011 device
     * tree node in prepare_dtb_domU, so initialization on related variables
     * shall be done first.
     */
    if ( kinfo.vpl011 )
    {
        rc = domain_vpl011_init(d, NULL);
        if ( rc < 0 )
            return rc;
    }

    rc = prepare_dtb_domU(d, &kinfo);
    if ( rc < 0 )
        return rc;

    rc = construct_domain(d, &kinfo);
    if ( rc < 0 )
        return rc;

    if ( kinfo.dom0less_feature & DOM0LESS_XENSTORE )
    {
        ASSERT(hardware_domain);
        rc = alloc_xenstore_evtchn(d);
        if ( rc < 0 )
            return rc;
        d->arch.hvm.params[HVM_PARAM_STORE_PFN] = ~0ULL;
    }

    return rc;
}

void __init create_domUs(void)
{
    struct dt_device_node *node;
    const struct dt_device_node *cpupool_node,
                                *chosen = dt_find_node_by_path("/chosen");

    BUG_ON(chosen == NULL);
    dt_for_each_child_node(chosen, node)
    {
        struct domain *d;
        struct xen_domctl_createdomain d_cfg = {
            .arch.gic_version = XEN_DOMCTL_CONFIG_GIC_NATIVE,
            .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
            /*
             * The default of 1023 should be sufficient for guests because
             * on ARM we don't bind physical interrupts to event channels.
             * The only use of the evtchn port is inter-domain communications.
             * 1023 is also the default value used in libxl.
             */
            .max_evtchn_port = 1023,
            .max_grant_frames = -1,
            .max_maptrack_frames = -1,
            .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
        };
        unsigned int flags = 0U;
        uint32_t val;
        int rc;

        if ( !dt_device_is_compatible(node, "xen,domain") )
            continue;

        if ( (max_init_domid + 1) >= DOMID_FIRST_RESERVED )
            panic("No more domain IDs available\n");

        if ( dt_find_property(node, "xen,static-mem", NULL) )
            flags |= CDF_staticmem;

        if ( dt_property_read_bool(node, "direct-map") )
        {
            if ( !(flags & CDF_staticmem) )
                panic("direct-map is not valid for domain %s without static allocation.\n",
                      dt_node_name(node));

            flags |= CDF_directmap;
        }

        if ( !dt_property_read_u32(node, "cpus", &d_cfg.max_vcpus) )
            panic("Missing property 'cpus' for domain %s\n",
                  dt_node_name(node));

        if ( dt_find_compatible_node(node, NULL, "multiboot,device-tree") &&
             iommu_enabled )
            d_cfg.flags |= XEN_DOMCTL_CDF_iommu;

        if ( !dt_property_read_u32(node, "nr_spis", &d_cfg.arch.nr_spis) )
        {
            int vpl011_virq = GUEST_VPL011_SPI;

            d_cfg.arch.nr_spis = gic_number_lines() - 32;

            /*
             * The VPL011 virq is GUEST_VPL011_SPI, unless direct-map is
             * set, in which case it'll match the hardware.
             *
             * Since the domain is not yet created, we can't use
             * d->arch.vpl011.irq. So the logic to find the vIRQ has to
             * be hardcoded.
             * The logic here shall be consistent with the one in
             * domain_vpl011_init().
             */
            if ( flags & CDF_directmap )
            {
                vpl011_virq = serial_irq(SERHND_DTUART);
                if ( vpl011_virq < 0 )
                    panic("Error getting IRQ number for this serial port %d\n",
                          SERHND_DTUART);
            }

            /*
             * vpl011 uses one emulated SPI. If vpl011 is requested, make
             * sure that we allocate enough SPIs for it.
             */
            if ( dt_property_read_bool(node, "vpl011") )
                d_cfg.arch.nr_spis = MAX(d_cfg.arch.nr_spis,
                                         vpl011_virq - 32 + 1);
        }

        /* Get the optional property domain-cpupool */
        cpupool_node = dt_parse_phandle(node, "domain-cpupool", 0);
        if ( cpupool_node )
        {
            int pool_id = btcpupools_get_domain_pool_id(cpupool_node);
            if ( pool_id < 0 )
                panic("Error getting cpupool id from domain-cpupool (%d)\n",
                      pool_id);
            d_cfg.cpupool_id = pool_id;
        }

        if ( dt_property_read_u32(node, "max_grant_version", &val) )
            d_cfg.grant_opts = XEN_DOMCTL_GRANT_version(val);

        if ( dt_property_read_u32(node, "max_grant_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_grant_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_grant_frames = val;
        }

        if ( dt_property_read_u32(node, "max_maptrack_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_maptrack_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_maptrack_frames = val;
        }

        /*
         * The variable max_init_domid is initialized with zero, so here it's
         * very important to use the pre-increment operator to call
         * domain_create() with a domid > 0. (domid == 0 is reserved for Dom0)
         */
        d = domain_create(++max_init_domid, &d_cfg, flags);
        if ( IS_ERR(d) )
            panic("Error creating domain %s (rc = %ld)\n",
                  dt_node_name(node), PTR_ERR(d));

        d->is_console = true;
        dt_device_set_used_by(node, d->domain_id);

        rc = construct_domU(d, node);
        if ( rc )
            panic("Could not set up domain %s (rc = %d)\n",
                  dt_node_name(node), rc);
    }
}

static int __init construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    int rc;
#ifdef CONFIG_STATIC_SHM
    const struct dt_device_node *chosen = dt_find_node_by_path("/chosen");
#endif

    /* Sanity! */
    BUG_ON(d->domain_id != 0);

    printk("*** LOADING DOMAIN 0 ***\n");

    /* The ordering of operands is to work around a clang5 issue. */
    if ( CONFIG_DOM0_MEM[0] && !dom0_mem_set )
        parse_dom0_mem(CONFIG_DOM0_MEM);

    if ( dom0_mem <= 0 )
    {
        warning_add("PLEASE SPECIFY dom0_mem PARAMETER - USING 512M FOR NOW\n");
        dom0_mem = MB(512);
    }

    iommu_hwdom_init(d);

    d->max_pages = dom0_mem >> PAGE_SHIFT;

    kinfo.unassigned_mem = dom0_mem;
    kinfo.d = d;

    rc = kernel_probe(&kinfo, NULL);
    if ( rc < 0 )
        return rc;

#ifdef CONFIG_ARM_64
    /* type must be set before allocate_memory */
    d->arch.type = kinfo.type;
#endif
    allocate_memory_11(d, &kinfo);
    find_gnttab_region(d, &kinfo);

#ifdef CONFIG_STATIC_SHM
    rc = process_shm(d, &kinfo, chosen);
    if ( rc < 0 )
        return rc;
#endif

    /* Map extra GIC MMIO, irqs and other hw stuffs to dom0. */
    rc = gic_map_hwdom_extra_mappings(d);
    if ( rc < 0 )
        return rc;

    rc = platform_specific_mapping(d);
    if ( rc < 0 )
        return rc;

    if ( acpi_disabled )
    {
        rc = prepare_dtb_hwdom(d, &kinfo);
        if ( rc < 0 )
            return rc;
#ifdef CONFIG_HAS_PCI
        rc = pci_host_bridge_mappings(d);
#endif
    }
    else
        rc = prepare_acpi(d, &kinfo);

    if ( rc < 0 )
        return rc;

    return construct_domain(d, &kinfo);
}

void __init create_dom0(void)
{
    struct domain *dom0;
    struct xen_domctl_createdomain dom0_cfg = {
        .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
        .max_evtchn_port = -1,
        .max_grant_frames = gnttab_dom0_frames(),
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
    };
    int rc;

    /* The vGIC for DOM0 is exactly emulating the hardware GIC */
    dom0_cfg.arch.gic_version = XEN_DOMCTL_CONFIG_GIC_NATIVE;
    /*
     * Xen vGIC supports a maximum of 992 interrupt lines.
     * 32 are substracted to cover local IRQs.
     */
    dom0_cfg.arch.nr_spis = min(gic_number_lines(), (unsigned int) 992) - 32;
    if ( gic_number_lines() > 992 )
        printk(XENLOG_WARNING "Maximum number of vGIC IRQs exceeded.\n");
    dom0_cfg.arch.tee_type = tee_get_type();
    dom0_cfg.max_vcpus = dom0_max_vcpus();

    if ( iommu_enabled )
        dom0_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    dom0 = domain_create(0, &dom0_cfg, CDF_privileged | CDF_directmap);
    if ( IS_ERR(dom0) )
        panic("Error creating domain 0 (rc = %ld)\n", PTR_ERR(dom0));

    if ( alloc_dom0_vcpu0(dom0) == NULL )
        panic("Error creating domain 0 vcpu0\n");

    rc = construct_dom0(dom0);
    if ( rc )
        panic("Could not set up DOM0 guest OS (rc = %d)\n", rc);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
