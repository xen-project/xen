/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/init.h>
#include <xen/compile.h>
#include <xen/lib.h>
#include <xen/llc-coloring.h>
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
#include <asm/device.h>
#include <asm/kernel.h>
#include <asm/setup.h>
#include <asm/tee/tee.h>
#include <asm/pci.h>
#include <asm/platform.h>
#include <asm/psci.h>
#include <asm/setup.h>
#include <asm/arm64/sve.h>
#include <asm/cpufeature.h>
#include <asm/dom0less-build.h>
#include <asm/domain_build.h>
#include <asm/static-shmem.h>
#include <xen/event.h>

#include <xen/irq.h>
#include <xen/grant_table.h>
#include <asm/grant_table.h>
#include <xen/serial.h>

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

int __init parse_arch_dom0_param(const char *s, const char *e)
{
    long long val;

    if ( !parse_signed_integer("sve", s, e, &val) )
    {
#ifdef CONFIG_ARM64_SVE
        if ( (val >= INT_MIN) && (val <= INT_MAX) )
            opt_dom0_sve = val;
        else
            printk(XENLOG_INFO "'sve=%lld' value out of range!\n", val);

        return 0;
#else
        panic("'sve' property found, but CONFIG_ARM64_SVE not selected\n");
#endif
    }

    return -EINVAL;
}

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

unsigned int __init get_allocation_size(paddr_t size)
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
    struct membanks *mem = kernel_info_get_mem(kinfo);
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

    if ( mem->nr_banks > 0 &&
         size < MB(128) &&
         start + size < mem->bank[0].start )
    {
        D11PRINT("Allocation below bank 0 is too small, not using\n");
        goto fail;
    }

    res = guest_physmap_add_page(d, _gfn(mfn_x(smfn)), smfn, order);
    if ( res )
        panic("Failed map pages to DOM0: %d\n", res);

    kinfo->unassigned_mem -= size;

    if ( mem->nr_banks == 0 )
    {
        mem->bank[0].start = start;
        mem->bank[0].size = size;
        mem->nr_banks = 1;
        return true;
    }

    for( i = 0; i < mem->nr_banks; i++ )
    {
        struct membank *bank = &mem->bank[i];

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
        if ( start + size < bank->start && mem->nr_banks < mem->max_banks )
        {
            memmove(bank + 1, bank,
                    sizeof(*bank) * (mem->nr_banks - i));
            mem->nr_banks++;
            bank->start = start;
            bank->size = size;
            return true;
        }
    }

    if ( i == mem->nr_banks && mem->nr_banks < mem->max_banks )
    {
        struct membank *bank = &mem->bank[mem->nr_banks];

        bank->start = start;
        bank->size = size;
        mem->nr_banks++;
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
    struct membanks *mem = kernel_info_get_mem(kinfo);
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

    mem->nr_banks = 0;

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
    while ( kinfo->unassigned_mem && mem->nr_banks < mem->max_banks )
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
            if ( mem->nr_banks == mem->max_banks )
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

    for( i = 0; i < mem->nr_banks; i++ )
    {
        printk("BANK[%d] %#"PRIpaddr"-%#"PRIpaddr" (%ldMB)\n",
               i,
               mem->bank[i].start,
               mem->bank[i].start + mem->bank[i].size,
               /* Don't want format this as PRIpaddr (16 digit hex) */
               (unsigned long)(mem->bank[i].size >> 20));
    }
}

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
    struct domain *d = kinfo->d;
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
    if ( !iommu_node )
        iommu_node = dt_parse_phandle(node, "iommu-map", 1);
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
         *   xen,static-heap, linux,initrd-start and linux,initrd-end.
         * * remove stdout-path.
         * * remove bootargs, linux,uefi-system-table,
         *   linux,uefi-mmap-start, linux,uefi-mmap-size,
         *   linux,uefi-mmap-desc-size, and linux,uefi-mmap-desc-ver
         *   (since EFI boot is not currently supported in dom0).
         */
        if ( dt_node_path_is_equal(node, "/chosen") )
        {
            if ( dt_property_name_is_equal(prop, "xen,static-heap") ||
                 dt_property_name_is_equal(prop, "xen,xen-bootargs") ||
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

void __init set_interrupt(gic_interrupt_t interrupt,
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
int __init domain_fdt_begin_node(void *fdt, const char *name, uint64_t unit)
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

int __init make_memory_node(const struct kernel_info *kinfo, int addrcells,
                            int sizecells, const struct membanks *mem)
{
    void *fdt = kinfo->fdt;
    unsigned int i;
    int res, reg_size = addrcells + sizecells;
    int nr_cells = 0;
    __be32 reg[DT_MEM_NODE_REG_RANGE_SIZE];
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

        if ( (mem->bank[i].type == MEMBANK_STATIC_DOMAIN) ||
             (mem->bank[i].type == MEMBANK_FDT_RESVMEM) )
            continue;

        nr_cells += reg_size;
        BUG_ON(nr_cells >= ARRAY_SIZE(reg));
        dt_child_set_range(&cells, addrcells, sizecells, start, size);
    }

    /*
     * static shared memory banks need to be listed as /memory node, so when
     * this function is handling the normal memory, add the banks.
     */
    if ( mem == kernel_info_get_mem_const(kinfo) )
        shm_mem_node_fill_reg_range(kinfo, reg, &nr_cells, addrcells,
                                    sizecells);

    for ( cells = reg, i = 0; cells < reg + nr_cells; i++, cells += reg_size )
    {
        uint64_t start = dt_read_number(cells, addrcells);
        uint64_t size = dt_read_number(cells + addrcells, sizecells);

        dt_dprintk("  Bank %u: %#"PRIx64"->%#"PRIx64"\n",
                   i, start, start + size);
    }

    dt_dprintk("(reg size %d, nr cells %d)\n", reg_size, nr_cells);

    res = fdt_property(fdt, "reg", reg, nr_cells * sizeof(*reg));
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

int __init add_ext_regions(unsigned long s_gfn, unsigned long e_gfn,
                           void *data)
{
    struct membanks *ext_regions = data;
    paddr_t start, size;
    paddr_t s = pfn_to_paddr(s_gfn);
    paddr_t e = pfn_to_paddr(e_gfn);

    if ( ext_regions->nr_banks >= ext_regions->max_banks )
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

static int __init add_hwdom_free_regions(unsigned long s_gfn,
                                         unsigned long e_gfn, void *data)
{
    struct membanks *free_regions = data;
    paddr_t start, size;
    paddr_t s = pfn_to_paddr(s_gfn);
    paddr_t e = pfn_to_paddr(e_gfn);
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
static int __init find_unallocated_memory(const struct kernel_info *kinfo,
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

    ASSERT(domain_use_host_layout(kinfo->d));

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
        struct membanks *gnttab = membanks_xzalloc(1, MEMORY);
        /*
         * Exclude the following regions:
         * 1) Remove reserved memory
         * 2) Grant table assigned to hwdom
         */
        const struct membanks *mem_banks[] = {
            bootinfo_get_reserved_mem(),
            gnttab,
        };

        if ( !gnttab )
            goto fail;

        gnttab->nr_banks = 1;
        gnttab->bank[0].start = kinfo->gnttab_start;
        gnttab->bank[0].size = kinfo->gnttab_size;

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

static int __init handle_pci_range(const struct dt_device_node *dev,
                                   uint64_t addr, uint64_t len, void *data)
{
    struct rangeset *mem_holes = data;
    paddr_t start, end;
    int res;

    if ( (addr != (paddr_t)addr) || (((paddr_t)~0 - addr) < len) )
    {
        printk(XENLOG_ERR "%s: [0x%"PRIx64", 0x%"PRIx64"] exceeds the maximum allowed PA width (%u bits)",
               dt_node_full_name(dev), addr, (addr + len), PADDR_BITS);
        return -ERANGE;
    }

    start = addr & PAGE_MASK;
    end = PAGE_ALIGN(addr + len);
    res = rangeset_remove_range(mem_holes, PFN_DOWN(start), PFN_DOWN(end - 1));
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
 * - Static shared memory regions, which are described by special property
 *   "xen,shared-mem"
 */
static int __init find_memory_holes(const struct kernel_info *kinfo,
                                    struct membanks *ext_regions)
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
    res = rangeset_add_range(mem_holes, PFN_DOWN(start), PFN_DOWN(end));
    if ( res )
    {
        printk(XENLOG_ERR "Failed to add: %#"PRIpaddr"->%#"PRIpaddr"\n",
               start, end);
        goto out;
    }

    /* Remove static shared memory regions */
    res = remove_shm_from_rangeset(kinfo, mem_holes);
    if ( res )
        goto out;

    /*
     * Remove regions described by "reg" and "ranges" properties where
     * the memory is addressable (MMIO, RAM, PCI BAR, etc).
     */
    dt_for_each_device_node( dt_host, np )
    {
        unsigned int naddr;
        paddr_t addr, size;

        naddr = dt_number_of_address(np);

        for ( i = 0; i < naddr; i++ )
        {
            res = dt_device_get_paddr(np, i, &addr, &size);
            if ( res )
            {
                printk(XENLOG_ERR "Unable to retrieve address %u for %s\n",
                       i, dt_node_full_name(np));
                goto out;
            }

            start = addr & PAGE_MASK;
            end = PAGE_ALIGN(addr + size);
            res = rangeset_remove_range(mem_holes, PFN_DOWN(start),
                                        PFN_DOWN(end - 1));
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
    res = rangeset_report_ranges(mem_holes, PFN_DOWN(start), PFN_DOWN(end),
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
                                  struct membanks *ext_regions)
{
    unsigned int i;
    uint64_t bankend;
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
    const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;
    const struct membanks *kinfo_mem = kernel_info_get_mem_const(kinfo);
    int res = -ENOENT;

    for ( i = 0; i < GUEST_RAM_BANKS; i++ )
    {
        struct membank *ext_bank = &(ext_regions->bank[ext_regions->nr_banks]);

        ext_bank->start = ROUNDUP(bankbase[i] + kinfo_mem->bank[i].size, SZ_2M);

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

    if ( res )
        return res;

    return remove_shm_holes_for_domU(kinfo, ext_regions);
}

static int __init find_host_extended_regions(const struct kernel_info *kinfo,
                                             struct membanks *ext_regions)
{
    int res;
    struct membanks *gnttab = membanks_xzalloc(1, MEMORY);

    /*
     * Exclude the following regions:
     * 1) Remove RAM assigned to domain
     * 2) Remove reserved memory
     * 3) Grant table assigned to domain
     * 4) Remove static shared memory (when the feature is enabled)
     */
    const struct membanks *mem_banks[] = {
        kernel_info_get_mem_const(kinfo),
        bootinfo_get_reserved_mem(),
        gnttab,
#ifdef CONFIG_STATIC_SHM
        bootinfo_get_shmem(),
#endif
    };

    dt_dprintk("Find unallocated memory for extended regions\n");

    if ( !gnttab )
        return -ENOMEM;

    gnttab->nr_banks = 1;
    gnttab->bank[0].start = kinfo->gnttab_start;
    gnttab->bank[0].size = kinfo->gnttab_size;

    res = find_unallocated_memory(kinfo, mem_banks, ARRAY_SIZE(mem_banks),
                                  ext_regions, add_ext_regions);
    xfree(gnttab);

    return res;
}

int __init make_hypervisor_node(struct domain *d,
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
    struct membanks *ext_regions = NULL;
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
        ext_regions = membanks_xzalloc(NR_MEM_BANKS, MEMORY);
        if ( !ext_regions )
            return -ENOMEM;

        if ( domain_use_host_layout(d) )
        {
            if ( !is_iommu_enabled(d) )
                res = find_host_extended_regions(kinfo, ext_regions);
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

int __init make_psci_node(void *fdt)
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

int __init make_cpus_node(const struct domain *d, void *fdt)
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

int __init make_timer_node(const struct kernel_info *kinfo)
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
    const struct bootmodule *initrd = kinfo->initrd_bootmodule;
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

    res = fdt_end_node(fdt);

    return res;
}

static int __init handle_node(struct domain *d, struct kernel_info *kinfo,
                              struct dt_device_node *node,
                              p2m_type_t p2mt)
{
    static const struct dt_device_match skip_matches[] __initconst =
    {
        DT_MATCH_COMPATIBLE("xen,domain"),
        DT_MATCH_COMPATIBLE("xen,domain-shared-memory-v1"),
        DT_MATCH_COMPATIBLE("xen,evtchn-v1"),
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
    static __initdata bool res_mem_node_found = false;
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
    if ( device_get_class(node) == DEVICE_INTERRUPT_CONTROLLER )
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

    res = handle_device(d, node, p2mt, NULL, NULL);
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

    if ( dt_node_path_is_equal(node, "/reserved-memory") )
    {
        res_mem_node_found = true;
        /*
         * Avoid duplicate /reserved-memory nodes in Device Tree, so add the
         * static shared memory nodes there.
         */
        res = make_shm_resv_memory_node(kinfo, dt_n_addr_cells(node),
                                        dt_n_size_cells(node));
        if ( res )
            return res;
    }

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        res = handle_node(d, kinfo, child, p2mt);
        if ( res )
            return res;
    }

    if ( node == dt_host )
    {
        const struct membanks *reserved_mem = bootinfo_get_reserved_mem();
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

        res = make_memory_node(kinfo, addrcells, sizecells,
                               kernel_info_get_mem(kinfo));
        if ( res )
            return res;

        /*
         * Create a second memory node to store the ranges covering
         * reserved-memory regions.
         */
        if ( reserved_mem->nr_banks > 0 )
        {
            res = make_memory_node(kinfo, addrcells, sizecells, reserved_mem);
            if ( res )
                return res;
        }

        if ( !res_mem_node_found )
        {
            res = make_resv_memory_node(kinfo, addrcells, sizecells);
            if ( res )
                return res;
        }
    }

    res = fdt_end_node(kinfo->fdt);

    return res;
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

int __init construct_domain(struct domain *d, struct kernel_info *kinfo)
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

    if ( is_sve_domain(d) && (kinfo->type == DOMAIN_32BIT) )
    {
        printk("SVE is not available for 32-bit domain\n");
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
        regs->r0 = 0U; /* SBZ */
        regs->r1 = 0xffffffffU; /* We use DTB therefore no machine id */
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

static int __init construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = KERNEL_INFO_INIT;
    int rc;

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
    find_gnttab_region(d, &kinfo);
    if ( is_domain_direct_mapped(d) )
        allocate_memory_11(d, &kinfo);
    else
        allocate_memory(d, &kinfo);

    rc = process_shm_chosen(d, &kinfo);
    if ( rc < 0 )
        return rc;

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
    unsigned int flags = CDF_privileged;
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

    if ( opt_dom0_sve )
    {
        unsigned int vl;

        if ( sve_domctl_vl_param(opt_dom0_sve, &vl) )
            dom0_cfg.arch.sve_vl = sve_encode_vl(vl);
        else
            panic("SVE vector length error\n");
    }

    if ( !llc_coloring_enabled )
        flags |= CDF_directmap;

    dom0 = domain_create(0, &dom0_cfg, flags);
    if ( IS_ERR(dom0) )
        panic("Error creating domain 0 (rc = %ld)\n", PTR_ERR(dom0));

    if ( llc_coloring_enabled && (rc = dom0_set_llc_colors(dom0)) )
        panic("Error initializing LLC coloring for domain 0 (rc = %d)\n", rc);

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
