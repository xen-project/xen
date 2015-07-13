#include <xen/config.h>
#include <xen/init.h>
#include <xen/compile.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/irq.h>
#include <asm/regs.h>
#include <xen/errno.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <asm/device.h>
#include <asm/setup.h>
#include <asm/platform.h>
#include <asm/psci.h>
#include <asm/setup.h>
#include <asm/cpufeature.h>

#include <asm/gic.h>
#include <xen/irq.h>
#include <xen/grant_table.h>
#include "kernel.h"

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

int dom0_11_mapping = 1;

#define DOM0_MEM_DEFAULT 0x8000000 /* 128 MiB */
static u64 __initdata dom0_mem = DOM0_MEM_DEFAULT;

static void __init parse_dom0_mem(const char *s)
{
    dom0_mem = parse_size_and_unit(s, &s);
    if ( dom0_mem == 0 )
        dom0_mem = DOM0_MEM_DEFAULT;
}
custom_param("dom0_mem", parse_dom0_mem);

//#define DEBUG_DT

#ifdef DEBUG_DT
# define DPRINT(fmt, args...) printk(XENLOG_DEBUG fmt, ##args)
#else
# define DPRINT(fmt, args...) do {} while ( 0 )
#endif

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

struct vcpu *__init alloc_dom0_vcpu0(struct domain *dom0)
{
    if ( opt_dom0_max_vcpus == 0 )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > MAX_VIRT_CPUS )
        opt_dom0_max_vcpus = MAX_VIRT_CPUS;

    dom0->vcpu = xzalloc_array(struct vcpu *, opt_dom0_max_vcpus);
    if ( !dom0->vcpu )
        return NULL;
    dom0->max_vcpus = opt_dom0_max_vcpus;

    return alloc_vcpu(dom0, 0, 0);
}

static unsigned int get_11_allocation_size(paddr_t size)
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
static bool_t insert_11_bank(struct domain *d,
                             struct kernel_info *kinfo,
                             struct page_info *pg,
                             unsigned int order)
{
    int res, i;
    paddr_t spfn;
    paddr_t start, size;

    spfn = page_to_mfn(pg);
    start = pfn_to_paddr(spfn);
    size = pfn_to_paddr((1 << order));

    D11PRINT("Allocated %#"PRIpaddr"-%#"PRIpaddr" (%ldMB/%ldMB, order %d)\n",
             start, start + size,
             1UL << (order+PAGE_SHIFT-20),
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

    res = guest_physmap_add_page(d, spfn, spfn, order);
    if ( res )
        panic("Failed map pages to DOM0: %d", res);

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
            memmove(bank + 1, bank, sizeof(*bank)*(kinfo->mem.nr_banks - i));
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
 * 3. For 32-bit dom0 we want to place as much of the RAM as we
 *    reasonably can below 4GB, so that it can be used by non-LPAE
 *    enabled kernels.
 * 4. For 32-bit dom0 the kernel must be located below 4GB.
 * 5. We want to have a few largers banks rather than many smaller ones.
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
 * first bank is under 4G. Then for the subsequent allocations we
 * initially allocate memory only from below 4GB. Once that runs out
 * (as described above) we allow higher allocations and continue until
 * that runs out (or we have allocated sufficient dom0 memory).
 */
static void allocate_memory_11(struct domain *d, struct kernel_info *kinfo)
{
    const unsigned int min_low_order =
        get_order_from_bytes(min_t(paddr_t, dom0_mem, MB(128)));
    const unsigned int min_order = get_order_from_bytes(MB(4));
    struct page_info *pg;
    unsigned int order = get_11_allocation_size(kinfo->unassigned_mem);
    int i;

    bool_t lowmem = is_32bit_domain(d);
    unsigned int bits;

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
        for ( bits = order ; bits <= (lowmem ? 32 : PADDR_BITS); bits++ )
        {
            pg = alloc_domheap_pages(d, order, MEMF_bits(bits));
            if ( pg != NULL )
                goto got_bank0;
        }
        order--;
    }

    panic("Unable to allocate first memory bank");

 got_bank0:

    if ( !insert_11_bank(d, kinfo, pg, order) )
        BUG(); /* Cannot fail for first bank */

    /* Now allocate more memory and fill in additional banks */

    order = get_11_allocation_size(kinfo->unassigned_mem);
    while ( kinfo->unassigned_mem && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        pg = alloc_domheap_pages(d, order, lowmem ? MEMF_bits(32) : 0);
        if ( !pg )
        {
            order --;

            if ( lowmem && order < min_low_order)
            {
                D11PRINT("Failed at min_low_order, allow high allocations\n");
                order = get_11_allocation_size(kinfo->unassigned_mem);
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
                order = get_11_allocation_size(kinfo->unassigned_mem);
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
        order = get_11_allocation_size(kinfo->unassigned_mem);
    }

    if ( kinfo->unassigned_mem )
        printk("WARNING: Failed to allocate requested dom0 memory."
               /* Don't want format this as PRIpaddr (16 digit hex) */
               " %ldMB unallocated\n",
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

static void allocate_memory(struct domain *d, struct kernel_info *kinfo)
{

    struct dt_device_node *memory = NULL;
    const void *reg;
    u32 reg_len, reg_size;
    unsigned int bank = 0;

    if ( dom0_11_mapping )
        return allocate_memory_11(d, kinfo);

    while ( (memory = dt_find_node_by_type(memory, "memory")) )
    {
        int l;

        DPRINT("memory node\n");

        reg_size = dt_cells_to_size(dt_n_addr_cells(memory) + dt_n_size_cells(memory));

        reg = dt_get_property(memory, "reg", &reg_len);
        if ( reg == NULL )
            panic("Memory node has no reg property");

        for ( l = 0;
              kinfo->unassigned_mem > 0 && l + reg_size <= reg_len
                  && kinfo->mem.nr_banks < NR_MEM_BANKS;
              l += reg_size )
        {
            paddr_t start, size;

            if ( dt_device_get_address(memory, bank, &start, &size) )
                panic("Unable to retrieve the bank %u for %s",
                      bank, dt_node_full_name(memory));

            if ( size > kinfo->unassigned_mem )
                size = kinfo->unassigned_mem;

            printk("Populate P2M %#"PRIx64"->%#"PRIx64"\n",
                   start, start + size);
            if ( p2m_populate_ram(d, start, start + size) < 0 )
                panic("Failed to populate P2M");
            kinfo->mem.bank[kinfo->mem.nr_banks].start = start;
            kinfo->mem.bank[kinfo->mem.nr_banks].size = size;
            kinfo->mem.nr_banks++;

            kinfo->unassigned_mem -= size;
        }
    }
}

static int write_properties(struct domain *d, struct kernel_info *kinfo,
                            const struct dt_device_node *node)
{
    const char *bootargs = NULL;
    const struct dt_property *prop, *status = NULL;
    int res = 0;
    int had_dom0_bootargs = 0;

    const struct bootmodule *mod = kinfo->kernel_bootmodule;

    if ( mod && mod->cmdline[0] )
        bootargs = &mod->cmdline[0];

    dt_for_each_property_node (node, prop)
    {
        const void *prop_data = prop->value;
        void *new_data = NULL;
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

        res = fdt_property(kinfo->fdt, prop->name, prop_data, prop_len);

        xfree(new_data);

        if ( res )
            return res;
    }

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
        const struct bootmodule *mod = kinfo->initrd_bootmodule;

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
    }

    return 0;
}

/*
 * Helper to write an interrupts with the GIC format
 * This code is assuming the irq is an PPI.
 */

typedef __be32 gic_interrupt_t[3];

static void set_interrupt_ppi(gic_interrupt_t interrupt, unsigned int irq,
                              unsigned int cpumask, unsigned int level)
{
    __be32 *cells = interrupt;

    BUG_ON(irq < 16 && irq >= 32);

    /* See linux Documentation/devictree/bindings/arm/gic.txt */
    dt_set_cell(&cells, 1, 1); /* is a PPI */
    dt_set_cell(&cells, 1, irq - 16); /* PPIs start at 16 */
    dt_set_cell(&cells, 1, (cpumask << 8) | level);
}

/*
 * Helper to set interrupts for a node in the flat device tree.
 * It needs 2 property:
 *  "interrupts": contains the list of interrupts
 *  "interrupt-parent": link to the GIC
 */
static int fdt_property_interrupts(void *fdt, gic_interrupt_t *intr,
                                   unsigned num_irq)
{
    int res;

    res = fdt_property(fdt, "interrupts", intr, sizeof (intr[0]) * num_irq);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "interrupt-parent",
                            dt_interrupt_controller->phandle);

    return res;
}

static int make_memory_node(const struct domain *d,
                            void *fdt,
                            const struct dt_device_node *parent,
                            const struct kernel_info *kinfo)
{
    int res, i;
    int reg_size = dt_n_addr_cells(parent) + dt_n_size_cells(parent);
    int nr_cells = reg_size*kinfo->mem.nr_banks;
    __be32 reg[nr_cells];
    __be32 *cells;

    DPRINT("Create memory node (reg size %d, nr cells %d)\n", reg_size, nr_cells);

    /* ePAPR 3.4 */
    res = fdt_begin_node(fdt, "memory");
    if ( res )
        return res;

    res = fdt_property_string(fdt, "device_type", "memory");
    if ( res )
        return res;

    cells = &reg[0];
    for ( i = 0 ; i < kinfo->mem.nr_banks; i++ )
    {
        u64 start = kinfo->mem.bank[i].start;
        u64 size = kinfo->mem.bank[i].size;

        DPRINT("  Bank %d: %#"PRIx64"->%#"PRIx64"\n",
                i, start, start + size);

        dt_set_range(&cells, parent, start, size);
    }

    res = fdt_property(fdt, "reg", reg, sizeof(reg));
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int make_hypervisor_node(const struct kernel_info *kinfo,
                                const struct dt_device_node *parent)
{
    const char compat[] =
        "xen,xen-"__stringify(XEN_VERSION)"."__stringify(XEN_SUBVERSION)"\0"
        "xen,xen";
    __be32 reg[4];
    gic_interrupt_t intr;
    __be32 *cells;
    int res;
    /* Convenience alias */
    int addrcells = dt_n_addr_cells(parent);
    int sizecells = dt_n_size_cells(parent);
    void *fdt = kinfo->fdt;

    DPRINT("Create hypervisor node\n");

    /*
     * Sanity-check address sizes, since addresses and sizes which do
     * not take up exactly 4 or 8 bytes are not supported.
     */
    if ((addrcells != 1 && addrcells != 2) ||
        (sizecells != 1 && sizecells != 2))
        panic("Cannot cope with this size");

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    res = fdt_begin_node(fdt, "hypervisor");
    if ( res )
        return res;

    /* Cannot use fdt_property_string due to embedded nulls */
    res = fdt_property(fdt, "compatible", compat, sizeof(compat));
    if ( res )
        return res;

    /* reg 0 is grant table space */
    cells = &reg[0];
    dt_set_range(&cells, parent, kinfo->gnttab_start, kinfo->gnttab_size);
    res = fdt_property(fdt, "reg", reg,
                       dt_cells_to_size(addrcells + sizecells));
    if ( res )
        return res;

    /*
     * Placeholder for the event channel interrupt.  The values will be
     * replaced later.
     */
    set_interrupt_ppi(intr, ~0, 0xf, DT_IRQ_TYPE_INVALID);
    res = fdt_property_interrupts(fdt, &intr, 1);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

static int make_psci_node(void *fdt, const struct dt_device_node *parent)
{
    int res;
    const char compat[] =
        "arm,psci-0.2""\0"
        "arm,psci";

    DPRINT("Create PSCI node\n");

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

static int make_cpus_node(const struct domain *d, void *fdt,
                          const struct dt_device_node *parent)
{
    int res;
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *npcpu;
    unsigned int cpu;
    const void *compatible = NULL;
    u32 len;
    /* Placeholder for cpu@ + a 32-bit number + \0 */
    char buf[15];
    u32 clock_frequency;
    bool_t clock_valid;
    uint64_t mpidr_aff;

    DPRINT("Create cpus node\n");

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
         */
        mpidr_aff = vcpuid_to_vaffinity(cpu);
        DPRINT("Create cpu@%"PRIx64" (logical CPUID: %d) node\n", mpidr_aff, cpu);

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

        if (clock_valid) {
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

static int make_gic_node(const struct domain *d, void *fdt,
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
        DPRINT("  Skipping (secondary GIC)\n");
        return 0;
    }

    DPRINT("Create gic node\n");

    res = fdt_begin_node(fdt, "interrupt-controller");
    if ( res )
        return res;

    /*
     * The value of the property "phandle" in the property "interrupts"
     * to know on which interrupt controller the interrupt is wired.
     */
    if ( gic->phandle )
    {
        DPRINT("  Set phandle = 0x%x\n", gic->phandle);
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

static int make_timer_node(const struct domain *d, void *fdt,
                           const struct dt_device_node *node)
{
    static const struct dt_device_match timer_ids[] __initconst =
    {
        DT_MATCH_COMPATIBLE("arm,armv7-timer"),
        DT_MATCH_COMPATIBLE("arm,armv8-timer"),
        { /* sentinel */ },
    };
    struct dt_device_node *dev;
    u32 len;
    const void *compatible;
    int res;
    unsigned int irq;
    gic_interrupt_t intrs[3];
    u32 clock_frequency;
    bool_t clock_valid;

    DPRINT("Create timer node\n");

    dev = dt_find_matching_node(NULL, timer_ids);
    if ( !dev )
    {
        dprintk(XENLOG_ERR, "Missing timer node in the device tree?\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    compatible = dt_get_property(dev, "compatible", &len);
    if ( !compatible )
    {
        dprintk(XENLOG_ERR, "Can't find compatible property for timer node\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_begin_node(fdt, "timer");
    if ( res )
        return res;

    res = fdt_property(fdt, "compatible", compatible, len);
    if ( res )
        return res;

    /* The timer IRQ is emulated by Xen. It always exposes an active-low
     * level-sensitive interrupt */

    irq = timer_get_irq(TIMER_PHYS_SECURE_PPI);
    DPRINT("  Secure interrupt %u\n", irq);
    set_interrupt_ppi(intrs[0], irq, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    irq = timer_get_irq(TIMER_PHYS_NONSECURE_PPI);
    DPRINT("  Non secure interrupt %u\n", irq);
    set_interrupt_ppi(intrs[1], irq, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    irq = timer_get_irq(TIMER_VIRT_PPI);
    DPRINT("  Virt interrupt %u\n", irq);
    set_interrupt_ppi(intrs[2], irq, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    res = fdt_property_interrupts(fdt, intrs, 3);
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

static int map_irq_to_domain(const struct dt_device_node *dev,
                             struct domain *d, unsigned int irq)

{
    bool_t need_mapping = !dt_device_for_passthrough(dev);
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

        res = route_irq_to_guest(d, irq, irq, dt_node_name(dev));
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map IRQ%"PRId32" to dom%d\n",
                   irq, d->domain_id);
            return res;
        }
    }

    DPRINT("  - IRQ: %u\n", irq);
    return 0;
}

static int map_dt_irq_to_domain(const struct dt_device_node *dev,
                                const struct dt_irq *dt_irq,
                                void *data)
{
    struct domain *d = data;
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

    res = map_irq_to_domain(dev, d, irq);

    return 0;
}

static int map_range_to_domain(const struct dt_device_node *dev,
                               u64 addr, u64 len,
                               void *data)
{
    struct domain *d = data;
    bool_t need_mapping = !dt_device_for_passthrough(dev);
    int res;

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

    if ( need_mapping )
    {
        res = map_mmio_regions(d,
                               paddr_to_pfn(addr),
                               DIV_ROUND_UP(len, PAGE_SIZE),
                               paddr_to_pfn(addr));
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map 0x%"PRIx64
                   " - 0x%"PRIx64" in domain %d\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + len) - 1,
                   d->domain_id);
            return res;
        }
    }

    DPRINT("  - MMIO: %010"PRIx64" - %010"PRIx64"\n", addr, addr + len);

    return 0;
}

/*
 * For a node which describes a discoverable bus (such as a PCI bus)
 * then we may need to perform additional mappings in order to make
 * the child resources available to domain 0.
 */
static int map_device_children(struct domain *d,
                               const struct dt_device_node *dev)
{
    int ret;

    if ( dt_device_type_is_equal(dev, "pci") )
    {
        DPRINT("Mapping children of %s to guest\n", dt_node_full_name(dev));

        ret = dt_for_each_irq_map(dev, &map_dt_irq_to_domain, d);
        if ( ret < 0 )
            return ret;

        ret = dt_for_each_range(dev, &map_range_to_domain, d);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * For a given device node:
 *  - Give permission to the guest to manage IRQ and MMIO range
 *  - Retrieve the IRQ configuration (i.e edge/level) from device tree
 * When the device is not marked for guest passthrough:
 *  - Assign the device to the guest if it's protected by an IOMMU
 *  - Map the IRQs and iomem regions to DOM0
 */
static int handle_device(struct domain *d, struct dt_device_node *dev)
{
    unsigned int nirq;
    unsigned int naddr;
    unsigned int i;
    int res;
    struct dt_raw_irq rirq;
    u64 addr, size;
    bool_t need_mapping = !dt_device_for_passthrough(dev);

    nirq = dt_number_of_irq(dev);
    naddr = dt_number_of_address(dev);

    DPRINT("%s passthrough = %d nirq = %d naddr = %u\n", dt_node_full_name(dev),
           need_mapping, nirq, naddr);

    if ( dt_device_is_protected(dev) && need_mapping )
    {
        DPRINT("%s setup iommu\n", dt_node_full_name(dev));
        res = iommu_assign_dt_device(d, dev);
        if ( res )
        {
            printk(XENLOG_ERR "Failed to setup the IOMMU for %s\n",
                   dt_node_full_name(dev));
            return res;
        }
    }

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
            DPRINT("irq %u not connected to primary controller."
                   "Connected to %s\n", i, dt_node_full_name(rirq.controller));
            continue;
        }

        res = platform_get_irq(dev, i);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to get irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        res = map_irq_to_domain(dev, d, res);
        if ( res )
            return res;
    }

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

        res = map_range_to_domain(dev, addr, size, d);
        if ( res )
            return res;
    }

    res = map_device_children(d, dev);
    if ( res )
        return res;

    return 0;
}

static int handle_node(struct domain *d, struct kernel_info *kinfo,
                       struct dt_device_node *node)
{
    static const struct dt_device_match skip_matches[] __initconst =
    {
        DT_MATCH_COMPATIBLE("xen,xen"),
        DT_MATCH_COMPATIBLE("xen,multiboot-module"),
        DT_MATCH_COMPATIBLE("multiboot,module"),
        DT_MATCH_COMPATIBLE("arm,psci"),
        DT_MATCH_COMPATIBLE("arm,psci-0.2"),
        DT_MATCH_COMPATIBLE("arm,cortex-a7-pmu"),
        DT_MATCH_COMPATIBLE("arm,cortex-a15-pmu"),
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
    struct dt_device_node *child;
    int res;
    const char *name;
    const char *path;

    path = dt_node_full_name(node);

    DPRINT("handle %s\n", path);

    /* Skip theses nodes and the sub-nodes */
    if ( dt_match_node(skip_matches, node) )
    {
        DPRINT("  Skip it (matched)\n");
        return 0;
    }
    if ( platform_device_is_blacklisted(node) )
    {
        DPRINT("  Skip it (blacklisted)\n");
        return 0;
    }

    /* Replace these nodes with our own. Note that the original may be
     * used_by DOMID_XEN so this check comes first. */
    if ( device_get_class(node) == DEVICE_GIC )
        return make_gic_node(d, kinfo->fdt, node);
    if ( dt_match_node(timer_matches, node) )
        return make_timer_node(d, kinfo->fdt, node);

    /* Skip nodes used by Xen */
    if ( dt_device_used_by(node) == DOMID_XEN )
    {
        DPRINT("  Skip it (used by Xen)\n");
        return 0;
    }

    /* Even if the IOMMU device is not used by Xen, it should not be
     * passthrough to DOM0
     */
    if ( device_get_class(node) == DEVICE_IOMMU )
    {
        DPRINT(" IOMMU, skip it\n");
        return 0;
    }

    res = handle_device(d, node);
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
        res = handle_node(d, kinfo, child);
        if ( res )
            return res;
    }

    if ( node == dt_host )
    {
        res = make_hypervisor_node(kinfo, node);
        if ( res )
            return res;

        res = make_psci_node(kinfo->fdt, node);
        if ( res )
            return res;

        res = make_cpus_node(d, kinfo->fdt, node);
        if ( res )
            return res;

        res = make_memory_node(d, kinfo->fdt, node, kinfo);
        if ( res )
            return res;

    }

    res = fdt_end_node(kinfo->fdt);

    return res;
}

static int prepare_dtb(struct domain *d, struct kernel_info *kinfo)
{
    const void *fdt;
    int new_size;
    int ret;

    ASSERT(dt_host && (dt_host->sibling == NULL));

    fdt = device_tree_flattened;

    new_size = fdt_totalsize(fdt) + DOM0_FDT_EXTRA_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    fdt_finish_reservemap(kinfo->fdt);

    ret = handle_node(d, kinfo, dt_host);
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

static void dtb_load(struct kernel_info *kinfo)
{
    void * __user dtb_virt = (void * __user)(register_t)kinfo->dtb_paddr;
    unsigned long left;

    printk("Loading dom0 DTB to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->dtb_paddr, kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt));

    left = raw_copy_to_guest_flush_dcache(dtb_virt, kinfo->fdt,
                                        fdt_totalsize(kinfo->fdt));
    if ( left != 0 )
        panic("Unable to copy the DTB to dom0 memory (left = %lu bytes)", left);
    xfree(kinfo->fdt);
}

static void initrd_load(struct kernel_info *kinfo)
{
    const struct bootmodule *mod = kinfo->initrd_bootmodule;
    paddr_t load_addr = kinfo->initrd_paddr;
    paddr_t paddr, len;
    unsigned long offs;
    int node;
    int res;
    __be32 val[2];
    __be32 *cellp;

    if ( !mod || !mod->size )
        return;

    paddr = mod->start;
    len = mod->size;

    printk("Loading dom0 initrd from %"PRIpaddr" to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           paddr, load_addr, load_addr + len);

    /* Fix up linux,initrd-start and linux,initrd-end in /chosen */
    node = fdt_path_offset(kinfo->fdt, "/chosen");
    if ( node < 0 )
        panic("Cannot find the /chosen node");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-start",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-start\" property");

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, ARRAY_SIZE(val), load_addr + len);
    res = fdt_setprop_inplace(kinfo->fdt, node, "linux,initrd-end",
                              val, sizeof(val));
    if ( res )
        panic("Cannot fix up \"linux,initrd-end\" property");

    for ( offs = 0; offs < len; )
    {
        int rc;
        paddr_t s, l, ma;
        void *dst;

        s = offs & ~PAGE_MASK;
        l = min(PAGE_SIZE - s, len);

        rc = gvirt_to_maddr(load_addr + offs, &ma, GV2M_WRITE);
        if ( rc )
        {
            panic("Unable to translate guest address");
            return;
        }

        dst = map_domain_page(_mfn(paddr_to_pfn(ma)));

        copy_from_paddr(dst + s, paddr + offs, l);

        unmap_domain_page(dst);
        offs += l;
    }
}

static void evtchn_fixup(struct domain *d, struct kernel_info *kinfo)
{
    int res, node;
    gic_interrupt_t intr;

    /*
     * The allocation of the event channel IRQ has been deferred until
     * now. At this time, all PPIs used by DOM0 have been registered.
     */
    res = vgic_allocate_ppi(d);
    if ( res < 0 )
        panic("Unable to allocate a PPI for the event channel interrupt\n");

    d->arch.evtchn_irq = res;

    printk("Allocating PPI %u for event channel interrupt\n",
           d->arch.evtchn_irq);

    /* Fix up "interrupts" in /hypervisor node */
    node = fdt_path_offset(kinfo->fdt, "/hypervisor");
    if ( node < 0 )
        panic("Cannot find the /hypervisor node");

    /* Interrupt event channel upcall:
     *  - Active-low level-sensitive
     *  - All CPUs
     *
     *  TODO: Handle properly the cpumask
     */
    set_interrupt_ppi(intr, d->arch.evtchn_irq, 0xf,
                      DT_IRQ_TYPE_LEVEL_LOW);
    res = fdt_setprop_inplace(kinfo->fdt, node, "interrupts",
                              &intr, sizeof(intr));
    if ( res )
        panic("Cannot fix up \"interrupts\" property of the hypervisor node");
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
    kinfo->gnttab_size = (_etext - _stext) & PAGE_MASK;

    /* Make sure the grant table will fit in the region */
    if ( (kinfo->gnttab_size >> PAGE_SHIFT) < max_grant_frames )
        panic("Cannot find a space for the grant table region\n");

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

int construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    struct vcpu *saved_current;
    int rc, i, cpu;

    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    iommu_hwdom_init(d);

    d->max_pages = ~0U;

    kinfo.unassigned_mem = dom0_mem;

    rc = kernel_probe(&kinfo);
    if ( rc < 0 )
        return rc;

#ifdef CONFIG_ARM_64
    /* if aarch32 mode is not supported at EL1 do not allow 32-bit domain */
    if ( !(cpu_has_el1_32) && kinfo.type == DOMAIN_32BIT )
    {
        printk("Platform does not support 32-bit domain\n");
        return -EINVAL;
    }
    d->arch.type = kinfo.type;
#endif

    allocate_memory(d, &kinfo);
    find_gnttab_region(d, &kinfo);

    rc = prepare_dtb(d, &kinfo);
    if ( rc < 0 )
        return rc;

    rc = platform_specific_mapping(d);
    if ( rc < 0 )
        return rc;

    /*
     * The following loads use the domain's p2m and require current to
     * be a vcpu of the domain, temporarily switch
     */
    saved_current = current;
    p2m_restore_state(v);
    set_current(v);

    /*
     * kernel_load will determine the placement of the kernel as well
     * as the initrd & fdt in RAM, so call it first.
     */
    kernel_load(&kinfo);
    /* initrd_load will fix up the fdt, so call it before dtb_load */
    initrd_load(&kinfo);
    /* Allocate the event channel IRQ and fix up the device tree */
    evtchn_fixup(d, &kinfo);
    dtb_load(&kinfo);

    /* Now that we are done restore the original p2m and current. */
    set_current(saved_current);
    p2m_restore_state(saved_current);

    discard_initial_modules();

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    memset(regs, 0, sizeof(*regs));

    regs->pc = (register_t)kinfo.entry;

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
        regs->r2 = kinfo.dtb_paddr;
    }
#ifdef CONFIG_ARM_64
    else
    {
        regs->cpsr = PSR_GUEST64_INIT;
        /* From linux/Documentation/arm64/booting.txt */
        regs->x0 = kinfo.dtb_paddr;
        regs->x1 = 0; /* Reserved for future use */
        regs->x2 = 0; /* Reserved for future use */
        regs->x3 = 0; /* Reserved for future use */
    }
#endif

    for ( i = 1, cpu = 0; i < d->max_vcpus; i++ )
    {
        cpu = cpumask_cycle(cpu, &cpu_online_map);
        if ( alloc_vcpu(d, i, cpu) == NULL )
        {
            printk("Failed to allocate dom0 vcpu %d on pcpu %d\n", i, cpu);
            break;
        }
    }

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
