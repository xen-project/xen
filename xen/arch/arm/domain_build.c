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
#include <asm/setup.h>
#include <asm/platform.h>

#include <asm/gic.h>
#include <xen/irq.h>
#include "kernel.h"

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

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

/*
 * Amount of extra space required to dom0's device tree.  No new nodes
 * are added (yet) but one terminating reserve map entry (16 bytes) is
 * added.
 */
#define DOM0_FDT_EXTRA_SIZE (128 + sizeof(struct fdt_reserve_entry))

struct vcpu *__init alloc_dom0_vcpu0(void)
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

static int set_memory_reg_11(struct domain *d, struct kernel_info *kinfo,
                             const void *fdt, const u32 *cell, int len,
                             int address_cells, int size_cells, u32 *new_cell)
{
    int reg_size = (address_cells + size_cells) * sizeof(*cell);
    paddr_t start;
    paddr_t size;
    struct page_info *pg;
    unsigned int order = get_order_from_bytes(dom0_mem);
    int res;
    paddr_t spfn;

    pg = alloc_domheap_pages(d, order, 0);
    if ( !pg )
        panic("Failed to allocate contiguous memory for dom0\n");

    spfn = page_to_mfn(pg);
    start = spfn << PAGE_SHIFT;
    size = (1 << order) << PAGE_SHIFT;

    // 1:1 mapping
    printk("Populate P2M %#"PRIx64"->%#"PRIx64" (1:1 mapping for dom0)\n",
           start, start + size);
    res = guest_physmap_add_page(d, spfn, spfn, order);

    if ( res )
        panic("Unable to add pages in DOM0: %d\n", res);

    device_tree_set_reg(&new_cell, address_cells, size_cells, start, size);

    kinfo->mem.bank[0].start = start;
    kinfo->mem.bank[0].size = size;
    kinfo->mem.nr_banks = 1;

    return reg_size;
}

static int set_memory_reg(struct domain *d, struct kernel_info *kinfo,
                          const void *fdt, const u32 *cell, int len,
                          int address_cells, int size_cells, u32 *new_cell)
{
    int reg_size = (address_cells + size_cells) * sizeof(*cell);
    int l = 0;
    u64 start;
    u64 size;

    if ( platform_has_quirk(PLATFORM_QUIRK_DOM0_MAPPING_11) )
        return set_memory_reg_11(d, kinfo, fdt, cell, len, address_cells,
                                 size_cells, new_cell);

    while ( kinfo->unassigned_mem > 0 && l + reg_size <= len
            && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
        if ( size > kinfo->unassigned_mem )
            size = kinfo->unassigned_mem;
        device_tree_set_reg(&new_cell, address_cells, size_cells, start, size);

        printk("Populate P2M %#"PRIx64"->%#"PRIx64"\n", start, start + size);
        if ( p2m_populate_ram(d, start, start + size) < 0 )
            panic("Failed to populate P2M\n");
        kinfo->mem.bank[kinfo->mem.nr_banks].start = start;
        kinfo->mem.bank[kinfo->mem.nr_banks].size = size;
        kinfo->mem.nr_banks++;
        kinfo->unassigned_mem -= size;

        l += reg_size;
    }

    return l;
}

static int write_properties(struct domain *d, struct kernel_info *kinfo,
                            const void *fdt,
                            int node, const char *name, int depth,
                            u32 address_cells, u32 size_cells)
{
    const char *bootargs = NULL;
    int prop;

    if ( early_info.modules.nr_mods >= MOD_KERNEL &&
         early_info.modules.module[MOD_KERNEL].cmdline[0] )
        bootargs = &early_info.modules.module[MOD_KERNEL].cmdline[0];

    for ( prop = fdt_first_property_offset(fdt, node);
          prop >= 0;
          prop = fdt_next_property_offset(fdt, prop) )
    {
        const struct fdt_property *p;
        const char *prop_name;
        const char *prop_data;
        int prop_len;
        char *new_data = NULL;

        p = fdt_get_property_by_offset(fdt, prop, NULL);
        prop_name = fdt_string(fdt, fdt32_to_cpu(p->nameoff));
        prop_data = p->data;
        prop_len  = fdt32_to_cpu(p->len);

        /*
         * In chosen node:
         *
         * * remember xen,dom0-bootargs if we don't already have
         *   bootargs (from module #1, above).
         * * remove bootargs and xen,dom0-bootargs.
         */
        if ( device_tree_node_matches(fdt, node, "chosen") )
        {
            if ( strcmp(prop_name, "bootargs") == 0 )
                continue;
            else if ( strcmp(prop_name, "xen,dom0-bootargs") == 0 )
            {
                if ( !bootargs )
                    bootargs = prop_data;
                continue;
            }
        }
        /*
         * In a memory node: adjust reg property.
         */
        else if ( device_tree_node_matches(fdt, node, "memory") )
        {
            if ( strcmp(prop_name, "reg") == 0 )
            {
                new_data = xzalloc_bytes(prop_len);
                if ( new_data  == NULL )
                    return -FDT_ERR_XEN(ENOMEM);

                prop_len = set_memory_reg(d, kinfo, fdt,
                                          (u32 *)prop_data, prop_len,
                                          address_cells, size_cells,
                                          (u32 *)new_data);
                prop_data = new_data;
            }
        }

        /*
         * TODO: Should call map_mmio_regions() for all devices in the
         * tree that have a "reg" parameter (except cpus).  This
         * requires looking into the parent node's "ranges" property
         * to translate the bus address in the "reg" value into
         * physical addresses.  Regions also need to be rounded up to
         * whole pages.
         */

        fdt_property(kinfo->fdt, prop_name, prop_data, prop_len);

        xfree(new_data);
    }

    if ( device_tree_node_matches(fdt, node, "chosen") && bootargs )
        fdt_property(kinfo->fdt, "bootargs", bootargs, strlen(bootargs) + 1);

    /*
     * XXX should populate /chosen/linux,initrd-{start,end} here if we
     * have module[2]
     */

    if ( prop == -FDT_ERR_NOTFOUND )
        return 0;
    return prop;
}

/* Returns the next node in fdt (starting from offset) which should be
 * passed through to dom0.
 */
static int fdt_next_dom0_node(const void *fdt, int node,
                              int *depth_out)
{
    int depth = *depth_out;

    while ( (node = fdt_next_node(fdt, node, &depth)) &&
            node >= 0 && depth >= 0 )
    {
        if ( depth >= DEVICE_TREE_MAX_DEPTH )
            break;

        /* Skip /hypervisor/ node. We will inject our own. */
        if ( fdt_node_check_compatible(fdt, node, "xen,xen" ) == 0 )
        {
            printk("Device-tree contains \"xen,xen\" node. Ignoring.\n");
            continue;
        }

        /* Skip multiboot subnodes */
        if ( fdt_node_check_compatible(fdt, node,
                                       "xen,multiboot-module" ) == 0 )
            continue;

        /* We've arrived at a node which dom0 is interested in. */
        break;
    }

    *depth_out = depth;
    return node;
}

static void make_hypervisor_node(void *fdt, int addrcells, int sizecells)
{
    const char compat[] =
        "xen,xen-"__stringify(XEN_VERSION)"."__stringify(XEN_SUBVERSION)"\0"
        "xen,xen";
    u32 reg[4];
    u32 intr[3];
    u32 *cell;

    /*
     * Sanity-check address sizes, since addresses and sizes which do
     * not take up exactly 4 or 8 bytes are not supported.
     */
    if ((addrcells != 1 && addrcells != 2) ||
        (sizecells != 1 && sizecells != 2))
        panic("Cannot cope with this size");

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    fdt_begin_node(fdt, "hypervisor");

    /* Cannot use fdt_property_string due to embedded nulls */
    fdt_property(fdt, "compatible", compat, sizeof(compat));

    /* reg 0 is grant table space */
    cell = &reg[0];
    device_tree_set_reg(&cell, addrcells, sizecells, 0xb0000000, 0x20000);
    fdt_property(fdt, "reg", reg,
                 sizeof(reg[0]) * (addrcells + sizecells));

    /*
     * interrupts is evtchn upcall  <1 15 0xf08>
     * See linux Documentation/devicetree/bindings/arm/gic.txt
     */
    intr[0] = cpu_to_fdt32(1); /* is a PPI */
    intr[1] = cpu_to_fdt32(VGIC_IRQ_EVTCHN_CALLBACK - 16); /* PPIs start at 16 */
    intr[2] = cpu_to_fdt32(0xf08); /* Active-low level-sensitive */

    fdt_property(fdt, "interrupts", intr, sizeof(intr[0]) * 3);

    fdt_end_node(fdt);
}

static int write_nodes(struct domain *d, struct kernel_info *kinfo,
                       const void *fdt)
{
    int node;
    int depth = 0, last_depth = -1;
    u32 address_cells[DEVICE_TREE_MAX_DEPTH];
    u32 size_cells[DEVICE_TREE_MAX_DEPTH];
    int ret;

    for ( node = 0, depth = 0;
          node >= 0 && depth >= 0;
          node = fdt_next_dom0_node(fdt, node, &depth) )
    {
        const char *name;

        name = fdt_get_name(fdt, node, NULL);

        if ( depth >= DEVICE_TREE_MAX_DEPTH )
        {
            printk("warning: node `%s' is nested too deep (%d)\n",
                   name, depth);
            continue;
        }

        /* We cannot handle descending more than one level at a time */
        ASSERT( depth <= last_depth + 1 );

        while ( last_depth-- >= depth )
            fdt_end_node(kinfo->fdt);

        address_cells[depth] = device_tree_get_u32(fdt, node, "#address-cells",
                                    depth > 0 ? address_cells[depth-1] : 0);
        size_cells[depth] = device_tree_get_u32(fdt, node, "#size-cells",
                                    depth > 0 ? size_cells[depth-1] : 0);

        fdt_begin_node(kinfo->fdt, name);

        ret = write_properties(d, kinfo, fdt, node, name, depth,
                               address_cells[depth-1], size_cells[depth-1]);
        if ( ret < 0 )
            return ret;

        last_depth = depth;
    }

    while ( last_depth-- >= 1 )
        fdt_end_node(kinfo->fdt);

    make_hypervisor_node(kinfo->fdt, address_cells[0], size_cells[0]);

    fdt_end_node(kinfo->fdt);
    return 0;
}

/* Map the device in the domain */
static int map_device(struct domain *d, const struct dt_device_node *dev)
{
    unsigned int nirq;
    unsigned int naddr;
    unsigned int i;
    int res;
    struct dt_irq irq;
    struct dt_raw_irq rirq;
    u64 addr, size;

    nirq = dt_number_of_irq(dev);
    naddr = dt_number_of_address(dev);

    DPRINT("%s nirq = %d naddr = %u\n", dt_node_full_name(dev), nirq, naddr);

    /* Map IRQs */
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

        res = dt_irq_translate(&rirq, &irq);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to translate irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        DPRINT("irq %u = %u type = 0x%x\n", i, irq.irq, irq.type);
        /* Don't check return because the IRQ can be use by multiple device */
        gic_route_irq_to_guest(d, &irq, dt_node_name(dev));
    }

    /* Map the address ranges */
    for ( i = 0; i < naddr; i++ )
    {
        res = dt_device_get_address(dev, i, &addr, &size);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve address %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        DPRINT("addr %u = 0x%"PRIx64" - 0x%"PRIx64"\n",
               i, addr, addr + size - 1);

        res = map_mmio_regions(d, addr & PAGE_MASK,
                               PAGE_ALIGN(addr + size) - 1,
                               addr & PAGE_MASK);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to map 0x%"PRIx64
                   " - 0x%"PRIx64" in dom0\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + size) - 1);
            return res;
        }
    }

    return 0;
}

static int handle_node(struct domain *d, const struct dt_device_node *np)
{
    const struct dt_device_node *child;
    int res;

    DPRINT("handle %s\n", dt_node_full_name(np));

    /* Skip theses nodes and the sub-nodes */
    if ( dt_device_is_compatible(np, "xen,xen") ||
         dt_device_type_is_equal(np, "memory") ||
         !strcmp("/chosen", dt_node_full_name(np)) )
        return 0;

    if ( dt_device_used_by(np) != DOMID_XEN )
    {
        res = map_device(d, np);

        if ( res )
            return res;
    }

    for ( child = np->child; child != NULL; child = child->sibling )
    {
        res = handle_node(d, child);
        if ( res )
            return res;
    }

    return 0;
}

static int map_devices_from_device_tree(struct domain *d)
{
    ASSERT(dt_host && (dt_host->sibling == NULL));

    return handle_node(d, dt_host);
}

static int prepare_dtb(struct domain *d, struct kernel_info *kinfo)
{
    void *fdt;
    int new_size;
    int ret;
    paddr_t end;

    kinfo->unassigned_mem = dom0_mem;

    fdt = device_tree_flattened;

    new_size = fdt_totalsize(fdt) + DOM0_FDT_EXTRA_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    fdt_finish_reservemap(kinfo->fdt);

    ret = write_nodes(d, kinfo, fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    /*
     * DTB must be load below 4GiB and far enough from linux (Linux uses
     * the space after it to decompress)
     * Load the DTB at the end of the first bank, while ensuring it is
     * also below 4G
     */
    end = kinfo->mem.bank[0].start + kinfo->mem.bank[0].size;
    end = MIN(1ull << 32, end);
    kinfo->dtb_paddr = end - fdt_totalsize(kinfo->fdt);
    /* Align the address to 2Mb. Linux only requires 4 byte alignment */
    kinfo->dtb_paddr &= ~((2 << 20) - 1);

    if ( fdt_totalsize(kinfo->fdt) > end )
    {
        printk(XENLOG_ERR "Not enough memory in the first bank for "
               "the device tree.");
        ret = -FDT_ERR_XEN(EINVAL);
        goto err;
    }


    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);
    return -EINVAL;
}

static void dtb_load(struct kernel_info *kinfo)
{
    void * __user dtb_virt = (void * __user)(register_t)kinfo->dtb_paddr;
    unsigned long rc;

    printk("Loading dom0 DTB to 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
           kinfo->dtb_paddr, kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt));

    rc = raw_copy_to_guest(dtb_virt, kinfo->fdt, fdt_totalsize(kinfo->fdt));
    if ( rc != 0 )
        panic("Unable to copy the DTB to dom0 memory (rc = %lu)\n", rc);
    xfree(kinfo->fdt);
}

int construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    int rc, i, cpu;

    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    d->max_pages = ~0U;

    rc = prepare_dtb(d, &kinfo);
    if ( rc < 0 )
        return rc;

    rc = kernel_prepare(&kinfo);
    if ( rc < 0 )
        return rc;

    map_devices_from_device_tree(d);
    rc = platform_specific_mapping(d);
    if ( rc < 0 )
        return rc;

    if ( kinfo.check_overlap )
        kinfo.check_overlap(&kinfo);

    /* The following loads use the domain's p2m */
    p2m_load_VTTBR(d);

    kernel_load(&kinfo);
    dtb_load(&kinfo);

    discard_initial_modules();

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    memset(regs, 0, sizeof(*regs));

    regs->pc = (register_t)kinfo.entry;

#ifdef CONFIG_ARM_64
    d->arch.type = kinfo.type;
#endif

    if ( is_pv32_domain(d) )
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
