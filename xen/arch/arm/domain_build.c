#include <xen/config.h>
#include <xen/init.h>
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

#include "gic.h"
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

/*
 * Amount of extra space required to dom0's device tree.  No new nodes
 * are added (yet) but one terminating reserve map entry (16 bytes) is
 * added.
 */
#define DOM0_FDT_EXTRA_SIZE (sizeof(struct fdt_reserve_entry))

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

static int set_memory_reg(struct domain *d, struct kernel_info *kinfo,
                          const void *fdt, const u32 *cell, int len,
                          int address_cells, int size_cells, u32 *new_cell)
{
    int reg_size = (address_cells + size_cells) * sizeof(*cell);
    int l = 0;
    u64 start;
    u64 size;

    while ( kinfo->unassigned_mem > 0 && l + reg_size <= len
            && kinfo->mem.nr_banks < NR_MEM_BANKS )
    {
        device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
        if ( size > kinfo->unassigned_mem )
            size = kinfo->unassigned_mem;
        device_tree_set_reg(&new_cell, address_cells, size_cells, start, size);

        printk("Populate P2M %#llx->%#llx\n", start, start + size);
        p2m_populate_ram(d, start, start + size);
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
    int prop;

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
         * In chosen node: replace bootargs with value from
         * xen,dom0-bootargs.
         */
        if ( device_tree_node_matches(fdt, node, "chosen") )
        {
            if ( strcmp(prop_name, "bootargs") == 0 )
                continue;
            if ( strcmp(prop_name, "xen,dom0-bootargs") == 0 )
                prop_name = "bootargs";
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

    if ( prop == -FDT_ERR_NOTFOUND )
        return 0;
    return prop;
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
          node = fdt_next_node(fdt, node, &depth) )
    {
        const char *name;

        name = fdt_get_name(fdt, node, NULL);

        if ( depth >= DEVICE_TREE_MAX_DEPTH )
        {
            printk("warning: node `%s' is nested too deep\n", name);
            continue;
        }

        while ( last_depth-- >= depth )
            fdt_end_node(kinfo->fdt);

        address_cells[depth] = device_tree_get_u32(fdt, node, "#address-cells");
        size_cells[depth] = device_tree_get_u32(fdt, node, "#size-cells");

        fdt_begin_node(kinfo->fdt, name);

        ret = write_properties(d, kinfo, fdt, node, name, depth,
                               address_cells[depth-1], size_cells[depth-1]);
        if ( ret < 0 )
            return ret;

        last_depth = depth;
    }

    while ( last_depth-- >= 0 )
        fdt_end_node(kinfo->fdt);

    return 0;
}

static int prepare_dtb(struct domain *d, struct kernel_info *kinfo)
{
    void *fdt;
    int new_size;
    int ret;

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
     * Put the device tree at the beginning of the first bank.  It
     * must be below 4 GiB.
     */
    kinfo->dtb_paddr = kinfo->mem.bank[0].start + 0x100;
    if ( kinfo->dtb_paddr + fdt_totalsize(kinfo->fdt) > (1ull << 32) )
    {
        printk("Not enough memory below 4 GiB for the device tree.");
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
    void * __user dtb_virt = (void *)(u32)kinfo->dtb_paddr;

    raw_copy_to_guest(dtb_virt, kinfo->fdt, fdt_totalsize(kinfo->fdt));
    xfree(kinfo->fdt);
}

int construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    int rc;

    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    d->max_pages = ~0U;

    if ( (rc = p2m_alloc_table(d)) != 0 )
        return rc;

    rc = prepare_dtb(d, &kinfo);
    if ( rc < 0 )
        return rc;

    rc = kernel_prepare(&kinfo);
    if ( rc < 0 )
        return rc;

    printk("Map CS2 MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x18000000ULL, 0x1BFFFFFFULL);
    map_mmio_regions(d, 0x18000000, 0x1BFFFFFF, 0x18000000);
    printk("Map CS3 MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x1C000000ULL, 0x1FFFFFFFULL);
    map_mmio_regions(d, 0x1C000000, 0x1FFFFFFF, 0x1C000000);
    printk("Map VGIC MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x2C008000ULL, 0x2DFFFFFFULL);
    map_mmio_regions(d, 0x2C008000, 0x2DFFFFFF, 0x2C008000);

    gicv_setup(d);

    printk("Routing peripheral interrupts to guest\n");
    /* TODO Get from device tree */
    gic_route_irq_to_guest(d, 34, "timer0");
    /*gic_route_irq_to_guest(d, 37, "uart0"); -- XXX used by Xen*/
    gic_route_irq_to_guest(d, 38, "uart1");
    gic_route_irq_to_guest(d, 39, "uart2");
    gic_route_irq_to_guest(d, 40, "uart3");
    gic_route_irq_to_guest(d, 41, "mmc0-1");
    gic_route_irq_to_guest(d, 42, "mmc0-2");
    gic_route_irq_to_guest(d, 44, "keyboard");
    gic_route_irq_to_guest(d, 45, "mouse");
    gic_route_irq_to_guest(d, 46, "lcd");
    gic_route_irq_to_guest(d, 47, "eth");

    /* Enable second stage translation */
    WRITE_CP32(READ_CP32(HCR) | HCR_VM, HCR); isb();

    /* The following loads use the domain's p2m */
    p2m_load_VTTBR(d);

    dtb_load(&kinfo);
    kernel_load(&kinfo);

    clear_bit(_VPF_down, &v->pause_flags);

    memset(regs, 0, sizeof(*regs));

    regs->pc = (uint32_t)kinfo.entry;

    regs->cpsr = PSR_ABT_MASK|PSR_FIQ_MASK|PSR_IRQ_MASK|PSR_MODE_SVC;

/* FROM LINUX head.S

 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *...
 */

    regs->r0 = 0; /* SBZ */
    regs->r1 = 2272; /* Machine NR: Versatile Express */
    regs->r2 = kinfo.dtb_paddr;

    WRITE_CP32(SCTLR_BASE, SCTLR);

    WRITE_CP32(HCR_AMO|HCR_IMO|HCR_VM, HCR);
    isb();

    local_abort_enable();

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
