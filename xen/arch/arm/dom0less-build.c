/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/err.h>
#include <xen/event.h>
#include <xen/grant_table.h>
#include <xen/iocap.h>
#include <xen/libfdt/libfdt.h>
#include <xen/llc-coloring.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/sizes.h>
#include <xen/static-memory.h>
#include <xen/vmap.h>

#include <public/bootfdt.h>
#include <public/io/xs_wire.h>

#include <asm/arm64/sve.h>
#include <asm/dom0less-build.h>
#include <asm/domain_build.h>
#include <asm/grant_table.h>
#include <asm/setup.h>
#include <asm/static-shmem.h>

#ifdef CONFIG_VGICV2
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

    res = fdt_property_cell(fdt, "linux,phandle", kinfo->phandle_intc);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_intc);
    if (res)
        return res;

    res = fdt_end_node(fdt);

    return res;
}
#endif

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

    res = fdt_property_cell(fdt, "#redistributor-regions",
                            d->arch.vgic.nr_regions);
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

    res = fdt_property_cell(fdt, "linux,phandle", kinfo->phandle_intc);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_intc);
    if (res)
        return res;

    res = fdt_end_node(fdt);

    return res;
}
#endif

int __init make_intc_domU_node(struct kernel_info *kinfo)
{
    switch ( kinfo->d->arch.vgic.version )
    {
#ifdef CONFIG_GICV3
    case GIC_V3:
        return make_gicv3_domU_node(kinfo);
#endif
#ifdef CONFIG_VGICV2
    case GIC_V2:
        return make_gicv2_domU_node(kinfo);
#endif
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
                            kinfo->phandle_intc);
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

int __init make_arch_nodes(struct kernel_info *kinfo)
{
    int ret;

    ret = make_psci_node(kinfo->fdt);
    if ( ret )
        return -EINVAL;

    if ( kinfo->arch.vpl011 )
    {
#ifdef CONFIG_SBSA_VUART_CONSOLE
        ret = make_vpl011_uart_node(kinfo);
#endif
        if ( ret )
            return -EINVAL;
    }

    return 0;
}

/* TODO: make arch.type generic ? */
#ifdef CONFIG_ARM_64
void __init set_domain_type(struct domain *d, struct kernel_info *kinfo)
{
    /* type must be set before allocate memory */
    d->arch.type = kinfo->arch.type;
}
#else
void __init set_domain_type(struct domain *d, struct kernel_info *kinfo)
{
    /* Nothing to do */
}
#endif

int __init init_vuart(struct domain *d, struct kernel_info *kinfo,
                      const struct dt_device_node *node)
{
    int rc = 0;

    kinfo->arch.vpl011 = dt_property_read_bool(node, "vpl011");

    /*
     * Base address and irq number are needed when creating vpl011 device
     * tree node in prepare_dtb_domU, so initialization on related variables
     * shall be done first.
     */
    if ( kinfo->arch.vpl011 )
    {
        rc = domain_vpl011_init(d, NULL);
        if ( rc < 0 )
            return rc;
    }

    return rc;
}

void __init arch_create_domUs(struct dt_device_node *node,
                       struct xen_domctl_createdomain *d_cfg,
                       unsigned int flags)
{
    uint32_t val;

    d_cfg->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_NATIVE;
    d_cfg->flags |= XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap;

    if ( !dt_property_read_u32(node, "nr_spis", &d_cfg->arch.nr_spis) )
    {
        int vpl011_virq = GUEST_VPL011_SPI;

        d_cfg->arch.nr_spis = VGIC_DEF_NR_SPIS;

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
            d_cfg->arch.nr_spis = MAX(d_cfg->arch.nr_spis,
                                      vpl011_virq - 32 + 1);
    }
    else if ( flags & CDF_hardware )
        panic("nr_spis cannot be specified for hardware domain\n");

    if ( dt_get_property(node, "sve", &val) )
    {
#ifdef CONFIG_ARM64_SVE
        unsigned int sve_vl_bits;
        bool ret = false;

        if ( !val )
        {
            /* Property found with no value, means max HW VL supported */
            ret = sve_domctl_vl_param(-1, &sve_vl_bits);
        }
        else
        {
            if ( dt_property_read_u32(node, "sve", &val) )
                ret = sve_domctl_vl_param(val, &sve_vl_bits);
            else
                panic("Error reading 'sve' property\n");
        }

        if ( ret )
            d_cfg->arch.sve_vl = sve_encode_vl(sve_vl_bits);
        else
            panic("SVE vector length error\n");
#else
        panic("'sve' property found, but CONFIG_ARM64_SVE not selected\n");
#endif
    }
}

int __init init_intc_phandle(struct kernel_info *kinfo, const char *name,
                             const int node_next, const void *pfdt)
{
    if ( dt_node_cmp(name, "gic") == 0 )
    {
        uint32_t phandle_intc = fdt_get_phandle(pfdt, node_next);

        if ( phandle_intc != 0 )
            kinfo->phandle_intc = phandle_intc;

        return 0;
    }

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
