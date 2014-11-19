/*
 * xen/arch/arm/platforms/xgene-storm.c
 *
 * Applied Micro's X-Gene specific settings
 *
 * Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
 * Anup Patel <apatel@apm.com>
 * Copyright (c) 2013 Applied Micro.
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
#include <asm/platform.h>
#include <xen/stdbool.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/gic.h>

/* XGENE RESET Specific defines */
#define XGENE_RESET_ADDR        0x17000014UL
#define XGENE_RESET_SIZE        0x100
#define XGENE_RESET_MASK        0x1

/* Variables to save reset address of soc during platform initialization. */
static u64 reset_addr, reset_size;
static u32 reset_mask;
static bool reset_vals_valid = false;

static uint32_t xgene_storm_quirks(void)
{
    return PLATFORM_QUIRK_GIC_64K_STRIDE|PLATFORM_QUIRK_GUEST_PIRQ_NEED_EOI;
}

static int map_one_mmio(struct domain *d, const char *what,
                         unsigned long start, unsigned long end)
{
    int ret;

    printk("Additional MMIO %lx-%lx (%s)\n",
           start, end, what);
    ret = map_mmio_regions(d, start, end - start, start);
    if ( ret )
        printk("Failed to map %s @ %lx to dom%d\n",
               what, start, d->domain_id);
    return ret;
}

static int map_one_spi(struct domain *d, const char *what,
                       unsigned int spi, unsigned int type)
{
    unsigned int irq;
    int ret;

    irq = spi + 32; /* SPIs start at IRQ 32 */

    ret = irq_set_spi_type(irq, type);
    if ( ret )
    {
        printk("Failed to set the type for IRQ%u\n", irq);
        return ret;
    }

    printk("Additional IRQ %u (%s)\n", irq, what);

    ret = route_irq_to_guest(d, irq, what);
    if ( ret )
        printk("Failed to route %s to dom%d\n", what, d->domain_id);

    return ret;
}

/* Creates MMIO mappings base..end as well as 4 SPIs from the given base. */
static int xgene_storm_pcie_specific_mapping(struct domain *d,
                                             const struct dt_device_node *node,
                                             paddr_t base, paddr_t end,
                                             int base_spi)
{
    int ret;

    printk("Mapping additional regions for PCIe device %s\n",
           dt_node_full_name(node));

    /* Map the PCIe bus resources */
    ret = map_one_mmio(d, "PCI MEMORY", paddr_to_pfn(base), paddr_to_pfn(end));
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTA", base_spi+0, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTB", base_spi+1, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTC", base_spi+2, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTD", base_spi+3, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = 0;
err:
    return ret;
}

/*
 * Xen does not currently support mapping MMIO regions and interrupt
 * for bus child devices (referenced via the "ranges" and
 * "interrupt-map" properties to domain 0). Instead for now map the
 * necessary resources manually.
 */
static int xgene_storm_specific_mapping(struct domain *d)
{
    struct dt_device_node *node = NULL;
    int ret;

    while ( (node = dt_find_compatible_node(node, "pci", "apm,xgene-pcie")) )
    {
        u64 addr;

        /* Identify the bus via it's control register address */
        ret = dt_device_get_address(node, 0, &addr, NULL);
        if ( ret < 0 )
            return ret;

        if ( !dt_device_is_available(node) )
            continue;

       switch ( addr )
        {
        case 0x1f2b0000: /* PCIe0 */
            ret = xgene_storm_pcie_specific_mapping(d,
                node,
                0x0e000000000UL, 0x10000000000UL, 0xc2);
            break;
        case 0x1f2c0000: /* PCIe1 */
            ret = xgene_storm_pcie_specific_mapping(d,
                node,
                0x0d000000000UL, 0x0e000000000UL, 0xc8);
            break;
        case 0x1f2d0000: /* PCIe2 */
            ret = xgene_storm_pcie_specific_mapping(d,
                node,
                0x09000000000UL, 0x0a000000000UL, 0xce);
            break;
        case 0x1f500000: /* PCIe3 */
            ret = xgene_storm_pcie_specific_mapping(d,
                node,
                0x0a000000000UL, 0x0c000000000UL, 0xd4);
            break;
        case 0x1f510000: /* PCIe4 */
            ret = xgene_storm_pcie_specific_mapping(d,
                node,
                0x0c000000000UL, 0x0d000000000UL, 0xda);
            break;

        default:
            printk("Ignoring unknown PCI bus %s\n", dt_node_full_name(node));
            continue;
        }

        if ( ret < 0 )
            return ret;
    }

    return 0;
}

static void xgene_storm_reset(void)
{
    void __iomem *addr;

    if ( !reset_vals_valid )
    {
        printk("XGENE: Invalid reset values, can not reset XGENE...\n");
        return;
    }

    addr = ioremap_nocache(reset_addr, reset_size);

    if ( !addr )
    {
        printk("XGENE: Unable to map xgene reset address, can not reset XGENE...\n");
        return;
    }

    /* Write reset mask to base address */
    writel(reset_mask, addr);

    iounmap(addr);
}

static int xgene_storm_init(void)
{
    /* TBD: Once Linux side device tree bindings are finalized retrieve
     * these values from dts.
     */
    reset_addr = XGENE_RESET_ADDR;
    reset_size = XGENE_RESET_SIZE;
    reset_mask = XGENE_RESET_MASK;

    reset_vals_valid = true;
    return 0;
}

static const char * const xgene_storm_dt_compat[] __initconst =
{
    "apm,xgene-storm",
    NULL
};

PLATFORM_START(xgene_storm, "APM X-GENE STORM")
    .compatible = xgene_storm_dt_compat,
    .init = xgene_storm_init,
    .reset = xgene_storm_reset,
    .quirks = xgene_storm_quirks,
    .specific_mapping = xgene_storm_specific_mapping,

    .dom0_evtchn_ppi = 24,
    .dom0_gnttab_start = 0x1f800000,
    .dom0_gnttab_size = 0x20000,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
