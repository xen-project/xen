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

/* Variables to save reset address of soc during platform initialization. */
static u64 reset_addr, reset_size;
static u32 reset_mask;
static bool reset_vals_valid = false;

static uint32_t xgene_storm_quirks(void)
{
    return PLATFORM_QUIRK_GIC_64K_STRIDE;
}

static int map_one_mmio(struct domain *d, const char *what,
                         paddr_t start, paddr_t end)
{
    int ret;

    printk("Additional MMIO %"PRIpaddr"-%"PRIpaddr" (%s)\n",
           start, end, what);
    ret = map_mmio_regions(d, start, end, start);
    if ( ret )
        printk("Failed to map %s @ %"PRIpaddr" to dom%d\n",
               what, start, d->domain_id);
    return ret;
}

static int map_one_spi(struct domain *d, const char *what,
                       unsigned int spi, unsigned int type)
{
    struct dt_irq irq;
    int ret;

    irq.type = type;

    irq.irq = spi + 32; /* SPIs start at IRQ 32 */

    printk("Additional IRQ %u (%s)\n", irq.irq, what);

    ret = gic_route_irq_to_guest(d, &irq, what);
    if ( ret )
        printk("Failed to route %s to dom%d\n", what, d->domain_id);

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
    int ret;

    /* Map the PCIe bus resources */
    ret = map_one_mmio(d, "PCI MEM REGION", 0xe000000000UL, 0xe010000000UL);
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "PCI IO REGION", 0xe080000000UL, 0xe080010000UL);
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "PCI CFG REGION", 0xe0d0000000UL, 0xe0d0200000UL);
    if ( ret )
        goto err;
    ret = map_one_mmio(d, "PCI MSI REGION", 0xe010000000UL, 0xe010800000UL);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTA", 0xc2, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTB", 0xc3, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTC", 0xc4, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "PCI#INTD", 0xc5, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = 0;
err:
    return ret;
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
    static const struct dt_device_match reset_ids[] __initconst =
    {
        DT_MATCH_COMPATIBLE("apm,xgene-reboot"),
        {},
    };
    struct dt_device_node *dev;
    int res;

    dev = dt_find_matching_node(NULL, reset_ids);
    if ( !dev )
    {
        printk("XGENE: Unable to find a compatible reset node in the device tree");
        return 0;
    }

    dt_device_set_used_by(dev, DOMID_XEN);

    /* Retrieve base address and size */
    res = dt_device_get_address(dev, 0, &reset_addr, &reset_size);
    if ( res )
    {
        printk("XGENE: Unable to retrieve the base address for reset\n");
        return 0;
    }

    /* Get reset mask */
    res = dt_property_read_u32(dev, "mask", &reset_mask);
    if ( !res )
    {
        printk("XGENE: Unable to retrieve the reset mask\n");
        return 0;
    }

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
