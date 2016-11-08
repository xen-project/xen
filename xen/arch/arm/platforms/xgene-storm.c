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
#include <xen/vmap.h>
#include <xen/device_tree.h>
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

#define XGENE_SEC_GICV2_DIST_ADDR    0x78010000

static void __init xgene_check_pirq_eoi(void)
{
    const struct dt_device_node *node;
    int res;
    paddr_t dbase;
    const struct dt_device_match xgene_dt_int_ctrl_match[] =
    {
        DT_MATCH_COMPATIBLE("arm,cortex-a15-gic"),
        { /*sentinel*/ },
    };

    node = dt_find_interrupt_controller(xgene_dt_int_ctrl_match);
    if ( !node )
        panic("%s: Can not find interrupt controller node", __func__);

    res = dt_device_get_address(node, 0, &dbase, NULL);
    if ( !dbase )
        panic("%s: Cannot find a valid address for the distributor", __func__);

    /*
     * In old X-Gene Storm firmware and DT, secure mode addresses have
     * been mentioned in GICv2 node. EOI HW won't work in this case.
     * We check the GIC Distributor Base Address to deny Xen booting
     * with older firmware.
     */
    if ( dbase == XGENE_SEC_GICV2_DIST_ADDR )
        panic("OLD X-Gene Firmware is not supported by Xen.\n"
              "Please upgrade your firmware to the latest version");
}

static uint32_t xgene_storm_quirks(void)
{
    return PLATFORM_QUIRK_GIC_64K_STRIDE;
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
    xgene_check_pirq_eoi();

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
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
