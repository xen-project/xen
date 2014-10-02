/*
 * xen/arch/arm/platforms/brcm.c
 *
 * Broadcom Platform startup.
 *
 * Jon Fraser  <jfraser@broadcom.com>
 * Copyright (c) 2013-2014 Broadcom Corporation
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

#include <asm/platform.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <xen/delay.h>

struct brcm_plat_regs {
    uint32_t    hif_mask;
    uint32_t    hif_cpu_reset_config;
    uint32_t    hif_boot_continuation;
    uint32_t    cpu0_pwr_zone_ctrl;
    uint32_t    scratch_reg;
};

static u32 brcm_boot_continuation_pc;

static struct brcm_plat_regs regs;

static __init int brcm_get_dt_node(char *compat_str,
                                   const struct dt_device_node **dn,
                                   u32 *reg_base)
{
    const struct dt_device_node *node;
    u64 reg_base_64;
    int rc;

    node = dt_find_compatible_node(NULL, NULL, compat_str);
    if ( !node )
    {
        dprintk(XENLOG_ERR, "%s: missing \"%s\" node\n", __func__, compat_str);
        return -ENOENT;
    }

    rc = dt_device_get_address(node, 0, &reg_base_64, NULL);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "%s: missing \"reg\" prop\n", __func__);
        return rc;
    }

    if ( dn )
        *dn = node;

    if ( reg_base )
        *reg_base = reg_base_64;

    return 0;
}

static __init int brcm_populate_plat_regs(void)
{
    int rc;
    const struct dt_device_node *node;
    u32 reg_base;
    u32 val;

    rc = brcm_get_dt_node("brcm,brcmstb-cpu-biu-ctrl", &node, &reg_base);
    if ( rc )
        return rc;

    if ( !dt_property_read_u32(node, "cpu-reset-config-reg", &val) )
    {
        dprintk(XENLOG_ERR, "Missing property \"cpu-reset-config-reg\"\n");
        return -ENOENT;
    }
    regs.hif_cpu_reset_config = reg_base + val;

    if ( !dt_property_read_u32(node, "cpu0-pwr-zone-ctrl-reg", &val) )
    {
        dprintk(XENLOG_ERR, "Missing property \"cpu0-pwr-zone-ctrl-reg\"\n");
        return -ENOENT;
    }
    regs.cpu0_pwr_zone_ctrl = reg_base + val;

    if ( !dt_property_read_u32(node, "scratch-reg", &val) )
    {
        dprintk(XENLOG_ERR, "Missing property \"scratch-reg\"\n");
        return -ENOENT;
    }
    regs.scratch_reg = reg_base + val;

    rc = brcm_get_dt_node("brcm,brcmstb-hif-continuation", NULL, &reg_base);
    if ( rc )
        return rc;

    regs.hif_boot_continuation = reg_base;

    dprintk(XENLOG_INFO, "hif_cpu_reset_config  : %08xh\n",
                    regs.hif_cpu_reset_config);
    dprintk(XENLOG_INFO, "cpu0_pwr_zone_ctrl    : %08xh\n",
                    regs.cpu0_pwr_zone_ctrl);
    dprintk(XENLOG_INFO, "hif_boot_continuation : %08xh\n",
                    regs.hif_boot_continuation);
    dprintk(XENLOG_INFO, "scratch_reg : %08xh\n",
                    regs.scratch_reg);

    return 0;
}

#define ZONE_PWR_UP_REQ   (1 << 10)
#define ZONE_PWR_ON_STATE (1 << 26)

static int brcm_cpu_power_on(int cpu)
{
    u32 tmp;
    void __iomem *pwr_ctl;
    unsigned int timeout;

    dprintk(XENLOG_ERR, "%s: Power on cpu %d\n", __func__, cpu);

    pwr_ctl = ioremap_nocache(regs.cpu0_pwr_zone_ctrl + (cpu * sizeof(u32)),
                              sizeof(u32));

    if ( !pwr_ctl )
    {
        dprintk(XENLOG_ERR, "%s: Unable to map \"cpu0_pwr_zone_ctrl\"\n",
                        __func__);
        return -EFAULT;
    }

    /* request core power on */
    tmp = readl(pwr_ctl);
    tmp |= ZONE_PWR_UP_REQ;
    writel(tmp, pwr_ctl);

    /*
     * Wait for the cpu to power on.
     * Wait a max of 10 msec.
     */
    timeout = 10;
    tmp = readl(pwr_ctl);

    while ( !(tmp & ZONE_PWR_ON_STATE) )
    {
        if ( timeout-- == 0 )
            break;

        mdelay(1);
        tmp = readl(pwr_ctl);
    }

    iounmap(pwr_ctl);

    if ( timeout == 0 )
    {
        dprintk(XENLOG_ERR, "CPU%d power enable failed", cpu);
        return -ETIMEDOUT;
    }

    return 0;
}

static int brcm_cpu_release(u32 cpu)
{
    u32 tmp;
    u32 __iomem *reg;

    dprintk(XENLOG_INFO, "%s: Taking cpu %d out of reset \n", __func__, cpu);

    reg = ioremap_nocache(regs.hif_cpu_reset_config, sizeof(u32));
    if ( !reg )
    {
        dprintk(XENLOG_ERR, "%s: Unable to map \"hif_cpu_reset_config\"\n",
                __func__);
        return -EFAULT;
    }

    /* now take the cpu out of reset */
    tmp = readl(reg);
    tmp &= ~(1 << cpu);
    writel(tmp, reg);

    iounmap(reg);

    return 0;
}

static int brcm_set_boot_continuation(u32 cpu, u32 pc)
{
    u32 __iomem *reg;
    dprintk(XENLOG_INFO, "%s: cpu %d pc 0x%x\n", __func__, cpu, pc);

    reg = ioremap_nocache(regs.hif_boot_continuation + (cpu * 2 * sizeof(u32)),
                          2 * sizeof(u32));
    if ( !reg )
    {
        dprintk(XENLOG_ERR, "%s: Unable to map \"hif_boot_continuation\"\n",
                __func__);
        return -EFAULT;
    }

    writel(0, reg);
    writel(pc, reg + 1);

    iounmap(reg);

    return 0;
}

static int brcm_cpu_up(int cpu)
{
    int  rc;

    rc = brcm_cpu_power_on(cpu);
    if ( rc )
        return rc;

    rc = brcm_set_boot_continuation(cpu, brcm_boot_continuation_pc);
    if ( rc )
        return rc;

   return brcm_cpu_release(cpu);
}

static int __init brcm_smp_init(void)
{
    u32 __iomem *scratch;
    u32 target_pc;

    scratch = ioremap_nocache(regs.scratch_reg, sizeof(u32));

    if ( !scratch )
    {
        dprintk(XENLOG_ERR, "%s: Unable to map \"scratch_reg\"\n", __func__);
        return -EFAULT;
    }
    /*
     * The HIF CPU BIU CTRL Scratch Register is used to pass
     * addresses between this code in xen and the boot helper.
     * The helper puts its own entry point in the scratch register.
     * That address is written to the cpu boot continuation registers.
     * The helper expects xen to put xen's entry point back in the register.
     * The helper will jump to that address.
     * The helper is in SRAM, which will always be a 32 bit address.
     */

    brcm_boot_continuation_pc = readl(scratch);

    target_pc = __pa(init_secondary);
    writel(target_pc, scratch);

    iounmap(scratch);

    dprintk(XENLOG_INFO, "%s: target_pc 0x%x boot continuation pc 0x%x\n",
            __func__, target_pc, brcm_boot_continuation_pc);

    return 0;
}

static __init int brcm_init(void)
{
    return brcm_populate_plat_regs();
}

static const char const *brcm_dt_compat[] __initconst =
{
    "brcm,bcm7445d0",
    NULL
};

PLATFORM_START(brcm, "Broadcom B15")
    .compatible     = brcm_dt_compat,
    .init           = brcm_init,
    .smp_init       = brcm_smp_init,
    .cpu_up         = brcm_cpu_up,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
