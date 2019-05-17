/*
 * xen/arch/arm/platforms/xilinx-zynqmp.c
 *
 * Xilinx ZynqMP setup
 *
 * Copyright (c) 2016 Xilinx Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
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
#include <asm/platforms/xilinx-zynqmp-eemi.h>
#include <asm/smccc.h>

static const char * const zynqmp_dt_compat[] __initconst =
{
    "xlnx,zynqmp",
    NULL
};

static bool zynqmp_smc(struct cpu_user_regs *regs)
{
    /*
     * ZynqMP firmware is based on SMCCC 1.1. If SMCCC 1.1 is not
     * available something is wrong, don't try to handle it.
     */
    if ( !cpus_have_const_cap(ARM_SMCCC_1_1) )
    {
        printk_once(XENLOG_WARNING
                    "ZynqMP firmware Error: no SMCCC 1.1 support. Disabling firmware calls\n");

        return false;
    }
    return zynqmp_eemi(regs);
}

PLATFORM_START(xilinx_zynqmp, "Xilinx ZynqMP")
    .compatible = zynqmp_dt_compat,
    .smc = zynqmp_smc,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
