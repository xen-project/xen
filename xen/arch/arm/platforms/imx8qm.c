/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/platforms/imx8qm.c
 *
 * i.MX 8QM setup
 *
 * Copyright (c) 2016 Freescale Inc.
 * Copyright 2018-2019 NXP
 *
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <xen/sched.h>
#include <asm/platform.h>
#include <asm/smccc.h>

static const char * const imx8qm_dt_compat[] __initconst =
{
    "fsl,imx8qm",
    "fsl,imx8qxp",
    NULL
};

#define IMX_SIP_FID(fid) \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, \
                       ARM_SMCCC_CONV_64, \
                       ARM_SMCCC_OWNER_SIP, \
                       (fid))

#define IMX_SIP_F_CPUFREQ        0x1
#define IMX_SIP_F_TIME           0x2
#define IMX_SIP_F_WAKEUP_SRC     0x9
#define IMX_SIP_F_OTP_WRITE      0xB

#define IMX_SIP_TIME_SF_RTC_SET_TIME     0x00
#define IMX_SIP_TIME_SF_WDOG_START       0x01
#define IMX_SIP_TIME_SF_WDOG_STOP        0x02
#define IMX_SIP_TIME_SF_WDOG_SET_ACT     0x03
#define IMX_SIP_TIME_SF_WDOG_PING        0x04
#define IMX_SIP_TIME_SF_WDOG_SET_TIMEOUT 0x05
#define IMX_SIP_TIME_SF_WDOG_GET_STAT    0x06
#define IMX_SIP_TIME_SF_WDOG_SET_PRETIME 0x07

static bool imx8qm_is_sip_time_call_ok(uint32_t subfunction_id)
{
    switch ( subfunction_id )
    {
    case IMX_SIP_TIME_SF_RTC_SET_TIME:
        return true;
    case IMX_SIP_TIME_SF_WDOG_START:
    case IMX_SIP_TIME_SF_WDOG_STOP:
    case IMX_SIP_TIME_SF_WDOG_SET_ACT:
    case IMX_SIP_TIME_SF_WDOG_PING:
    case IMX_SIP_TIME_SF_WDOG_SET_TIMEOUT:
    case IMX_SIP_TIME_SF_WDOG_GET_STAT:
    case IMX_SIP_TIME_SF_WDOG_SET_PRETIME:
        return true;
    default:
        gprintk(XENLOG_WARNING, "imx8qm: smc: time: Unknown subfunction id %x\n",
                subfunction_id);
        return false;
    }
}

static bool imx8qm_smc(struct cpu_user_regs *regs)
{
    uint32_t function_id = get_user_reg(regs, 0);
    uint32_t subfunction_id = get_user_reg(regs, 1);
    struct arm_smccc_res res;

    if ( !cpus_have_const_cap(ARM_SMCCC_1_1) )
    {
        printk_once(XENLOG_WARNING
                    "imx8qm: smc: no SMCCC 1.1 support. Disabling firmware calls\n");

        return false;
    }

    /* Only hardware domain may use the SIP calls */
    if ( !is_hardware_domain(current->domain) )
    {
        gprintk(XENLOG_WARNING, "imx8qm: smc: No access\n");
        return false;
    }

    switch ( function_id )
    {
    case IMX_SIP_FID(IMX_SIP_F_CPUFREQ):
        /* Hardware domain can't take any informed decision here */
        return false;
    case IMX_SIP_FID(IMX_SIP_F_TIME):
        if ( imx8qm_is_sip_time_call_ok(subfunction_id) )
            goto allow_call;
        return false;
    /* Xen doesn't have suspend support */
    case IMX_SIP_FID(IMX_SIP_F_WAKEUP_SRC):
        return false;
    case IMX_SIP_FID(IMX_SIP_F_OTP_WRITE):
        /* subfunction_id is the fuse number, no sensible check possible */
        goto allow_call;
    default:
        gprintk(XENLOG_WARNING, "imx8qm: smc: Unknown function id %x\n",
                function_id);
        return false;
    }

 allow_call:
    arm_smccc_1_1_smc(function_id,
                      subfunction_id,
                      get_user_reg(regs, 2),
                      get_user_reg(regs, 3),
                      get_user_reg(regs, 4),
                      get_user_reg(regs, 5),
                      get_user_reg(regs, 6),
                      get_user_reg(regs, 7),
                      &res);

    set_user_reg(regs, 0, res.a0);
    set_user_reg(regs, 1, res.a1);
    set_user_reg(regs, 2, res.a2);
    set_user_reg(regs, 3, res.a3);

    return true;
}

PLATFORM_START(imx8qm, "i.MX 8Q{M,XP}")
    .compatible = imx8qm_dt_compat,
    .smc = imx8qm_smc,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
