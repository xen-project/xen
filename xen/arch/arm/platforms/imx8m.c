/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * i.MX 8M family setup
 *
 * Copyright 2026 Open-EP (E-Paper) Community
 */

#include <xen/sched.h>
#include <asm/platform.h>
#include <asm/regs.h>
#include <asm/smccc.h>

static const char * const imx8m_dt_compat[] __initconst =
{
    "fsl,imx8mp",
    "fsl,imx8mq",
    "fsl,imx8mm",
    "fsl,imx8mn",
    NULL
};

#define IMX_SIP_FID(fid) \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, \
                       ARM_SMCCC_CONV_64, \
                       ARM_SMCCC_OWNER_SIP, \
                       (fid))

/*
 * SiP SMC function IDs used by the i.MX8M Linux drivers.  There is no
 * public specification for these; the IDs and their subfunctions are
 * extracted from the vendor kernel call sites (see drivers/soc/imx,
 * drivers/devfreq, drivers/remoteproc).
 */
#define IMX_SIP_F_GPC       0x0   /* GPC power-domain control */
#define IMX_SIP_F_CPUFREQ   0x1   /* CPU frequency scaling */
#define IMX_SIP_F_DDR_DVFS  0x4   /* DRAM frequency scaling */
#define IMX_SIP_F_SRC       0x5   /* SRC: M-core remoteproc start/stop */
#define IMX_SIP_F_SOC_INFO  0x6   /* read-only SoC info query */
#define IMX_SIP_F_NOC       0x8   /* NoC QoS priority setup */

#define IMX_SIP_GPC_SF_PM_DOMAIN    0x03

#define IMX_SIP_SRC_SF_M4_START     0x00
#define IMX_SIP_SRC_SF_M4_STARTED   0x01
#define IMX_SIP_SRC_SF_M4_STOP      0x02

#define IMX_SIP_NOC_SF_PRIORITY     0x01

static bool imx8m_smc(struct cpu_user_regs *regs)
{
    uint32_t function_id = get_user_reg(regs, 0);
    uint32_t subfunction_id = get_user_reg(regs, 1);
    struct arm_smccc_res res;

    if ( !cpus_have_const_cap(ARM_SMCCC_1_1) )
    {
        printk_once(XENLOG_WARNING
                    "imx8m: smc: no SMCCC 1.1 support. Disabling firmware calls\n");

        return false;
    }

    /* Only the hardware domain may use the SiP calls */
    if ( !is_hardware_domain(current->domain) )
    {
        gprintk(XENLOG_WARNING, "imx8m: smc: No access\n");
        return false;
    }

    /*
     * Forward only the subfunctions the dom0 kernel actually issues.  All
     * of these manage hardware that belongs to the hardware domain (power
     * domains, M-core, NoC) or are read-only queries.
     */
    switch ( function_id )
    {
    case IMX_SIP_FID(IMX_SIP_F_GPC):
        if ( subfunction_id != IMX_SIP_GPC_SF_PM_DOMAIN )
            return false;
        break;

    /*
     * CPU and DRAM frequency scaling: the hardware domain does not see the
     * whole system and cannot make an informed decision about resources
     * shared with the other domains, so deny both (CPU frequency scaling
     * is denied on the i.MX8QM platform for the same reason).
     */
    case IMX_SIP_FID(IMX_SIP_F_CPUFREQ):
    case IMX_SIP_FID(IMX_SIP_F_DDR_DVFS):
        return false;

    case IMX_SIP_FID(IMX_SIP_F_SRC):
        /* SRC: M-core remoteproc start, poll-started and stop. */
        switch ( subfunction_id )
        {
        case IMX_SIP_SRC_SF_M4_START:
        case IMX_SIP_SRC_SF_M4_STARTED:
        case IMX_SIP_SRC_SF_M4_STOP:
            break;

        default:
            return false;
        }
        break;

    case IMX_SIP_FID(IMX_SIP_F_SOC_INFO):
        break;

    case IMX_SIP_FID(IMX_SIP_F_NOC):
        /*
         * NoC QoS priority setup.  Only i.MX8MQ issues this at boot;
         * i.MX8MP issues no NoC call, but the platform covers both.
         */
        if ( subfunction_id != IMX_SIP_NOC_SF_PRIORITY )
            return false;
        break;

    default:
        gprintk(XENLOG_WARNING,
                "imx8m: smc: Unknown function id %x subfunction id %x\n",
                function_id, subfunction_id);
        return false;
    }

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

PLATFORM_START(imx8m, "i.MX 8M")
    .compatible = imx8m_dt_compat,
    .smc = imx8m_smc,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
