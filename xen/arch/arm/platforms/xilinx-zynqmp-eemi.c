/*
 * xen/arch/arm/platforms/xilinx-zynqmp-eemi.c
 *
 * Xilinx ZynqMP EEMI API
 *
 * Copyright (c) 2018 Xilinx Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/regs.h>
#include <xen/sched.h>
#include <asm/smccc.h>
#include <asm/platforms/xilinx-zynqmp-eemi.h>

/*
 * EEMI firmware API:
 * https://www.xilinx.com/support/documentation/user_guides/ug1200-eemi-api.pdf
 *
 * IPI firmware API:
 * https://github.com/ARM-software/arm-trusted-firmware/blob/master/plat/xilinx/zynqmp/ipi_mailbox_service/ipi_mailbox_svc.h
 *
 * Power domain node_ids identify the area of effect of the power
 * management operations. They are the first parameter passed to power
 * management EEMI calls.
 *
 * Reset IDs identify the area of effect of a reset operation. They are
 * the first parameter passed to reset EEMI calls.
 *
 * For now, let the hardware domain access to all power domain nodes and
 * all reset lines. In the future, we'll check for ownership of
 * resources by specific virtual machines.
 */
static inline bool domain_has_node_access(struct domain *d, uint32_t nodeid)
{
    return is_hardware_domain(d);
}

static inline bool domain_has_reset_access(struct domain *d, uint32_t rst)
{
    return is_hardware_domain(d);
}

bool zynqmp_eemi(struct cpu_user_regs *regs)
{
    struct arm_smccc_res res;
    uint32_t fid = get_user_reg(regs, 0);
    uint32_t nodeid = get_user_reg(regs, 1);
    unsigned int pm_fn = fid & 0xFFFF;
    enum pm_ret_status ret;

    switch ( fid )
    {
    /* Mandatory SMC32 functions. */
    case ARM_SMCCC_CALL_COUNT_FID(SIP):
    case ARM_SMCCC_CALL_UID_FID(SIP):
    case ARM_SMCCC_REVISION_FID(SIP):
        goto forward_to_fw;
    /*
     * We can't allow CPUs to suspend without Xen knowing about it.
     * We accept but ignore the request and wait for the guest to issue
     * a WFI or PSCI call which Xen will trap and act accordingly upon.
     */
    case EEMI_FID(PM_SELF_SUSPEND):
        ret = XST_PM_SUCCESS;
        goto done;

    case EEMI_FID(PM_GET_NODE_STATUS):
    /* API for PUs.  */
    case EEMI_FID(PM_REQ_SUSPEND):
    case EEMI_FID(PM_FORCE_POWERDOWN):
    case EEMI_FID(PM_ABORT_SUSPEND):
    case EEMI_FID(PM_REQ_WAKEUP):
    case EEMI_FID(PM_SET_WAKEUP_SOURCE):
    /* API for slaves.  */
    case EEMI_FID(PM_REQ_NODE):
    case EEMI_FID(PM_RELEASE_NODE):
    case EEMI_FID(PM_SET_REQUIREMENT):
    case EEMI_FID(PM_SET_MAX_LATENCY):
        if ( !domain_has_node_access(current->domain, nodeid) )
        {
            gprintk(XENLOG_WARNING,
                    "zynqmp-pm: fn=%u No access to node %u\n", pm_fn, nodeid);
            ret = XST_PM_NO_ACCESS;
            goto done;
        }
        goto forward_to_fw;

    case EEMI_FID(PM_RESET_ASSERT):
    case EEMI_FID(PM_RESET_GET_STATUS):
        if ( !domain_has_reset_access(current->domain, nodeid) )
        {
            gprintk(XENLOG_WARNING,
                    "zynqmp-pm: fn=%u No access to reset %u\n", pm_fn, nodeid);
            ret = XST_PM_NO_ACCESS;
            goto done;
        }
        goto forward_to_fw;

    /* These calls are safe and always allowed.  */
    case EEMI_FID(PM_GET_TRUSTZONE_VERSION):
    case EEMI_FID(PM_GET_API_VERSION):
    case EEMI_FID(PM_GET_CHIPID):
        goto forward_to_fw;

    /* No MMIO access is allowed from non-secure domains */
    case EEMI_FID(PM_MMIO_WRITE):
    case EEMI_FID(PM_MMIO_READ):
        gprintk(XENLOG_WARNING,
                "zynqmp-pm: fn=%u No MMIO access to %u\n", pm_fn, nodeid);
        ret = XST_PM_NO_ACCESS;
        goto done;

    /* Exclusive to the hardware domain.  */
    case EEMI_FID(PM_INIT):
    case EEMI_FID(PM_SET_CONFIGURATION):
    case EEMI_FID(PM_FPGA_LOAD):
    case EEMI_FID(PM_FPGA_GET_STATUS):
    case EEMI_FID(PM_SECURE_SHA):
    case EEMI_FID(PM_SECURE_RSA):
    case EEMI_FID(PM_PINCTRL_SET_FUNCTION):
    case EEMI_FID(PM_PINCTRL_REQUEST):
    case EEMI_FID(PM_PINCTRL_RELEASE):
    case EEMI_FID(PM_PINCTRL_GET_FUNCTION):
    case EEMI_FID(PM_PINCTRL_CONFIG_PARAM_GET):
    case EEMI_FID(PM_PINCTRL_CONFIG_PARAM_SET):
    case EEMI_FID(PM_IOCTL):
    case EEMI_FID(PM_QUERY_DATA):
    case EEMI_FID(PM_CLOCK_ENABLE):
    case EEMI_FID(PM_CLOCK_DISABLE):
    case EEMI_FID(PM_CLOCK_GETSTATE):
    case EEMI_FID(PM_CLOCK_GETDIVIDER):
    case EEMI_FID(PM_CLOCK_SETDIVIDER):
    case EEMI_FID(PM_CLOCK_SETRATE):
    case EEMI_FID(PM_CLOCK_GETRATE):
    case EEMI_FID(PM_CLOCK_SETPARENT):
    case EEMI_FID(PM_CLOCK_GETPARENT):
        if ( !is_hardware_domain(current->domain) )
        {
            gprintk(XENLOG_WARNING, "eemi: fn=%u No access", pm_fn);
            ret = XST_PM_NO_ACCESS;
            goto done;
        }
        goto forward_to_fw;

    /* These calls are never allowed.  */
    case EEMI_FID(PM_SYSTEM_SHUTDOWN):
        ret = XST_PM_NO_ACCESS;
        goto done;

    case IPI_MAILBOX_FID(IPI_MAILBOX_OPEN):
    case IPI_MAILBOX_FID(IPI_MAILBOX_RELEASE):
    case IPI_MAILBOX_FID(IPI_MAILBOX_STATUS_ENQUIRY):
    case IPI_MAILBOX_FID(IPI_MAILBOX_NOTIFY):
    case IPI_MAILBOX_FID(IPI_MAILBOX_ACK):
    case IPI_MAILBOX_FID(IPI_MAILBOX_ENABLE_IRQ):
    case IPI_MAILBOX_FID(IPI_MAILBOX_DISABLE_IRQ):
        if ( !is_hardware_domain(current->domain) )
        {
            gprintk(XENLOG_WARNING, "IPI mailbox: fn=%u No access", pm_fn);
            ret = XST_PM_NO_ACCESS;
            goto done;
        }
        goto forward_to_fw;

    default:
        gprintk(XENLOG_WARNING, "zynqmp-pm: Unhandled PM Call: %u\n", fid);
        return false;
    }

forward_to_fw:
    /*
     * ZynqMP firmware calls (EEMI) take an argument that specifies the
     * area of effect of the function called. Specifically, node ids for
     * power management functions and reset ids for reset functions.
     *
     * The code above checks if a virtual machine has access rights over
     * the node id, reset id, etc. Now that the check has been done, we
     * can forward the whole command to firmware without additional
     * parameters checks.
     */
    arm_smccc_1_1_smc(get_user_reg(regs, 0),
                      get_user_reg(regs, 1),
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

done:
    set_user_reg(regs, 0, ret);
    return true;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
