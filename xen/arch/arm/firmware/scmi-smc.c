/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/firmware/scmi-smc.c
 *
 * ARM System Control and Management Interface (SCMI) over SMC
 * Generic handling layer
 *
 * Andrei Cherechesu <andrei.cherechesu@nxp.com>
 * Copyright 2024 NXP
 */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/device.h>
#include <asm/firmware/sci.h>
#include <asm/smccc.h>

#define SCMI_SMC_ID_PROP   "arm,smc-id"

static uint32_t __ro_after_init scmi_smc_id;

/*
 * Check if provided SMC Function Identifier matches the one known by the SCMI
 * layer, as read from DT prop 'arm,smc-id' during initialiation.
 */
static bool scmi_is_valid_smc_id(uint32_t fid)
{
    return (fid == scmi_smc_id);
}

/*
 * Generic handler for SCMI-SMC requests, currently only forwarding the
 * request to FW running at EL3 if it came from the hardware domain.
 * Called from the vSMC layer for SiP SMCs, since SCMI calls are usually
 * provided this way.
 *
 * Returns true if SMC was handled (regardless of response), false otherwise.
 */
static bool scmi_handle_smc(struct cpu_user_regs *regs)
{
    uint32_t fid = (uint32_t)get_user_reg(regs, 0);
    struct arm_smccc_res res;

    if ( !scmi_is_valid_smc_id(fid) )
        return false;

    /* Only the hardware domain should use SCMI calls */
    if ( !is_hardware_domain(current->domain) )
    {
        gdprintk(XENLOG_WARNING, "SCMI: Unprivileged access attempt\n");
        return false;
    }

    /* For the moment, forward the SCMI Request to FW running at EL3 */
    arm_smccc_1_1_smc(fid,
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
}

static int scmi_smc_domain_init(struct domain *d,
                                struct xen_domctl_createdomain *config)
{
    if ( !is_hardware_domain(d) )
        return 0;

    d->arch.sci_enabled = true;
    printk(XENLOG_DEBUG "SCMI: %pd init\n", d);
    return 0;
}

static void scmi_smc_domain_destroy(struct domain *d)
{
    if ( !is_hardware_domain(d) )
        return;

    printk(XENLOG_DEBUG "SCMI: %pd destroy\n", d);
}

static int __init scmi_check_smccc_ver(void)
{
    if ( smccc_ver < ARM_SMCCC_VERSION_1_1 )
    {
        printk(XENLOG_WARNING
               "SCMI: No SMCCC 1.1 support, SCMI calls forwarding disabled\n");
        return -ENOSYS;
    }

    return 0;
}

static const struct sci_mediator_ops scmi_smc_ops = {
    .handle_call = scmi_handle_smc,
    .domain_init = scmi_smc_domain_init,
    .domain_destroy = scmi_smc_domain_destroy,
};

/* Initialize the SCMI layer based on SMCs and Device-tree */
static int __init scmi_dom0_init(struct dt_device_node *dev, const void *data)
{
    int ret;

    if ( !acpi_disabled )
    {
        printk(XENLOG_WARNING "SCMI is not supported when using ACPI\n");
        return -EINVAL;
    }

    ret = scmi_check_smccc_ver();
    if ( ret )
        return ret;

    ret = dt_property_read_u32(dev, SCMI_SMC_ID_PROP, &scmi_smc_id);
    if ( !ret )
    {
        printk(XENLOG_ERR "SCMI: No valid \"%s\" property in \"%s\" DT node\n",
               SCMI_SMC_ID_PROP, dt_node_full_name(dev));
        return -ENOENT;
    }

    ret = sci_register(&scmi_smc_ops);
    if ( ret )
    {
        printk(XENLOG_ERR "SCMI: mediator already registered (ret = %d)\n",
               ret);
        return ret;
    }

    printk(XENLOG_INFO "Using SCMI with SMC ID: 0x%x\n", scmi_smc_id);

    return 0;
}

static const struct dt_device_match scmi_smc_match[] __initconst = {
    DT_MATCH_COMPATIBLE("arm,scmi-smc"),
    { /* sentinel */ },
};

DT_DEVICE_START(scmi_smc, "SCMI SMC DOM0", DEVICE_FIRMWARE)
    .dt_match = scmi_smc_match,
    .init = scmi_dom0_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
