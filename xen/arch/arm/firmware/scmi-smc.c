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

#include <asm/smccc.h>
#include <asm/firmware/scmi-smc.h>

#define SCMI_SMC_ID_PROP   "arm,smc-id"

static bool __ro_after_init scmi_enabled;
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
bool scmi_handle_smc(struct cpu_user_regs *regs)
{
    uint32_t fid = (uint32_t)get_user_reg(regs, 0);
    struct arm_smccc_res res;

    if ( !scmi_enabled )
        return false;

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

static int __init scmi_dt_init_smccc(void)
{
    static const struct dt_device_match scmi_ids[] __initconst =
    {
        /* We only support "arm,scmi-smc" binding for now */
        DT_MATCH_COMPATIBLE("arm,scmi-smc"),
        { /* sentinel */ },
    };
    const struct dt_device_node *scmi_node;
    int ret;

    /* If no SCMI firmware node found, fail silently as it's not mandatory */
    scmi_node = dt_find_matching_node(NULL, scmi_ids);
    if ( !scmi_node )
        return -EOPNOTSUPP;

    ret = dt_property_read_u32(scmi_node, SCMI_SMC_ID_PROP, &scmi_smc_id);
    if ( !ret )
    {
        printk(XENLOG_ERR "SCMI: No valid \"%s\" property in \"%s\" DT node\n",
               SCMI_SMC_ID_PROP, scmi_node->full_name);
        return -ENOENT;
    }

    scmi_enabled = true;

    return 0;
}

/* Initialize the SCMI layer based on SMCs and Device-tree */
static int __init scmi_init(void)
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

    ret = scmi_dt_init_smccc();
    if ( ret == -EOPNOTSUPP )
        return ret;
    if ( ret )
        goto err;

    printk(XENLOG_INFO "Using SCMI with SMC ID: 0x%x\n", scmi_smc_id);

    return 0;

 err:
    printk(XENLOG_ERR "SCMI: Initialization failed (ret = %d)\n", ret);
    return ret;
}

__initcall(scmi_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
