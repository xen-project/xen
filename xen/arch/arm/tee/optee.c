/*
 * xen/arch/arm/tee/optee.c
 *
 * OP-TEE mediator. It sits in between OP-TEE and guests and performs
 * actual calls to OP-TEE when some guest tries to interact with
 * OP-TEE. As OP-TEE does not know about second stage MMU translation,
 * mediator does this translation and performs other housekeeping tasks.
 *
 * OP-TEE ABI/protocol is described in two header files:
 *  - optee_smc.h provides information about SMCs: all possible calls,
 *    register allocation and return codes.
 *  - optee_msg.h provides format for messages that are passed with
 *    standard call OPTEE_SMC_CALL_WITH_ARG.
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018-2019 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/device_tree.h>
#include <xen/sched.h>

#include <asm/smccc.h>
#include <asm/tee/tee.h>
#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>

/* Client ID 0 is reserved for the hypervisor itself */
#define OPTEE_CLIENT_ID(domain) ((domain)->domain_id + 1)

/* Domain context */
struct optee_domain {
};

static bool optee_probe(void)
{
    struct dt_device_node *node;
    struct arm_smccc_res resp;

    /* Check for entry in dtb */
    node = dt_find_compatible_node(NULL, NULL, "linaro,optee-tz");
    if ( !node )
        return false;

    /* Check UID */
    arm_smccc_smc(ARM_SMCCC_CALL_UID_FID(TRUSTED_OS_END), &resp);

    if ( (uint32_t)resp.a0 != OPTEE_MSG_UID_0 ||
         (uint32_t)resp.a1 != OPTEE_MSG_UID_1 ||
         (uint32_t)resp.a2 != OPTEE_MSG_UID_2 ||
         (uint32_t)resp.a3 != OPTEE_MSG_UID_3 )
        return false;

    return true;
}

static int optee_domain_init(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_domain *ctx;

    ctx = xzalloc(struct optee_domain);
    if ( !ctx )
        return -ENOMEM;

    /*
     * Inform OP-TEE about a new guest.  This is a "Fast" call in
     * terms of OP-TEE. This basically means that it can't be
     * preempted, because there is no thread allocated for it in
     * OP-TEE. No blocking calls can be issued and interrupts are
     * disabled.
     *
     * a7 should be 0, so we can't skip last 6 parameters of arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_CREATED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);
    if ( resp.a0 != OPTEE_SMC_RETURN_OK )
    {
        printk(XENLOG_WARNING "%pd: Unable to create OPTEE client: rc = 0x%X\n",
               d, (uint32_t)resp.a0);

        xfree(ctx);

        return -ENODEV;
    }

    d->arch.tee = ctx;

    return 0;
}

static int optee_relinquish_resources(struct domain *d)
{
    struct arm_smccc_res resp;

    if ( !d->arch.tee )
        return 0;

    /*
     * Inform OP-TEE that domain is shutting down. This is
     * also a fast SMC call, like OPTEE_SMC_VM_CREATED, so
     * it is also non-preemptible.
     * At this time all domain VCPUs should be stopped. OP-TEE
     * relies on this.
     *
     * a7 should be 0, so we can't skip last 6 parameters of arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);

    XFREE(d->arch.tee);

    return 0;
}

static bool optee_handle_call(struct cpu_user_regs *regs)
{
    if ( !current->domain->arch.tee )
        return false;

    switch ( get_user_reg(regs, 0) )
    {
    case OPTEE_SMC_CALLS_COUNT:
    case OPTEE_SMC_CALLS_UID:
    case OPTEE_SMC_CALLS_REVISION:
    case OPTEE_SMC_CALL_GET_OS_UUID:
    case OPTEE_SMC_CALL_GET_OS_REVISION:
    case OPTEE_SMC_ENABLE_SHM_CACHE:
    case OPTEE_SMC_DISABLE_SHM_CACHE:
    case OPTEE_SMC_GET_SHM_CONFIG:
    case OPTEE_SMC_EXCHANGE_CAPABILITIES:
    case OPTEE_SMC_CALL_WITH_ARG:
    case OPTEE_SMC_CALL_RETURN_FROM_RPC:
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_ENOTAVAIL);
        return true;

    default:
        return false;
    }
}

static const struct tee_mediator_ops optee_ops =
{
    .probe = optee_probe,
    .domain_init = optee_domain_init,
    .relinquish_resources = optee_relinquish_resources,
    .handle_call = optee_handle_call,
};

REGISTER_TEE_MEDIATOR(optee, "OP-TEE", XEN_DOMCTL_CONFIG_TEE_OPTEE, &optee_ops);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
