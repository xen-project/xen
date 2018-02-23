/*
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

#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/current.h>
#include <asm/vgic.h>
#include <asm/vpsci.h>
#include <asm/event.h>

#include <public/sched.h>

static int do_common_cpu_on(register_t target_cpu, register_t entry_point,
                            register_t context_id)
{
    struct vcpu *v;
    struct domain *d = current->domain;
    struct vcpu_guest_context *ctxt;
    int rc;
    bool is_thumb = entry_point & 1;
    register_t vcpuid;

    vcpuid = vaffinity_to_vcpuid(target_cpu);

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
        return PSCI_INVALID_PARAMETERS;

    /* THUMB set is not allowed with 64-bit domain */
    if ( is_64bit_domain(d) && is_thumb )
        return PSCI_INVALID_ADDRESS;

    if ( !test_bit(_VPF_down, &v->pause_flags) )
        return PSCI_ALREADY_ON;

    if ( (ctxt = alloc_vcpu_guest_context()) == NULL )
        return PSCI_DENIED;

    vgic_clear_pending_irqs(v);

    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->user_regs.pc64 = (u64) entry_point;
    ctxt->sctlr = SCTLR_GUEST_INIT;
    ctxt->ttbr0 = 0;
    ctxt->ttbr1 = 0;
    ctxt->ttbcr = 0; /* Defined Reset Value */

    /*
     * x0/r0_usr are always updated because for PSCI 0.1 the general
     * purpose registers are undefined upon CPU_on.
     */
    if ( is_32bit_domain(d) )
    {
        ctxt->user_regs.cpsr = PSR_GUEST32_INIT;
        /* Start the VCPU with THUMB set if it's requested by the kernel */
        if ( is_thumb )
        {
            ctxt->user_regs.cpsr |= PSR_THUMB;
            ctxt->user_regs.pc64 &= ~(u64)1;
        }

        ctxt->user_regs.r0_usr = context_id;
    }
#ifdef CONFIG_ARM_64
    else
    {
        ctxt->user_regs.cpsr = PSR_GUEST64_INIT;
        ctxt->user_regs.x0 = context_id;
    }
#endif
    ctxt->flags = VGCF_online;

    domain_lock(d);
    rc = arch_set_info_guest(v, ctxt);
    free_vcpu_guest_context(ctxt);

    if ( rc < 0 )
    {
        domain_unlock(d);
        return PSCI_DENIED;
    }
    domain_unlock(d);

    vcpu_wake(v);

    return PSCI_SUCCESS;
}

static int32_t do_psci_cpu_on(uint32_t vcpuid, register_t entry_point)
{
    int32_t ret;

    ret = do_common_cpu_on(vcpuid, entry_point, 0);
    /*
     * PSCI 0.1 does not define the return codes PSCI_ALREADY_ON and
     * PSCI_INVALID_ADDRESS.
     * Instead, return PSCI_INVALID_PARAMETERS.
     */
    if ( ret == PSCI_ALREADY_ON || ret == PSCI_INVALID_ADDRESS )
        ret = PSCI_INVALID_PARAMETERS;

    return ret;
}

static int32_t do_psci_cpu_off(uint32_t power_state)
{
    struct vcpu *v = current;
    if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
        vcpu_sleep_nosync(v);
    return PSCI_SUCCESS;
}

static uint32_t do_psci_0_2_version(void)
{
    /*
     * PSCI is backward compatible from 0.2. So we can bump the version
     * without any issue.
     */
    return PSCI_VERSION(1, 1);
}

static register_t do_psci_0_2_cpu_suspend(uint32_t power_state,
                                          register_t entry_point,
                                          register_t context_id)
{
    struct vcpu *v = current;

    /*
     * Power off requests are treated as performing standby
     * as this simplifies Xen implementation.
     */

    vcpu_block_unless_event_pending(v);
    return PSCI_SUCCESS;
}

static int32_t do_psci_0_2_cpu_off(void)
{
    return do_psci_cpu_off(0);
}

static int32_t do_psci_0_2_cpu_on(register_t target_cpu,
                                  register_t entry_point,
                                  register_t context_id)
{
    return do_common_cpu_on(target_cpu, entry_point, context_id);
}

static const unsigned long target_affinity_mask[] = {
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 0 ) ),
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 1 ) ),
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 2 ) )
#ifdef CONFIG_ARM_64
    ,( MPIDR_HWID_MASK & AFFINITY_MASK( 3 ) )
#endif
};

static int32_t do_psci_0_2_affinity_info(register_t target_affinity,
                                         uint32_t lowest_affinity_level)
{
    struct domain *d = current->domain;
    struct vcpu *v;
    uint32_t vcpuid;
    unsigned long tmask;

    if ( lowest_affinity_level < ARRAY_SIZE(target_affinity_mask) )
    {
        tmask = target_affinity_mask[lowest_affinity_level];
        target_affinity &= tmask;
    }
    else
        return PSCI_INVALID_PARAMETERS;

    for ( vcpuid = 0; vcpuid < d->max_vcpus; vcpuid++ )
    {
        v = d->vcpu[vcpuid];

        if ( ( ( v->arch.vmpidr & tmask ) == target_affinity )
                && ( !test_bit(_VPF_down, &v->pause_flags) ) )
            return PSCI_0_2_AFFINITY_LEVEL_ON;
    }

    return PSCI_0_2_AFFINITY_LEVEL_OFF;
}

static int32_t do_psci_0_2_migrate_info_type(void)
{
    return PSCI_0_2_TOS_MP_OR_NOT_PRESENT;
}

static void do_psci_0_2_system_off( void )
{
    struct domain *d = current->domain;
    domain_shutdown(d,SHUTDOWN_poweroff);
}

static void do_psci_0_2_system_reset(void)
{
    struct domain *d = current->domain;
    domain_shutdown(d,SHUTDOWN_reboot);
}

static int32_t do_psci_1_0_features(uint32_t psci_func_id)
{
    /* /!\ Ordered by function ID and not name */
    switch ( psci_func_id )
    {
    case PSCI_0_2_FN32_PSCI_VERSION:
    case PSCI_0_2_FN32_CPU_SUSPEND:
    case PSCI_0_2_FN64_CPU_SUSPEND:
    case PSCI_0_2_FN32_CPU_OFF:
    case PSCI_0_2_FN32_CPU_ON:
    case PSCI_0_2_FN64_CPU_ON:
    case PSCI_0_2_FN32_AFFINITY_INFO:
    case PSCI_0_2_FN64_AFFINITY_INFO:
    case PSCI_0_2_FN32_MIGRATE_INFO_TYPE:
    case PSCI_0_2_FN32_SYSTEM_OFF:
    case PSCI_0_2_FN32_SYSTEM_RESET:
    case PSCI_1_0_FN32_PSCI_FEATURES:
    case ARM_SMCCC_VERSION_FID:
        return 0;
    default:
        return PSCI_NOT_SUPPORTED;
    }
}

#define PSCI_SET_RESULT(reg, val) set_user_reg(reg, 0, val)
#define PSCI_ARG(reg, n) get_user_reg(reg, n)

#ifdef CONFIG_ARM_64
#define PSCI_ARG32(reg, n) (uint32_t)(get_user_reg(reg, n))
#else
#define PSCI_ARG32(reg, n) PSCI_ARG(reg, n)
#endif

/*
 * PSCI 0.1 calls. It will return false if the function ID is not
 * handled.
 */
bool do_vpsci_0_1_call(struct cpu_user_regs *regs, uint32_t fid)
{
    switch ( (uint32_t)get_user_reg(regs, 0) )
    {
    case PSCI_cpu_off:
    {
        uint32_t pstate = PSCI_ARG32(regs, 1);

        perfc_incr(vpsci_cpu_off);
        PSCI_SET_RESULT(regs, do_psci_cpu_off(pstate));
        return true;
    }
    case PSCI_cpu_on:
    {
        uint32_t vcpuid = PSCI_ARG32(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);

        perfc_incr(vpsci_cpu_on);
        PSCI_SET_RESULT(regs, do_psci_cpu_on(vcpuid, epoint));
        return true;
    }
    default:
        return false;
    }
}

/*
 * PSCI 0.2 or later calls. It will return false if the function ID is
 * not handled.
 */
bool do_vpsci_0_2_call(struct cpu_user_regs *regs, uint32_t fid)
{
    /*
     * /!\ VPSCI_NR_FUNCS (in asm-arm/vpsci.h) should be updated when
     * adding/removing a function. SCCC_SMCCC_*_REVISION should be
     * updated once per release.
     */
    switch ( fid )
    {
    case PSCI_0_2_FN32_PSCI_VERSION:
        perfc_incr(vpsci_version);
        PSCI_SET_RESULT(regs, do_psci_0_2_version());
        return true;

    case PSCI_0_2_FN32_CPU_OFF:
        perfc_incr(vpsci_cpu_off);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_off());
        return true;

    case PSCI_0_2_FN32_MIGRATE_INFO_TYPE:
        perfc_incr(vpsci_migrate_info_type);
        PSCI_SET_RESULT(regs, do_psci_0_2_migrate_info_type());
        return true;

    case PSCI_0_2_FN32_SYSTEM_OFF:
        perfc_incr(vpsci_system_off);
        do_psci_0_2_system_off();
        PSCI_SET_RESULT(regs, PSCI_INTERNAL_FAILURE);
        return true;

    case PSCI_0_2_FN32_SYSTEM_RESET:
        perfc_incr(vpsci_system_reset);
        do_psci_0_2_system_reset();
        PSCI_SET_RESULT(regs, PSCI_INTERNAL_FAILURE);
        return true;

    case PSCI_0_2_FN32_CPU_ON:
    case PSCI_0_2_FN64_CPU_ON:
    {
        register_t vcpuid = PSCI_ARG(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);
        register_t cid = PSCI_ARG(regs, 3);

        perfc_incr(vpsci_cpu_on);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_on(vcpuid, epoint, cid));
        return true;
    }

    case PSCI_0_2_FN32_CPU_SUSPEND:
    case PSCI_0_2_FN64_CPU_SUSPEND:
    {
        uint32_t pstate = PSCI_ARG32(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);
        register_t cid = PSCI_ARG(regs, 3);

        perfc_incr(vpsci_cpu_suspend);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_suspend(pstate, epoint, cid));
        return true;
    }

    case PSCI_0_2_FN32_AFFINITY_INFO:
    case PSCI_0_2_FN64_AFFINITY_INFO:
    {
        register_t taff = PSCI_ARG(regs, 1);
        uint32_t laff = PSCI_ARG32(regs, 2);

        perfc_incr(vpsci_cpu_affinity_info);
        PSCI_SET_RESULT(regs, do_psci_0_2_affinity_info(taff, laff));
        return true;
    }

    case PSCI_1_0_FN32_PSCI_FEATURES:
    {
        uint32_t psci_func_id = PSCI_ARG32(regs, 1);

        perfc_incr(vpsci_features);
        PSCI_SET_RESULT(regs, do_psci_1_0_features(psci_func_id));
        return true;
    }

    default:
        return false;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
