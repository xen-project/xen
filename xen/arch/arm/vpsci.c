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
#include <asm/gic.h>
#include <asm/vgic.h>
#include <asm/psci.h>
#include <asm/event.h>

#include <public/sched.h>

static int do_common_cpu_on(register_t target_cpu, register_t entry_point,
                       register_t context_id,int ver)
{
    struct vcpu *v;
    struct domain *d = current->domain;
    struct vcpu_guest_context *ctxt;
    int rc;
    int is_thumb = entry_point & 1;
    register_t vcpuid;

    vcpuid = vaffinity_to_vcpuid(target_cpu);

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
        return PSCI_INVALID_PARAMETERS;

    /* THUMB set is not allowed with 64-bit domain */
    if ( is_64bit_domain(d) && is_thumb )
        return PSCI_INVALID_PARAMETERS;

    if( ( ver == XEN_PSCI_V_0_2 ) &&
            ( !test_bit(_VPF_down, &v->pause_flags) ) )
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
    if ( is_32bit_domain(d) )
    {
        ctxt->user_regs.cpsr = PSR_GUEST32_INIT;
        if( ver == XEN_PSCI_V_0_2 )
            ctxt->user_regs.r0_usr = context_id;
    }
#ifdef CONFIG_ARM_64
    else
    {
        ctxt->user_regs.cpsr = PSR_GUEST64_INIT;
        if( ver == XEN_PSCI_V_0_2 )
            ctxt->user_regs.x0 = context_id;
    }
#endif

    /* Start the VCPU with THUMB set if it's requested by the kernel */
    if ( is_thumb )
        ctxt->user_regs.cpsr |= PSR_THUMB;
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

int32_t do_psci_cpu_on(uint32_t vcpuid, register_t entry_point)
{
    return do_common_cpu_on(vcpuid,entry_point,0,XEN_PSCI_V_0_1);
}

int32_t do_psci_cpu_off(uint32_t power_state)
{
    struct vcpu *v = current;
    if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
        vcpu_sleep_nosync(v);
    return PSCI_SUCCESS;
}

uint32_t do_psci_0_2_version(void)
{
    return XEN_PSCI_V_0_2;
}

register_t do_psci_0_2_cpu_suspend(uint32_t power_state, register_t entry_point,
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

int32_t do_psci_0_2_cpu_off(void)
{
    return do_psci_cpu_off(0);
}

int32_t do_psci_0_2_cpu_on(register_t target_cpu, register_t entry_point,
                       register_t context_id)
{
    return do_common_cpu_on(target_cpu,entry_point,context_id,XEN_PSCI_V_0_2);
}

static const unsigned long target_affinity_mask[] = {
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 0 ) ),
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 1 ) ),
    ( MPIDR_HWID_MASK & AFFINITY_MASK( 2 ) )
#ifdef CONFIG_ARM_64
    ,( MPIDR_HWID_MASK & AFFINITY_MASK( 3 ) )
#endif
};

int32_t do_psci_0_2_affinity_info(register_t target_affinity,
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

int32_t do_psci_0_2_migrate(uint32_t target_cpu)
{
    return PSCI_NOT_SUPPORTED;
}

uint32_t do_psci_0_2_migrate_info_type(void)
{
    return PSCI_0_2_TOS_MP_OR_NOT_PRESENT;
}

register_t do_psci_0_2_migrate_info_up_cpu(void)
{
    return PSCI_NOT_SUPPORTED;
}

void do_psci_0_2_system_off( void )
{
    struct domain *d = current->domain;
    domain_shutdown(d,SHUTDOWN_poweroff);
}

void do_psci_0_2_system_reset(void)
{
    struct domain *d = current->domain;
    domain_shutdown(d,SHUTDOWN_reboot);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
