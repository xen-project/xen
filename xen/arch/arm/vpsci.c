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
#include <asm/psci.h>

int do_psci_cpu_on(uint32_t vcpuid, register_t entry_point)
{
    struct vcpu *v;
    struct domain *d = current->domain;
    struct vcpu_guest_context *ctxt;
    int rc;
    int is_thumb = entry_point & 1;

    if ( (vcpuid < 0) || (vcpuid >= MAX_VIRT_CPUS) )
        return PSCI_EINVAL;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
        return PSCI_EINVAL;

    /* THUMB set is not allowed with 64-bit domain */
    if ( is_pv64_domain(d) && is_thumb )
        return PSCI_EINVAL;

    if ( (ctxt = alloc_vcpu_guest_context()) == NULL )
        return PSCI_DENIED;

    vgic_clear_pending_irqs(v);

    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->user_regs.pc64 = (u64) entry_point;
    ctxt->sctlr = SCTLR_GUEST_INIT;
    ctxt->ttbr0 = 0;
    ctxt->ttbr1 = 0;
    ctxt->ttbcr = 0; /* Defined Reset Value */
    if ( is_pv32_domain(d) )
        ctxt->user_regs.cpsr = PSR_GUEST32_INIT;
#ifdef CONFIG_ARM_64
    else
        ctxt->user_regs.cpsr = PSR_GUEST64_INIT;
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

int do_psci_cpu_off(uint32_t power_state)
{
    struct vcpu *v = current;
    if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
        vcpu_sleep_nosync(v);
    return PSCI_SUCCESS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
