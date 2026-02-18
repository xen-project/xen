/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/vmap.h>

static void continue_new_vcpu(struct vcpu *prev)
{
    BUG_ON("unimplemented\n");
}

int arch_vcpu_create(struct vcpu *v)
{
    int rc;
    void *stack = vzalloc(STACK_SIZE);

    if ( !stack )
        return -ENOMEM;

    v->arch.cpu_info = stack + STACK_SIZE - sizeof(*v->arch.cpu_info);

    v->arch.xen_saved_context.sp = (register_t)v->arch.cpu_info;
    v->arch.xen_saved_context.ra = (register_t)continue_new_vcpu;

    /* Idle VCPUs don't need the rest of this setup */
    if ( is_idle_vcpu(v) )
        return 0;

    /*
     * As the vtimer and interrupt controller (IC) are not yet implemented,
     * return an error.
     *
     * TODO: Drop this once the vtimer and IC are implemented.
     */
    rc = -EOPNOTSUPP;
    goto fail;

    return rc;

 fail:
    arch_vcpu_destroy(v);
    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    vfree((void *)&v->arch.cpu_info[1] - STACK_SIZE);
}

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Enforce the requirement documented in struct cpu_info that
     * guest_cpu_user_regs must be the first field.
     */
    BUILD_BUG_ON(offsetof(struct cpu_info, guest_cpu_user_regs));
}
