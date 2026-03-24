/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ARM_SUSPEND_H
#define ARM_SUSPEND_H

struct domain;
struct vcpu;
struct vcpu_guest_context;

struct resume_info {
    struct vcpu_guest_context *ctxt;
    struct vcpu *wake_cpu;
};

void arch_domain_resume(struct domain *d);

#endif /* ARM_SUSPEND_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
