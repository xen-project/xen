#ifndef __ASM_ARM_HYPERCALL_H__
#define __ASM_ARM_HYPERCALL_H__

#include <public/domctl.h> /* for arch_do_domctl */
int do_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

long do_arm_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg);

long subarch_do_domctl(struct xen_domctl *domctl, struct domain *d,
                       XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

#endif /* __ASM_ARM_HYPERCALL_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
