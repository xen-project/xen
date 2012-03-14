#ifndef __ASM_ARM_HYPERCALL_H__
#define __ASM_ARM_HYPERCALL_H__

#include <public/domctl.h> /* for arch_do_domctl */
int do_physdev_op(int cmd, XEN_GUEST_HANDLE(void) arg);

#endif /* __ASM_ARM_HYPERCALL_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
