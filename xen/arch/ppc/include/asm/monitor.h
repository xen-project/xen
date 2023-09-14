/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from xen/arch/arm/include/asm/monitor.h */
#ifndef __ASM_PPC_MONITOR_H__
#define __ASM_PPC_MONITOR_H__

#include <public/domctl.h>
#include <xen/errno.h>

static inline
void arch_monitor_allow_userspace(struct domain *d, bool allow_userspace)
{
}

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    /* No arch-specific monitor ops on PPC. */
    return -EOPNOTSUPP;
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

static inline
int arch_monitor_init_domain(struct domain *d)
{
    /* No arch-specific domain initialization on PPC. */
    return 0;
}

static inline
void arch_monitor_cleanup_domain(struct domain *d)
{
    /* No arch-specific domain cleanup on PPC. */
}

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    BUG_ON("unimplemented");
    return 0;
}

#endif /* __ASM_PPC_MONITOR_H__ */
