/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/asm-generic/monitor.h
 *
 * Arch-specific monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 */

#ifndef __ASM_GENERIC_MONITOR_H__
#define __ASM_GENERIC_MONITOR_H__

#include <xen/errno.h>
#include <xen/lib.h>

struct domain;
struct xen_domctl_monitor_op;

static inline
void arch_monitor_allow_userspace(struct domain *d, bool allow_userspace)
{
}

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    /* No arch-specific monitor ops on GENERIC. */
    return -EOPNOTSUPP;
}

#ifndef HAS_ARCH_MONITOR_DOMCTL_EVENT
static inline
int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop)
{
    BUG_ON("unimplemented");
}
#endif

static inline
int arch_monitor_init_domain(struct domain *d)
{
    /* No arch-specific domain initialization on GENERIC. */
    return 0;
}

static inline
void arch_monitor_cleanup_domain(struct domain *d)
{
    /* No arch-specific domain cleanup on GENERIC. */
}

#endif /* __ASM_GENERIC_MONITOR_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: BSD
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
