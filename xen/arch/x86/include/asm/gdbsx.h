/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __X86_GDBX_H__
#define __X86_GDBX_H__

#include <xen/stdbool.h>

struct domain;
struct xen_domctl;

#ifdef CONFIG_GDBSX

void domain_pause_for_debugger(void);

int gdbsx_domctl(struct domain *d, struct xen_domctl *domctl, bool *copyback);

#else

#include <xen/errno.h>

static inline void domain_pause_for_debugger(void) {}

static inline int gdbsx_domctl(
    struct domain *d, struct xen_domctl *domctl, bool *copyback)
{
    return -ENOSYS;
}

#endif /* CONFIG_GDBSX */
#endif /* __X86_GDBX_H__ */
