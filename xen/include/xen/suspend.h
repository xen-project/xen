/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef XEN_SUSPEND_H
#define XEN_SUSPEND_H

#if __has_include(<asm/suspend.h>)
#include <asm/suspend.h>
#else
static inline void arch_domain_resume(struct domain *d) {}
#endif

#endif /* XEN_SUSPEND_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
