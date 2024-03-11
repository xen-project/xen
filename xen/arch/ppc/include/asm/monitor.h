/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from xen/arch/arm/include/asm/monitor.h */
#ifndef __ASM_PPC_MONITOR_H__
#define __ASM_PPC_MONITOR_H__

#include <public/domctl.h>
#include <xen/errno.h>

#include <asm-generic/monitor.h>

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    BUG_ON("unimplemented");
    return 0;
}

#endif /* __ASM_PPC_MONITOR_H__ */
