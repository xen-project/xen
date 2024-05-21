/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_MONITOR_H__
#define __ASM_RISCV_MONITOR_H__

#include <xen/bug.h>

#include <asm-generic/monitor.h>

struct domain;

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    BUG_ON("unimplemented");
    return 0;
}

#endif /* __ASM_RISCV_MONITOR_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
