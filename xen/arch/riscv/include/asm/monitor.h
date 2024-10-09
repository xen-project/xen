/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__MONITOR_H
#define ASM__RISCV__MONITOR_H

#include <xen/bug.h>

#include <asm-generic/monitor.h>

struct domain;

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    BUG_ON("unimplemented");
    return 0;
}

#endif /* ASM__RISCV__MONITOR_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
