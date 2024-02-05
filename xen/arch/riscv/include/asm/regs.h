/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM_RISCV_REGS_H__
#define __ARM_RISCV_REGS_H__

#ifndef __ASSEMBLY__

#include <xen/bug.h>

#define hyp_mode(r)     (0)

struct cpu_user_regs;

static inline bool guest_mode(const struct cpu_user_regs *r)
{
    BUG_ON("unimplemented");
}

#endif /* __ASSEMBLY__ */

#endif /* __ARM_RISCV_REGS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
