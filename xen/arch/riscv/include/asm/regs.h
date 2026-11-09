/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RISCV_REGS_H
#define RISCV_REGS_H

#ifndef __ASSEMBLER__

#include <xen/bug.h>

#define hyp_mode(r)     (0)

struct cpu_user_regs;

static inline bool guest_mode(const struct cpu_user_regs *r)
{
    BUG_ON("unimplemented");
}

#endif /* __ASSEMBLER__ */

#endif /* RISCV_REGS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
