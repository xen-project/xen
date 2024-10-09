/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__TRAPS_H
#define ASM__RISCV__TRAPS_H

#include <asm/processor.h>

#ifndef __ASSEMBLY__

void do_trap(struct cpu_user_regs *cpu_regs);
void handle_trap(void);
void trap_init(void);

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__TRAPS_H */
