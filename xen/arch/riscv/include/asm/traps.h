/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef RISCV_TRAPS_H
#define RISCV_TRAPS_H

#include <asm/processor.h>

#ifndef __ASSEMBLER__

void do_trap(struct cpu_user_regs *cpu_regs);
void handle_trap(void);
void trap_init(void);

#endif /* __ASSEMBLER__ */

#endif /* RISCV_TRAPS_H */
