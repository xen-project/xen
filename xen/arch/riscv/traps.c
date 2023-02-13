/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 Vates
 *
 * RISC-V Trap handlers
 */
#include <asm/processor.h>
#include <asm/traps.h>

void do_trap(struct cpu_user_regs *cpu_regs)
{
    die();
}
