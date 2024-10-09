/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Vates */

#ifndef ASM__RISCV__NOSPEC_H
#define ASM__RISCV__NOSPEC_H

static inline bool evaluate_nospec(bool condition)
{
    return condition;
}

static inline void block_speculation(void)
{
}

#endif /* ASM__RISCV__NOSPEC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
