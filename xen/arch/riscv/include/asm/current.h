/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#define switch_stack_and_jump(stack, fn) do {               \
    asm volatile (                                          \
            "mv sp, %0\n"                                   \
            "j " #fn :: "r" (stack), "X" (fn) : "memory" ); \
    unreachable();                                          \
} while ( false )

#endif /* __ASM_CURRENT_H */
