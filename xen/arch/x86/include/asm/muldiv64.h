/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_MULDIV64_H
#define X86_MULDIV64_H

#include <xen/stdint.h>

static inline uint64_t attr_const arch_muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    asm_inline (
        "mulq %[b]\n\t"
        "divq %[c]"
        : "+a" (a)
        : [b] "rm" ((uint64_t)b), [c] "rm" ((uint64_t)c)
        : "rdx" );

    return a;
}
#define arch_muldiv64 arch_muldiv64

#endif /* X86_MULDIV64_H */
