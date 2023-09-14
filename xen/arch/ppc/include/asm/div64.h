/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_DIV64_H__
#define __ASM_PPC_DIV64_H__

#include <xen/types.h>

#define do_div(n, base) ({                       \
    uint32_t base_ = (base);                     \
    uint32_t rem_ = (uint64_t)(n) % base_;       \
    (n) = (uint64_t)(n) / base_;                 \
    rem_;                                        \
})

#endif /* __ASM_PPC_DIV64_H__ */
