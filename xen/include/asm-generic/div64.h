/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_DIV64
#define __ASM_GENERIC_DIV64

#include <xen/types.h>

#if BITS_PER_LONG == 64

#define do_div(n, divisor) ({                   \
    uint32_t divisor_ = (divisor);              \
    uint32_t rem_ = (uint64_t)(n) % divisor_;   \
    (n) = (uint64_t)(n) / divisor_;             \
    rem_;                                       \
})

#endif /* BITS_PER_LONG */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
