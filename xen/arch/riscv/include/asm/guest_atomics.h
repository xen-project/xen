/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__GUEST_ATOMICS_H
#define ASM__RISCV__GUEST_ATOMICS_H

#include <xen/bug.h>

#define guest_testop(name)                                                  \
static inline int guest_##name(struct domain *d, int nr, volatile void *p)  \
{                                                                           \
    BUG_ON("unimplemented");                                                \
                                                                            \
    return 0;                                                               \
}

#define guest_bitop(name)                                                   \
static inline void guest_##name(struct domain *d, int nr, volatile void *p) \
{                                                                           \
    BUG_ON("unimplemented");                                                \
}

guest_bitop(set_bit)
guest_bitop(clear_bit)
guest_bitop(change_bit)

#undef guest_bitop

guest_testop(test_and_set_bit)
guest_testop(test_and_clear_bit)
guest_testop(test_and_change_bit)

#undef guest_testop

#define guest_test_bit(d, nr, p) ((void)(d), test_bit(nr, p))

#endif /* ASM__RISCV__GUEST_ATOMICS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
