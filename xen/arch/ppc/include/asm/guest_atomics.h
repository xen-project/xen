/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_GUEST_ATOMICS_H__
#define __ASM_PPC_GUEST_ATOMICS_H__

#include <xen/lib.h>

/* TODO: implement */
#define unimplemented_guest_bit_op(d, nr, p) ({                                \
    (void)(d);                                                                 \
    (void)(nr);                                                                \
    (void)(p);                                                                 \
    BUG_ON("unimplemented");                                                   \
    false;                                                                     \
})

#define guest_test_bit(d, nr, p)            unimplemented_guest_bit_op(d, nr, p)
#define guest_clear_bit(d, nr, p)           unimplemented_guest_bit_op(d, nr, p)
#define guest_set_bit(d, nr, p)             unimplemented_guest_bit_op(d, nr, p)
#define guest_test_and_set_bit(d, nr, p)    unimplemented_guest_bit_op(d, nr, p)
#define guest_test_and_clear_bit(d, nr, p)  unimplemented_guest_bit_op(d, nr, p)
#define guest_test_and_change_bit(d, nr, p) unimplemented_guest_bit_op(d, nr, p)

#endif /* __ASM_PPC_GUEST_ATOMICS_H__ */
