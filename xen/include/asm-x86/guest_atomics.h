#ifndef _X86_GUEST_ATOMICS_H
#define _X86_GUEST_ATOMICS_H

#include <xen/bitops.h>

/*
 * It is safe to use the atomics helpers on x86 on memory shared with
 * the guests.
 */
#define guest_set_bit(d, nr, p)     ((void)(d), set_bit(nr, p))
#define guest_clear_bit(d, nr, p)   ((void)(d), clear_bit(nr, p))
#define guest_change_bit(d, nr, p)  ((void)(d), change_bit(nr, p))
#define guest_test_bit(d, nr, p)    ((void)(d), test_bit(nr, p))

#define guest_test_and_set_bit(d, nr, p)    \
    ((void)(d), test_and_set_bit(nr, p))
#define guest_test_and_clear_bit(d, nr, p)  \
    ((void)(d), test_and_clear_bit(nr, p))
#define guest_test_and_change_bit(d, nr, p) \
    ((void)(d), test_and_change_bit(nr, p))

#define guest_cmpxchg(d, ptr, o, n) ((void)(d), cmpxchg(ptr, o, n))

#endif /* _X86_GUEST_ATOMICS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
