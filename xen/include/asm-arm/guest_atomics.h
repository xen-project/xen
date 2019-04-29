#ifndef _ARM_GUEST_ATOMICS_H
#define _ARM_GUEST_ATOMICS_H

#include <xen/bitops.h>
#include <xen/sched.h>

/*
 * The guest atomics helpers shares the same logic. We first try to use
 * the *_timeout version of the operation. If it didn't timeout, then we
 * successfully updated the memory. Nothing else to do.
 *
 * If it did timeout, then it means we didn't manage to update the
 * memory. This is possibly because the guest is misbehaving (i.e tight
 * store loop) but can also happen for other reasons (i.e nested Xen).
 * In that case pause the domain and retry the operation, this time
 * without a timeout.
 *
 * Note, those helpers rely on other part of the code to prevent sharing
 * a page between Xen and multiple domain.
 */

DECLARE_PER_CPU(unsigned int, guest_safe_atomic_max);

#define guest_bitop(name)                                                   \
static inline void guest_##name(struct domain *d, int nr, volatile void *p) \
{                                                                           \
    perfc_incr(atomics_guest);                                              \
                                                                            \
    if ( name##_timeout(nr, p, this_cpu(guest_safe_atomic_max)) )           \
        return;                                                             \
                                                                            \
    perfc_incr(atomics_guest_paused);                                       \
                                                                            \
    domain_pause_nosync(d);                                                 \
    name(nr, p);                                                            \
    domain_unpause(d);                                                      \
}

#define guest_testop(name)                                                  \
static inline int guest_##name(struct domain *d, int nr, volatile void *p)  \
{                                                                           \
    bool succeed;                                                           \
    int oldbit;                                                             \
                                                                            \
    perfc_incr(atomics_guest);                                              \
                                                                            \
    succeed = name##_timeout(nr, p, &oldbit,                                \
                             this_cpu(guest_safe_atomic_max));              \
    if ( succeed )                                                          \
        return oldbit;                                                      \
                                                                            \
    perfc_incr(atomics_guest_paused);                                       \
                                                                            \
    domain_pause_nosync(d);                                                 \
    oldbit = name(nr, p);                                                   \
    domain_unpause(d);                                                      \
                                                                            \
    return oldbit;                                                          \
}

guest_bitop(set_bit)
guest_bitop(clear_bit)
guest_bitop(change_bit)

#undef guest_bitop

/* test_bit does not use load-store atomic operations */
#define guest_test_bit(d, nr, p) ((void)(d), test_bit(nr, p))

guest_testop(test_and_set_bit)
guest_testop(test_and_clear_bit)
guest_testop(test_and_change_bit)

#undef guest_testop

static inline void guest_clear_mask16(struct domain *d, uint16_t mask,
                                      volatile uint16_t *p)
{
    perfc_incr(atomics_guest);

    if ( clear_mask16_timeout(mask, p, this_cpu(guest_safe_atomic_max)) )
        return;

    domain_pause_nosync(d);
    clear_mask16(mask, p);
    domain_unpause(d);
}

static inline unsigned long __guest_cmpxchg(struct domain *d,
                                            volatile void *ptr,
                                            unsigned long old,
                                            unsigned long new,
                                            unsigned int size)
{
    unsigned long oldval = old;

    perfc_incr(atomics_guest);

    if ( __cmpxchg_mb_timeout(ptr, &oldval, new, size,
                              this_cpu(guest_safe_atomic_max)) )
        return oldval;

    perfc_incr(atomics_guest_paused);

    domain_pause_nosync(d);
    oldval = __cmpxchg_mb(ptr, old, new, size);
    domain_unpause(d);

    return oldval;
}

#define guest_cmpxchg(d, ptr, o, n)                         \
    ((__typeof__(*(ptr)))__guest_cmpxchg(d, ptr,            \
                                         (unsigned long)(o),\
                                         (unsigned long)(n),\
                                         sizeof (*(ptr))))

#endif /* _ARM_GUEST_ATOMICS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
