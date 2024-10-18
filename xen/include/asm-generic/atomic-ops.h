/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The header provides default implementations for every xen/atomic.h-provided
 * forward inline declaration that can be synthesized from other atomic
 * functions or being created from scratch.
 */
#ifndef _ASM_GENERIC_ATOMIC_OPS_H_
#define _ASM_GENERIC_ATOMIC_OPS_H_

#include <xen/atomic.h>
#include <xen/lib.h>

#ifndef ATOMIC_READ
static inline int atomic_read(const atomic_t *v)
{
    return ACCESS_ONCE(v->counter);
}
#endif

#ifndef _ATOMIC_READ
static inline int _atomic_read(atomic_t v)
{
    return v.counter;
}
#endif

#ifndef ATOMIC_SET
static inline void atomic_set(atomic_t *v, int i)
{
    ACCESS_ONCE(v->counter) = i;
}
#endif

#ifndef _ATOMIC_SET
static inline void _atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}
#endif

#ifndef ATOMIC_SUB_AND_TEST
static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    return atomic_sub_return(i, v) == 0;
}
#endif

#ifndef ATOMIC_INC_AND_TEST
static inline int atomic_inc_and_test(atomic_t *v)
{
    return atomic_add_return(1, v) == 0;
}
#endif

#ifndef ATOMIC_INC
static inline void atomic_inc(atomic_t *v)
{
    atomic_add(1, v);
}
#endif

#ifndef ATOMIC_INC_RETURN
static inline int atomic_inc_return(atomic_t *v)
{
    return atomic_add_return(1, v);
}
#endif

#ifndef ATOMIC_DEC
static inline void atomic_dec(atomic_t *v)
{
    atomic_sub(1, v);
}
#endif

#ifndef ATOMIC_DEC_RETURN
static inline int atomic_dec_return(atomic_t *v)
{
    return atomic_sub_return(1, v);
}
#endif

#ifndef ATOMIC_DEC_AND_TEST
static inline int atomic_dec_and_test(atomic_t *v)
{
    return atomic_sub_return(1, v) == 0;
}
#endif

#ifndef ATOMIC_ADD_NEGATIVE
static inline int atomic_add_negative(int i, atomic_t *v)
{
    return atomic_add_return(i, v) < 0;
}
#endif

#endif /* _ASM_GENERIC_ATOMIC_OPS_H_ */
