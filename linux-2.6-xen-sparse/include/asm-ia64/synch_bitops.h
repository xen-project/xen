#ifndef __XEN_SYNCH_BITOPS_H__
#define __XEN_SYNCH_BITOPS_H__

/*
 * Copyright 1992, Linus Torvalds.
 * Heavily modified to provide guaranteed strong synchronisation
 * when communicating with Xen or other guest OSes running on other CPUs.
 */

#define ADDR (*(volatile long *) addr)

static __inline__ void synch_set_bit(int nr, volatile void * addr)
{
	set_bit(nr, addr);
}

static __inline__ void synch_clear_bit(int nr, volatile void * addr)
{
	clear_bit(nr, addr);
}

static __inline__ void synch_change_bit(int nr, volatile void * addr)
{
	change_bit(nr, addr);
}

static __inline__ int synch_test_and_set_bit(int nr, volatile void * addr)
{
    return test_and_set_bit(nr, addr);
}

static __inline__ int synch_test_and_clear_bit(int nr, volatile void * addr)
{
    return test_and_clear_bit(nr, addr);
}

static __inline__ int synch_test_and_change_bit(int nr, volatile void * addr)
{
    return test_and_change_bit(nr, addr);
}

static __inline__ int synch_const_test_bit(int nr, const volatile void * addr)
{
    return test_bit(nr, addr);
}

static __inline__ int synch_var_test_bit(int nr, volatile void * addr)
{
    return test_bit(nr, addr);
}

#define synch_cmpxchg	ia64_cmpxchg4_acq

#define synch_test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 synch_const_test_bit((nr),(addr)) : \
 synch_var_test_bit((nr),(addr)))

#define synch_cmpxchg_subword synch_cmpxchg

#endif /* __XEN_SYNCH_BITOPS_H__ */
