#ifndef __XEN_SYNCH_BITOPS_H__
#define __XEN_SYNCH_BITOPS_H__

/*
 * Copyright 1992, Linus Torvalds.
 * Heavily modified to provide guaranteed strong synchronisation
 * when communicating with Xen or other guest OSes running on other CPUs.
 */

#include <linux/config.h>

#define ADDR (*(volatile long *) addr)

static __inline__ void synch_set_bit(int nr, volatile void * addr)
{
    __asm__ __volatile__ ( 
        "lock btsl %1,%0"
        : "=m" (ADDR) : "Ir" (nr) : "memory" );
}

static __inline__ void synch_clear_bit(int nr, volatile void * addr)
{
    __asm__ __volatile__ (
        "lock btrl %1,%0"
        : "=m" (ADDR) : "Ir" (nr) : "memory" );
}

static __inline__ void synch_change_bit(int nr, volatile void * addr)
{
    __asm__ __volatile__ (
        "lock btcl %1,%0"
        : "=m" (ADDR) : "Ir" (nr) : "memory" );
}

static __inline__ int synch_test_and_set_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "lock btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR) : "Ir" (nr) : "memory");
    return oldbit;
}

static __inline__ int synch_test_and_clear_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "lock btrl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR) : "Ir" (nr) : "memory");
    return oldbit;
}

static __inline__ int synch_test_and_change_bit(int nr, volatile void * addr)
{
    int oldbit;

    __asm__ __volatile__ (
        "lock btcl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR) : "Ir" (nr) : "memory");
    return oldbit;
}

static __inline__ int synch_const_test_bit(int nr, const volatile void * addr)
{
    return ((1UL << (nr & 31)) & 
            (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int synch_var_test_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "btl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit) : "m" (ADDR), "Ir" (nr) );
    return oldbit;
}

#define synch_test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 synch_const_test_bit((nr),(addr)) : \
 synch_var_test_bit((nr),(addr)))

#endif /* __XEN_SYNCH_BITOPS_H__ */
