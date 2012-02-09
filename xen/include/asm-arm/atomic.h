/*
 *  arch/arm/include/asm/atomic.h
 *
 *  Copyright (C) 1996 Russell King.
 *  Copyright (C) 2002 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ARCH_ARM_ATOMIC__
#define __ARCH_ARM_ATOMIC__

#include <xen/config.h>
#include <asm/system.h>

#define build_atomic_read(name, size, type, reg)   \
static inline type name(const volatile type *addr) \
{                                                  \
    type ret;                                      \
    asm volatile("ldr" size " %0,%1"               \
                 : reg (ret)                       \
                 : "m" (*(volatile type *)addr));  \
    return ret;                                    \
}

#define build_atomic_write(name, size, type, reg)      \
static inline void name(volatile type *addr, type val) \
{                                                      \
    asm volatile("str" size " %1,%0"                   \
                 : "=m" (*(volatile type *)addr)       \
                 : reg (val));                         \
}

build_atomic_read(read_u8_atomic, "b", uint8_t, "=q")
build_atomic_read(read_u16_atomic, "h", uint16_t, "=r")
build_atomic_read(read_u32_atomic, "", uint32_t, "=r")
//build_atomic_read(read_u64_atomic, "d", uint64_t, "=r")
build_atomic_read(read_int_atomic, "", int, "=r")

build_atomic_write(write_u8_atomic, "b", uint8_t, "q")
build_atomic_write(write_u16_atomic, "h", uint16_t, "r")
build_atomic_write(write_u32_atomic, "", uint32_t, "r")
//build_atomic_write(write_u64_atomic, "d", uint64_t, "r")
build_atomic_write(write_int_atomic, "", int, "r")

void __bad_atomic_size(void);

#define read_atomic(p) ({                                               \
    typeof(*p) __x;                                                     \
    switch ( sizeof(*p) ) {                                             \
    case 1: __x = (typeof(*p))read_u8_atomic((uint8_t *)p); break;      \
    case 2: __x = (typeof(*p))read_u16_atomic((uint16_t *)p); break;    \
    case 4: __x = (typeof(*p))read_u32_atomic((uint32_t *)p); break;    \
    default: __x = 0; __bad_atomic_size(); break;                       \
    }                                                                   \
    __x;                                                                \
})

#define write_atomic(p, x) ({                                           \
    typeof(*p) __x = (x);                                               \
    switch ( sizeof(*p) ) {                                             \
    case 1: write_u8_atomic((uint8_t *)p, (uint8_t)__x); break;         \
    case 2: write_u16_atomic((uint16_t *)p, (uint16_t)__x); break;      \
    case 4: write_u32_atomic((uint32_t *)p, (uint32_t)__x); break;      \
    default: __bad_atomic_size(); break;                                \
    }                                                                   \
    __x;                                                                \
})

/*
 * NB. I've pushed the volatile qualifier into the operations. This allows
 * fast accessors such as _atomic_read() and _atomic_set() which don't give
 * the compiler a fit.
 */
typedef struct { int counter; } atomic_t;

#define ATOMIC_INIT(i) { (i) }

/*
 * On ARM, ordinary assignment (str instruction) doesn't clear the local
 * strex/ldrex monitor on some implementations. The reason we can use it for
 * atomic_set() is the clrex or dummy strex done on every exception return.
 */
#define _atomic_read(v) ((v).counter)
#define atomic_read(v)  (*(volatile int *)&(v)->counter)

#define _atomic_set(v,i) (((v).counter) = (i))
#define atomic_set(v,i) (((v)->counter) = (i))

/*
 * ARMv6 UP and SMP safe atomic ops.  We use load exclusive and
 * store exclusive to ensure that these are atomic.  We may loop
 * to ensure that the update happens.
 */
static inline void atomic_add(int i, atomic_t *v)
{
        unsigned long tmp;
        int result;

        __asm__ __volatile__("@ atomic_add\n"
"1:     ldrex   %0, [%3]\n"
"       add     %0, %0, %4\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
        : "r" (&v->counter), "Ir" (i)
        : "cc");
}

static inline int atomic_add_return(int i, atomic_t *v)
{
        unsigned long tmp;
        int result;

        smp_mb();

        __asm__ __volatile__("@ atomic_add_return\n"
"1:     ldrex   %0, [%3]\n"
"       add     %0, %0, %4\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
        : "r" (&v->counter), "Ir" (i)
        : "cc");

        smp_mb();

        return result;
}

static inline void atomic_sub(int i, atomic_t *v)
{
        unsigned long tmp;
        int result;

        __asm__ __volatile__("@ atomic_sub\n"
"1:     ldrex   %0, [%3]\n"
"       sub     %0, %0, %4\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
        : "r" (&v->counter), "Ir" (i)
        : "cc");
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
        unsigned long tmp;
        int result;

        smp_mb();

        __asm__ __volatile__("@ atomic_sub_return\n"
"1:     ldrex   %0, [%3]\n"
"       sub     %0, %0, %4\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
        : "r" (&v->counter), "Ir" (i)
        : "cc");

        smp_mb();

        return result;
}

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
        unsigned long oldval, res;

        smp_mb();

        do {
                __asm__ __volatile__("@ atomic_cmpxchg\n"
                "ldrex  %1, [%3]\n"
                "mov    %0, #0\n"
                "teq    %1, %4\n"
                "strexeq %0, %5, [%3]\n"
                    : "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
                    : "r" (&ptr->counter), "Ir" (old), "r" (new)
                    : "cc");
        } while (res);

        smp_mb();

        return oldval;
}

static inline void atomic_clear_mask(unsigned long mask, unsigned long *addr)
{
        unsigned long tmp, tmp2;

        __asm__ __volatile__("@ atomic_clear_mask\n"
"1:     ldrex   %0, [%3]\n"
"       bic     %0, %0, %4\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (tmp), "=&r" (tmp2), "+Qo" (*addr)
        : "r" (addr), "Ir" (mask)
        : "cc");
}

#define atomic_inc(v)           atomic_add(1, v)
#define atomic_dec(v)           atomic_sub(1, v)

#define atomic_inc_and_test(v)  (atomic_add_return(1, v) == 0)
#define atomic_dec_and_test(v)  (atomic_sub_return(1, v) == 0)
#define atomic_inc_return(v)    (atomic_add_return(1, v))
#define atomic_dec_return(v)    (atomic_sub_return(1, v))
#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)

#define atomic_add_negative(i,v) (atomic_add_return(i, v) < 0)

static inline atomic_t atomic_compareandswap(
    atomic_t old, atomic_t new, atomic_t *v)
{
    atomic_t rc;
    rc.counter = __cmpxchg(&v->counter, old.counter, new.counter, sizeof(int));
    return rc;
}

#endif /* __ARCH_ARM_ATOMIC__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
