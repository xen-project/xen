/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PowerPC64 atomic operations
 *
 * Copyright (C) 2001 Paul Mackerras <paulus@au.ibm.com>, IBM
 * Copyright (C) 2001 Anton Blanchard <anton@au.ibm.com>, IBM
 * Copyright Raptor Engineering LLC
 */

#ifndef _ASM_PPC64_ATOMIC_H_
#define _ASM_PPC64_ATOMIC_H_

#include <xen/atomic.h>

#include <asm/memory.h>

static inline int atomic_read(const atomic_t *v)
{
    return *(const volatile int *)&v->counter;
}

static inline int _atomic_read(atomic_t v)
{
    return v.counter;
}

static inline void atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

static inline void _atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

void __bad_atomic_read(const volatile void *p, void *res);
void __bad_atomic_size(void);

#define build_atomic_read(name, insn, type)                                    \
    static inline type name(const volatile type *addr)                         \
    {                                                                          \
        type ret;                                                              \
        asm volatile ( insn "%U1%X1 %0,%1" : "=r" (ret) : "m<>" (*addr) );     \
        return ret;                                                            \
    }

#define build_atomic_write(name, insn, type)                                   \
    static inline void name(volatile type *addr, type val)                     \
    {                                                                          \
        asm volatile ( insn "%U0%X0 %1,%0" : "=m<>" (*addr) : "r" (val) );     \
    }

#define build_add_sized(name, ldinsn, stinsn, type)                            \
    static inline void name(volatile type *addr, type val)                     \
    {                                                                          \
        type t;                                                                \
        asm volatile ( "1: " ldinsn " %0,0,%3\n"                               \
                       "add%I2 %0,%0,%2\n"                                     \
                       stinsn " %0,0,%3 \n"                                    \
                       "bne- 1b\n"                                             \
                       : "=&r" (t), "+m" (*addr)                               \
                       : "r" (val), "r" (addr)                                 \
                       : "cc" );                                               \
    }

build_atomic_read(read_u8_atomic, "lbz", uint8_t)
build_atomic_read(read_u16_atomic, "lhz", uint16_t)
build_atomic_read(read_u32_atomic, "lwz", uint32_t)
build_atomic_read(read_u64_atomic, "ldz", uint64_t)

build_atomic_write(write_u8_atomic, "stb", uint8_t)
build_atomic_write(write_u16_atomic, "sth", uint16_t)
build_atomic_write(write_u32_atomic, "stw", uint32_t)
build_atomic_write(write_u64_atomic, "std", uint64_t)

build_add_sized(add_u8_sized, "lbarx", "stbcx.",uint8_t)
build_add_sized(add_u16_sized, "lharx", "sthcx.", uint16_t)
build_add_sized(add_u32_sized, "lwarx", "stwcx.", uint32_t)

#undef build_atomic_read
#undef build_atomic_write
#undef build_add_sized

static always_inline void read_atomic_size(const volatile void *p, void *res,
                                           unsigned int size)
{
    ASSERT(IS_ALIGNED((vaddr_t)p, size));
    switch ( size )
    {
    case 1:
        *(uint8_t *)res = read_u8_atomic(p);
        break;
    case 2:
        *(uint16_t *)res = read_u16_atomic(p);
        break;
    case 4:
        *(uint32_t *)res = read_u32_atomic(p);
        break;
    case 8:
        *(uint64_t *)res = read_u64_atomic(p);
        break;
    default:
        __bad_atomic_read(p, res);
        break;
    }
}

static always_inline void write_atomic_size(volatile void *p, const void *val,
                                            unsigned int size)
{
    ASSERT(IS_ALIGNED((vaddr_t)p, size));
    switch ( size )
    {
    case 1:
        write_u8_atomic(p, *(const uint8_t *)val);
        break;
    case 2:
        write_u16_atomic(p, *(const uint16_t *)val);
        break;
    case 4:
        write_u32_atomic(p, *(const uint32_t *)val);
        break;
    case 8:
        write_u64_atomic(p, *(const uint64_t *)val);
        break;
    default:
        __bad_atomic_size();
        break;
    }
}

#define read_atomic(p)                                                         \
    ({                                                                         \
        union {                                                                \
            typeof(*(p)) val;                                                  \
            char c[sizeof(*(p))];                                              \
        } x_;                                                                  \
        read_atomic_size(p, x_.c, sizeof(*(p)));                               \
        x_.val;                                                                \
    })

#define write_atomic(p, x)                                                     \
    do                                                                         \
    {                                                                          \
        typeof(*(p)) x_ = (x);                                                 \
        write_atomic_size(p, &x_, sizeof(*(p)));                               \
    } while ( 0 )

#define add_sized(p, x)                                                        \
    ({                                                                         \
        typeof(*(p)) x_ = (x);                                                 \
        switch ( sizeof(*(p)) )                                                \
        {                                                                      \
        case 1:                                                                \
            add_u8_sized((uint8_t *)(p), x_);                                  \
            break;                                                             \
        case 2:                                                                \
            add_u16_sized((uint16_t *)(p), x_);                                \
            break;                                                             \
        case 4:                                                                \
            add_u32_sized((uint32_t *)(p), x_);                                \
            break;                                                             \
        default:                                                               \
            __bad_atomic_size();                                               \
            break;                                                             \
        }                                                                      \
    })

static inline void atomic_add(int a, atomic_t *v)
{
    int t;

    asm volatile ( "1: lwarx %0,0,%3\n"
                   "add %0,%2,%0\n"
                   "stwcx. %0,0,%3\n"
                   "bne- 1b"
                   : "=&r" (t), "+m" (v->counter)
                   : "r" (a), "r" (&v->counter)
                   : "cc" );
}

static inline int atomic_add_return(int a, atomic_t *v)
{
    int t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%2\n"
                   "add %0,%1,%0\n"
                   "stwcx. %0,0,%2\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (t)
                   : "r" (a), "r" (&v->counter)
                   : "cc", "memory" );

    return t;
}

static inline void atomic_sub(int a, atomic_t *v)
{
    int t;

    asm volatile ( "1: lwarx %0,0,%3\n"
                   "subf %0,%2,%0\n"
                   "stwcx. %0,0,%3\n"
                   "bne- 1b"
                   : "=&r" (t), "+m" (v->counter)
                   : "r" (a), "r" (&v->counter)
                   : "cc" );
}

static inline int atomic_sub_return(int a, atomic_t *v)
{
    int t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%2\n"
                   "subf %0,%1,%0\n"
                   "stwcx. %0,0,%2\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (t)
                   : "r" (a), "r" (&v->counter)
                   : "cc", "memory" );

    return t;
}

static inline void atomic_inc(atomic_t *v)
{
    int t;

    asm volatile ( "1: lwarx %0,0,%2\n"
                   "addic %0,%0,1\n"
                   "stwcx. %0,0,%2\n"
                   "bne- 1b"
                   : "=&r" (t), "+m" (v->counter)
                   : "r" (&v->counter)
                   : "cc" );
}

static inline int atomic_inc_return(atomic_t *v)
{
    int t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%1\n"
                   "addic %0,%0,1\n"
                   "stwcx. %0,0,%1\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (t)
                   : "r" (&v->counter)
                   : "cc", "memory" );

    return t;
}

static inline void atomic_dec(atomic_t *v)
{
    int t;

    asm volatile ( "1: lwarx %0,0,%2\n"
                   "addic %0,%0,-1\n"
                   "stwcx. %0,0,%2\n"
                   "bne- 1b"
                   : "=&r" (t), "+m" (v->counter)
                   : "r" (&v->counter)
                   : "cc" );
}

static inline int atomic_dec_return(atomic_t *v)
{
    int t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%1\n"
                   "addic %0,%0,-1\n"
                   "stwcx. %0,0,%1\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (t)
                   : "r" (&v->counter)
                   : "cc", "memory" );

    return t;
}

/*
 * Atomically test *v and decrement if it is greater than 0.
 * The function returns the old value of *v minus 1.
 */
static inline int atomic_dec_if_positive(atomic_t *v)
{
    int t;

    asm volatile( PPC_ATOMIC_ENTRY_BARRIER
                  "1: lwarx %0,0,%1 # atomic_dec_if_positive\n"
                  "addic. %0,%0,-1\n"
                  "blt- 2f\n"
                  "stwcx. %0,0,%1\n"
                  "bne- 1b\n"
                  PPC_ATOMIC_EXIT_BARRIER
                  "2:"
                  : "=&r" (t)
                  : "r" (&v->counter)
                  : "cc", "memory" );

    return t;
}

static inline atomic_t atomic_compareandswap(atomic_t old, atomic_t new,
                                             atomic_t *v)
{
    atomic_t rc;
    rc.counter = __cmpxchg(&v->counter, old.counter, new.counter,
                           sizeof(v->counter));
    return rc;
}

#define arch_cmpxchg(ptr, o, n)                                                \
    ({                                                                         \
        __typeof__(*(ptr)) o_ = (o);                                           \
        __typeof__(*(ptr)) n_ = (n);                                           \
        (__typeof__(*(ptr))) __cmpxchg((ptr), (unsigned long)o_,               \
                                       (unsigned long)n_, sizeof(*(ptr)));     \
    })

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
    return arch_cmpxchg(&v->counter, old, new);
}

#define ATOMIC_OP(op, insn, suffix, sign) \
    static inline void atomic_##op(int a, atomic_t *v)                           \
    {                                                                            \
        int t;                                                                   \
        asm volatile ( "1: lwarx %0,0,%3\n"                                      \
                       insn "%I2" suffix " %0,%0,%2\n"                           \
                       "stwcx. %0,0,%3 \n"                                       \
                       "bne- 1b\n"                                               \
                       : "=&r" (t), "+m" (v->counter)                            \
                       : "r" #sign (a), "r" (&v->counter)                        \
                       : "cc" );                                                 \
    }

ATOMIC_OP(and, "and", ".", K)

static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    return atomic_sub_return(i, v) == 0;
}

static inline int atomic_inc_and_test(atomic_t *v)
{
    return atomic_add_return(1, v) == 0;
}

static inline int atomic_dec_and_test(atomic_t *v)
{
    return atomic_sub_return(1, v) == 0;
}

static inline int atomic_add_negative(int i, atomic_t *v)
{
    return atomic_add_return(i, v) < 0;
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;

	c = atomic_read(v);
	while (c != u && (old = atomic_cmpxchg(v, c, c + a)) != c)
		c = old;
	return c;
}

static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
    return __atomic_add_unless(v, a, u);
}

#endif /* _ASM_PPC64_ATOMIC_H_ */
