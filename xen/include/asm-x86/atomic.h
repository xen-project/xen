#ifndef __ARCH_X86_ATOMIC__
#define __ARCH_X86_ATOMIC__

#include <xen/config.h>
#include <asm/system.h>

#ifdef CONFIG_SMP
#define LOCK "lock ; "
#else
#define LOCK ""
#endif

#define build_atomic_read(name, size, type, reg, barrier) \
static inline type name(const volatile type *addr) \
{ type ret; asm volatile("mov" size " %1,%0":reg (ret) \
:"m" (*(volatile type *)addr) barrier); return ret; }

#define build_atomic_write(name, size, type, reg, barrier) \
static inline void name(volatile type *addr, type val) \
{ asm volatile("mov" size " %1,%0": "=m" (*(volatile type *)addr) \
:reg (val) barrier); }

build_atomic_read(atomic_read8, "b", uint8_t, "=q", )
build_atomic_read(atomic_read16, "w", uint16_t, "=r", )
build_atomic_read(atomic_read32, "l", uint32_t, "=r", )
build_atomic_read(atomic_read_int, "l", int, "=r", )

build_atomic_write(atomic_write8, "b", uint8_t, "q", )
build_atomic_write(atomic_write16, "w", uint16_t, "r", )
build_atomic_write(atomic_write32, "l", uint32_t, "r", )
build_atomic_write(atomic_write_int, "l", int, "r", )

#ifdef __x86_64__
build_atomic_read(atomic_read64, "q", uint64_t, "=r", )
build_atomic_write(atomic_write64, "q", uint64_t, "r", )
#else
static inline uint64_t atomic_read64(const volatile uint64_t *addr)
{
    uint64_t *__addr = (uint64_t *)addr;
    return __cmpxchg8b(__addr, 0, 0);
}
static inline void atomic_write64(volatile uint64_t *addr, uint64_t val)
{
    uint64_t old = *addr, new, *__addr = (uint64_t *)addr;
    while ( (new = __cmpxchg8b(__addr, old, val)) != old )
        old = new;
}
#endif

#undef build_atomic_read
#undef build_atomic_write

/*
 * NB. I've pushed the volatile qualifier into the operations. This allows
 * fast accessors such as _atomic_read() and _atomic_set() which don't give
 * the compiler a fit.
 */
typedef struct { int counter; } atomic_t;

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically reads the value of @v.
 */
#define _atomic_read(v)		((v).counter)
#define atomic_read(v)		atomic_read_int(&((v)->counter))

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 * 
 * Atomically sets the value of @v to @i.
 */ 
#define _atomic_set(v,i)	(((v).counter) = (i))
#define atomic_set(v,i)		atomic_write_int(&((v)->counter), (i))

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 * 
 * Atomically adds @i to @v.
 */
static __inline__ void atomic_add(int i, atomic_t *v)
{
	asm volatile(
		LOCK "addl %1,%0"
		:"=m" (*(volatile int *)&v->counter)
		:"ir" (i), "m" (*(volatile int *)&v->counter));
}

/**
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(int i, atomic_t *v)
{
	asm volatile(
		LOCK "subl %1,%0"
		:"=m" (*(volatile int *)&v->counter)
		:"ir" (i), "m" (*(volatile int *)&v->counter));
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static __inline__ int atomic_sub_and_test(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(
		LOCK "subl %2,%0; sete %1"
		:"=m" (*(volatile int *)&v->counter), "=qm" (c)
		:"ir" (i), "m" (*(volatile int *)&v->counter) : "memory");
	return c;
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.
 */ 
static __inline__ void atomic_inc(atomic_t *v)
{
	asm volatile(
		LOCK "incl %0"
		:"=m" (*(volatile int *)&v->counter)
		:"m" (*(volatile int *)&v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static __inline__ void atomic_dec(atomic_t *v)
{
	asm volatile(
		LOCK "decl %0"
		:"=m" (*(volatile int *)&v->counter)
		:"m" (*(volatile int *)&v->counter));
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */ 
static __inline__ int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(
		LOCK "decl %0; sete %1"
		:"=m" (*(volatile int *)&v->counter), "=qm" (c)
		:"m" (*(volatile int *)&v->counter) : "memory");
	return c != 0;
}

/**
 * atomic_inc_and_test - increment and test 
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */ 
static __inline__ int atomic_inc_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(
		LOCK "incl %0; sete %1"
		:"=m" (*(volatile int *)&v->counter), "=qm" (c)
		:"m" (*(volatile int *)&v->counter) : "memory");
	return c != 0;
}

/**
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 * 
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */ 
static __inline__ int atomic_add_negative(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(
		LOCK "addl %2,%0; sets %1"
		:"=m" (*(volatile int *)&v->counter), "=qm" (c)
		:"ir" (i), "m" (*(volatile int *)&v->counter) : "memory");
	return c;
}

static __inline__ atomic_t atomic_compareandswap(
	atomic_t old, atomic_t new, atomic_t *v)
{
	atomic_t rc;
	rc.counter = 
		__cmpxchg(&v->counter, old.counter, new.counter, sizeof(int));
	return rc;
}

/* Atomic operations are already serializing on x86 */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

#endif /* __ARCH_X86_ATOMIC__ */
