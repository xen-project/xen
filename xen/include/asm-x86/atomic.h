#ifndef __ARCH_X86_ATOMIC__
#define __ARCH_X86_ATOMIC__

#include <xen/config.h>
#include <xen/atomic.h>
#include <asm/system.h>

#define build_read_atomic(name, size, type, reg, barrier) \
static inline type name(const volatile type *addr) \
{ type ret; asm volatile("mov" size " %1,%0":reg (ret) \
:"m" (*(volatile type *)addr) barrier); return ret; }

#define build_write_atomic(name, size, type, reg, barrier) \
static inline void name(volatile type *addr, type val) \
{ asm volatile("mov" size " %1,%0": "=m" (*(volatile type *)addr) \
:reg (val) barrier); }

#define build_add_sized(name, size, type, reg) \
    static inline void name(volatile type *addr, type val)              \
    {                                                                   \
        asm volatile("add" size " %1,%0"                                \
                     : "=m" (*addr)                                     \
                     : reg (val));                                      \
    }

build_read_atomic(read_u8_atomic, "b", uint8_t, "=q", )
build_read_atomic(read_u16_atomic, "w", uint16_t, "=r", )
build_read_atomic(read_u32_atomic, "l", uint32_t, "=r", )
build_read_atomic(read_u64_atomic, "q", uint64_t, "=r", )

build_write_atomic(write_u8_atomic, "b", uint8_t, "q", )
build_write_atomic(write_u16_atomic, "w", uint16_t, "r", )
build_write_atomic(write_u32_atomic, "l", uint32_t, "r", )
build_write_atomic(write_u64_atomic, "q", uint64_t, "r", )

build_add_sized(add_u8_sized, "b", uint8_t, "qi")
build_add_sized(add_u16_sized, "w", uint16_t, "ri")
build_add_sized(add_u32_sized, "l", uint32_t, "ri")
build_add_sized(add_u64_sized, "q", uint64_t, "ri")

#undef build_read_atomic
#undef build_write_atomic
#undef build_add_sized

void __bad_atomic_size(void);

#define read_atomic(p) ({                                 \
    unsigned long x_;                                     \
    switch ( sizeof(*(p)) ) {                             \
    case 1: x_ = read_u8_atomic((uint8_t *)(p)); break;   \
    case 2: x_ = read_u16_atomic((uint16_t *)(p)); break; \
    case 4: x_ = read_u32_atomic((uint32_t *)(p)); break; \
    case 8: x_ = read_u64_atomic((uint64_t *)(p)); break; \
    default: x_ = 0; __bad_atomic_size(); break;          \
    }                                                     \
    (typeof(*(p)))x_;                                     \
})

#define write_atomic(p, x) ({                             \
    typeof(*(p)) __x = (x);                               \
    unsigned long x_ = (unsigned long)__x;                \
    switch ( sizeof(*(p)) ) {                             \
    case 1: write_u8_atomic((uint8_t *)(p), x_); break;   \
    case 2: write_u16_atomic((uint16_t *)(p), x_); break; \
    case 4: write_u32_atomic((uint32_t *)(p), x_); break; \
    case 8: write_u64_atomic((uint64_t *)(p), x_); break; \
    default: __bad_atomic_size(); break;                  \
    }                                                     \
})

#define add_sized(p, x) ({                                \
    typeof(*(p)) x_ = (x);                                \
    switch ( sizeof(*(p)) )                               \
    {                                                     \
    case 1: add_u8_sized((uint8_t *)(p), x_); break;      \
    case 2: add_u16_sized((uint16_t *)(p), x_); break;    \
    case 4: add_u32_sized((uint32_t *)(p), x_); break;    \
    case 8: add_u64_sized((uint64_t *)(p), x_); break;    \
    default: __bad_atomic_size(); break;                  \
    }                                                     \
})

static inline int atomic_read(const atomic_t *v)
{
    return read_atomic(&v->counter);
}

static inline int _atomic_read(atomic_t v)
{
    return v.counter;
}

static inline void atomic_set(atomic_t *v, int i)
{
    write_atomic(&v->counter, i);
}

static inline void _atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
    return cmpxchg(&v->counter, old, new);
}

static inline void atomic_add(int i, atomic_t *v)
{
    asm volatile (
        "lock; addl %1,%0"
        : "=m" (*(volatile int *)&v->counter)
        : "ir" (i), "m" (*(volatile int *)&v->counter) );
}

static inline int atomic_add_return(int i, atomic_t *v)
{
    return i + arch_fetch_and_add(&v->counter, i);
}

static inline void atomic_sub(int i, atomic_t *v)
{
    asm volatile (
        "lock; subl %1,%0"
        : "=m" (*(volatile int *)&v->counter)
        : "ir" (i), "m" (*(volatile int *)&v->counter) );
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
    return arch_fetch_and_add(&v->counter, -i) - i;
}

static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    bool_t c;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile ( "lock; subl %2,%0"
                   : "+m" (*(volatile int *)&v->counter), "=@ccz" (c)
                   : "ir" (i) : "memory" );
#else
    asm volatile ( "lock; subl %2,%0; setz %1"
                   : "+m" (*(volatile int *)&v->counter), "=qm" (c)
                   : "ir" (i) : "memory" );
#endif

    return c;
}

static inline void atomic_inc(atomic_t *v)
{
    asm volatile (
        "lock; incl %0"
        : "=m" (*(volatile int *)&v->counter)
        : "m" (*(volatile int *)&v->counter) );
}

static inline int atomic_inc_return(atomic_t *v)
{
    return atomic_add_return(1, v);
}

static inline int atomic_inc_and_test(atomic_t *v)
{
    bool_t c;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile ( "lock; incl %0"
                   : "+m" (*(volatile int *)&v->counter), "=@ccz" (c)
                   :: "memory" );
#else
    asm volatile ( "lock; incl %0; setz %1"
                   : "+m" (*(volatile int *)&v->counter), "=qm" (c)
                   :: "memory" );
#endif

    return c;
}

static inline void atomic_dec(atomic_t *v)
{
    asm volatile (
        "lock; decl %0"
        : "=m" (*(volatile int *)&v->counter)
        : "m" (*(volatile int *)&v->counter) );
}

static inline int atomic_dec_return(atomic_t *v)
{
    return atomic_sub_return(1, v);
}

static inline int atomic_dec_and_test(atomic_t *v)
{
    bool_t c;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile ( "lock; decl %0"
                   : "+m" (*(volatile int *)&v->counter), "=@ccz" (c)
                   :: "memory" );
#else
    asm volatile ( "lock; decl %0; setz %1"
                   : "+m" (*(volatile int *)&v->counter), "=qm" (c)
                   :: "memory" );
#endif

    return c;
}

static inline int atomic_add_negative(int i, atomic_t *v)
{
    bool_t c;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile ( "lock; addl %2,%0"
                   : "+m" (*(volatile int *)&v->counter), "=@ccs" (c)
                   : "ir" (i) : "memory" );
#else
    asm volatile ( "lock; addl %2,%0; sets %1"
                   : "+m" (*(volatile int *)&v->counter), "=qm" (c)
                   : "ir" (i) : "memory" );
#endif

    return c;
}

static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
    int c, old;

    c = atomic_read(v);
    while (c != u && (old = atomic_cmpxchg(v, c, c + a)) != c)
        c = old;
    return c;
}

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

#endif /* __ARCH_X86_ATOMIC__ */
