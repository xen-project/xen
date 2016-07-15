#ifndef __ARCH_ARM_ATOMIC__
#define __ARCH_ARM_ATOMIC__

#include <xen/config.h>
#include <xen/atomic.h>
#include <xen/prefetch.h>
#include <asm/system.h>

#define build_atomic_read(name, size, width, type, reg)\
static inline type name(const volatile type *addr) \
{                                                  \
    type ret;                                      \
    asm volatile("ldr" size " %" width "0,%1"      \
                 : reg (ret)                       \
                 : "m" (*(volatile type *)addr));  \
    return ret;                                    \
}

#define build_atomic_write(name, size, width, type, reg) \
static inline void name(volatile type *addr, type val) \
{                                                      \
    asm volatile("str" size " %"width"1,%0"            \
                 : "=m" (*(volatile type *)addr)       \
                 : reg (val));                         \
}

#define build_add_sized(name, size, width, type, reg) \
static inline void name(volatile type *addr, type val)                  \
{                                                                       \
    type t;                                                             \
    asm volatile("ldr" size " %"width"1,%0\n"                           \
                 "add %"width"1,%"width"1,%"width"2\n"                  \
                 "str" size " %"width"1,%0"                             \
                 : "=m" (*(volatile type *)addr), "=r" (t)              \
                 : reg (val));                                          \
}

#if defined (CONFIG_ARM_32)
#define BYTE ""
#define WORD ""
#elif defined (CONFIG_ARM_64)
#define BYTE "w"
#define WORD "w"
#endif

build_atomic_read(read_u8_atomic,  "b", BYTE, uint8_t, "=r")
build_atomic_read(read_u16_atomic, "h", WORD, uint16_t, "=r")
build_atomic_read(read_u32_atomic, "",  WORD, uint32_t, "=r")
build_atomic_read(read_int_atomic, "",  WORD, int, "=r")

build_atomic_write(write_u8_atomic,  "b", BYTE, uint8_t, "r")
build_atomic_write(write_u16_atomic, "h", WORD, uint16_t, "r")
build_atomic_write(write_u32_atomic, "",  WORD, uint32_t, "r")
build_atomic_write(write_int_atomic, "",  WORD, int, "r")

#if 0 /* defined (CONFIG_ARM_64) */
build_atomic_read(read_u64_atomic, "x", uint64_t, "=r")
build_atomic_write(write_u64_atomic, "x", uint64_t, "r")
#endif

build_add_sized(add_u8_sized, "b", BYTE, uint8_t, "ri")
build_add_sized(add_u16_sized, "h", WORD, uint16_t, "ri")
build_add_sized(add_u32_sized, "", WORD, uint32_t, "ri")

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

#define add_sized(p, x) ({                                              \
    typeof(*(p)) __x = (x);                                             \
    switch ( sizeof(*(p)) )                                             \
    {                                                                   \
    case 1: add_u8_sized((uint8_t *)(p), __x); break;                   \
    case 2: add_u16_sized((uint16_t *)(p), __x); break;                 \
    case 4: add_u32_sized((uint32_t *)(p), __x); break;                 \
    default: __bad_atomic_size(); break;                                \
    }                                                                   \
})

/*
 * On ARM, ordinary assignment (str instruction) doesn't clear the local
 * strex/ldrex monitor on some implementations. The reason we can use it for
 * atomic_set() is the clrex or dummy strex done on every exception return.
 */
static inline int atomic_read(const atomic_t *v)
{
    return *(volatile int *)&v->counter;
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

#if defined(CONFIG_ARM_32)
# include <asm/arm32/atomic.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/atomic.h>
#else
# error "unknown ARM variant"
#endif

static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    return atomic_sub_return(i, v) == 0;
}

static inline void atomic_inc(atomic_t *v)
{
    atomic_add(1, v);
}

static inline int atomic_inc_return(atomic_t *v)
{
    return atomic_add_return(1, v);
}

static inline int atomic_inc_and_test(atomic_t *v)
{
    return atomic_add_return(1, v) == 0;
}

static inline void atomic_dec(atomic_t *v)
{
    atomic_sub(1, v);
}

static inline int atomic_dec_return(atomic_t *v)
{
    return atomic_sub_return(1, v);
}

static inline int atomic_dec_and_test(atomic_t *v)
{
    return atomic_sub_return(1, v) == 0;
}

static inline int atomic_add_negative(int i, atomic_t *v)
{
    return atomic_add_return(i, v) < 0;
}

static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
    return __atomic_add_unless(v, a, u);
}

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

#endif /* __ARCH_ARM_ATOMIC__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
