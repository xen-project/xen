#ifndef __X86_64_SYSTEM_H__
#define __X86_64_SYSTEM_H__

#define cmpxchg(ptr,o,n)                                                \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)(o),            \
                                   (unsigned long)(n),sizeof(*(ptr))))

/*
 * Atomic 16 bytes compare and exchange.  Compare OLD with MEM, if
 * identical, store NEW in MEM.  Return the initial value in MEM.
 * Success is indicated by comparing RETURN with OLD.
 *
 * This function can only be called when cpu_has_cx16 is true.
 */

static always_inline __uint128_t __cmpxchg16b(
    volatile void *ptr, const __uint128_t *oldp, const __uint128_t *newp)
{
    union {
        struct { uint64_t lo, hi; };
        __uint128_t raw;
    } new = { .raw = *newp }, old = { .raw = *oldp }, prev;

    ASSERT(cpu_has_cx16);

    /* Don't use "=A" here - clang can't deal with that. */
    asm volatile ( "lock cmpxchg16b %[ptr]"
                   : "=d" (prev.hi), "=a" (prev.lo),
                     [ptr] "+m" (*(volatile __uint128_t *)ptr)
                   : "c" (new.hi), "b" (new.lo), "d" (old.hi), "a" (old.lo) );

    return prev.raw;
}

static always_inline __uint128_t cmpxchg16b_local_(
    void *ptr, const __uint128_t *oldp, const __uint128_t *newp)
{
    union {
        struct { uint64_t lo, hi; };
        __uint128_t raw;
    } new = { .raw = *newp }, old = { .raw = *oldp }, prev;

    ASSERT(cpu_has_cx16);

    /* Don't use "=A" here - clang can't deal with that. */
    asm volatile ( "cmpxchg16b %[ptr]"
                   : "=d" (prev.hi), "=a" (prev.lo),
                     [ptr] "+m" (*(__uint128_t *)ptr)
                   : "c" (new.hi), "b" (new.lo), "d" (old.hi), "a" (old.lo) );

    return prev.raw;
}

#define cmpxchg16b(ptr, o, n) ({                           \
    volatile void *_p = (ptr);                             \
    ASSERT(!((unsigned long)_p & 0xf));                    \
    BUILD_BUG_ON(sizeof(*(o)) != sizeof(__uint128_t));     \
    BUILD_BUG_ON(sizeof(*(n)) != sizeof(__uint128_t));     \
    __cmpxchg16b(_p, (void *)(o), (void *)(n));            \
})

#endif /* __X86_64_SYSTEM_H__ */
