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
    asm volatile ( "lock; cmpxchg16b %2"
                   : "=d" (prev.hi), "=a" (prev.lo), "+m" (*__xg(ptr))
                   : "c" (new.hi), "b" (new.lo), "0" (old.hi), "1" (old.lo) );

    return prev.raw;
}

#define cmpxchg16b(ptr, o, n) ({                           \
    volatile void *_p = (ptr);                             \
    ASSERT(!((unsigned long)_p & 0xf));                    \
    BUILD_BUG_ON(sizeof(*(o)) != sizeof(__uint128_t));     \
    BUILD_BUG_ON(sizeof(*(n)) != sizeof(__uint128_t));     \
    __cmpxchg16b(_p, (void *)(o), (void *)(n));            \
})

/*
 * This function causes value _o to be changed to _n at location _p.
 * If this access causes a fault then we return 1, otherwise we return 0.
 * If no fault occurs then _o is updated to the value we saw at _p. If this
 * is the same as the initial value of _o then _n is written to location _p.
 */
#define __cmpxchg_user(_p,_o,_n,_isuff,_oppre,_regtype)                 \
    stac();                                                             \
    asm volatile (                                                      \
        "1: lock; cmpxchg"_isuff" %"_oppre"2,%3\n"                      \
        "2:\n"                                                          \
        ".section .fixup,\"ax\"\n"                                      \
        "3:     movl $1,%1\n"                                           \
        "       jmp 2b\n"                                               \
        ".previous\n"                                                   \
        _ASM_EXTABLE(1b, 3b)                                            \
        : "=a" (_o), "=r" (_rc)                                         \
        : _regtype (_n), "m" (*__xg((volatile void *)_p)), "0" (_o), "1" (0) \
        : "memory");                                                    \
    clac()

#define cmpxchg_user(_p,_o,_n)                                          \
({                                                                      \
    int _rc;                                                            \
    switch ( sizeof(*(_p)) ) {                                          \
    case 1:                                                             \
        __cmpxchg_user(_p,_o,_n,"b","b","q");                           \
        break;                                                          \
    case 2:                                                             \
        __cmpxchg_user(_p,_o,_n,"w","w","r");                           \
        break;                                                          \
    case 4:                                                             \
        __cmpxchg_user(_p,_o,_n,"l","k","r");                           \
        break;                                                          \
    case 8:                                                             \
        __cmpxchg_user(_p,_o,_n,"q","","r");                            \
        break;                                                          \
    }                                                                   \
    _rc;                                                                \
})

#define mb()                    \
    asm volatile ( "mfence" : : : "memory" )

#endif /* __X86_64_SYSTEM_H__ */
