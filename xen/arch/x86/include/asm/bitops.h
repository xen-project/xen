#ifndef _X86_BITOPS_H
#define _X86_BITOPS_H

/*
 * Copyright 1992, Linus Torvalds.
 */

#include <asm/alternative.h>
#include <asm/asm_defns.h>
#include <asm/cpufeatureset.h>

/*
 * We specify the memory operand as both input and output because the memory
 * operand is both read from and written to. Since the operand is in fact a
 * word array, we also specify "memory" in the clobbers list to indicate that
 * words other than the one directly addressed by the memory operand may be
 * modified.
 */

#define ADDR (*(volatile int *) addr)
#define CONST_ADDR (*(const volatile int *) addr)

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void set_bit(int nr, volatile void *addr)
{
    asm volatile ( "lock; btsl %1,%0"
                   : "+m" (ADDR) : "Ir" (nr) : "memory");
}
#define set_bit(nr, addr) ({                            \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    set_bit(nr, addr);                                  \
})

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void variable_set_bit(int nr, void *addr)
{
    asm volatile ( "btsl %1,%0" : "+m" (*(int *)addr) : "Ir" (nr) : "memory" );
}
static inline void constant_set_bit(int nr, void *addr)
{
    ((unsigned int *)addr)[nr >> 5] |= (1u << (nr & 31));
}
#define __set_bit(nr, addr) ({                          \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    __builtin_constant_p(nr) ?                          \
        constant_set_bit(nr, addr) :                    \
        variable_set_bit(nr, addr);                     \
})

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.
 */
static inline void clear_bit(int nr, volatile void *addr)
{
    asm volatile ( "lock; btrl %1,%0"
                   : "+m" (ADDR) : "Ir" (nr) : "memory");
}
#define clear_bit(nr, addr) ({                          \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    clear_bit(nr, addr);                                \
})

/**
 * __clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * Unlike clear_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void variable_clear_bit(int nr, void *addr)
{
    asm volatile ( "btrl %1,%0" : "+m" (*(int *)addr) : "Ir" (nr) : "memory" );
}
static inline void constant_clear_bit(int nr, void *addr)
{
    ((unsigned int *)addr)[nr >> 5] &= ~(1u << (nr & 31));
}
#define __clear_bit(nr, addr) ({                        \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    __builtin_constant_p(nr) ?                          \
        constant_clear_bit(nr, addr) :                  \
        variable_clear_bit(nr, addr);                   \
})

/**
 * __change_bit - Toggle a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike change_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void variable_change_bit(int nr, void *addr)
{
    asm volatile ( "btcl %1,%0" : "+m" (*(int *)addr) : "Ir" (nr) : "memory" );
}
static inline void constant_change_bit(int nr, void *addr)
{
    ((unsigned int *)addr)[nr >> 5] ^= (1u << (nr & 31));
}
#define __change_bit(nr, addr) ({                       \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    __builtin_constant_p(nr) ?                          \
        constant_change_bit(nr, addr) :                 \
        variable_change_bit(nr, addr);                  \
})

/**
 * change_bit - Toggle a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void change_bit(int nr, volatile void *addr)
{
    asm volatile ( "lock; btcl %1,%0"
                    : "+m" (ADDR) : "Ir" (nr) : "memory");
}
#define change_bit(nr, addr) ({                         \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    change_bit(nr, addr);                               \
})

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "lock; btsl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (ADDR) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define test_and_set_bit(nr, addr) ({                   \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    test_and_set_bit(nr, addr);                         \
})

/**
 * arch__test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.  
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int arch__test_and_set_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "btsl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (*(int *)addr) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define arch__test_and_set_bit arch__test_and_set_bit

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "lock; btrl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (ADDR) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define test_and_clear_bit(nr, addr) ({                 \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    test_and_clear_bit(nr, addr);                       \
})

/**
 * arch__test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.  
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int arch__test_and_clear_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "btrl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (*(int *)addr) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define arch__test_and_clear_bit arch__test_and_clear_bit

/* WARNING: non atomic and it can be reordered! */
static inline int arch__test_and_change_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "btcl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (*(int *)addr) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define arch__test_and_change_bit arch__test_and_change_bit

/**
 * test_and_change_bit - Change a bit and return its new value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static inline int test_and_change_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile ( "lock; btcl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit),
                     [addr] "+m" (ADDR) : [nr] "Ir" (nr) : "memory" );

    return oldbit;
}
#define test_and_change_bit(nr, addr) ({                \
    if ( bitop_bad_size(addr) ) __bitop_bad_size();     \
    test_and_change_bit(nr, addr);                      \
})

static inline int variable_test_bit(int nr, const volatile void *addr)
{
    int oldbit;

    asm volatile ( "btl %[nr], %[addr]\n\t"
                   ASM_FLAG_OUT(, "sbbl %[old], %[old]\n\t")
                   : [old] ASM_FLAG_OUT("=@ccc", "=r") (oldbit)
                   : [addr] "m" (CONST_ADDR), [nr] "Ir" (nr) : "memory" );

    return oldbit;
}

#define arch_test_bit(nr, addr) ({                      \
    __builtin_constant_p(nr) ?                          \
        generic_test_bit(nr, addr) :                    \
        variable_test_bit(nr, addr);                    \
})

extern unsigned int __find_first_bit(
    const unsigned long *addr, unsigned int size);
extern unsigned int __find_next_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset);
extern unsigned int __find_first_zero_bit(
    const unsigned long *addr, unsigned int size);
extern unsigned int __find_next_zero_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset);

static always_inline unsigned int __scanbit(unsigned long val, unsigned int max)
{
    if ( __builtin_constant_p(max) && max == BITS_PER_LONG )
        alternative_io("bsf %[in],%[out]; cmovz %[max],%k[out]",
                       "rep; bsf %[in],%[out]",
                       X86_FEATURE_BMI1,
                       [out] "=&r" (val),
                       [in] "r" (val), [max] "r" (max));
    else
        asm ( "bsf %1,%0 ; cmovz %2,%k0"
              : "=&r" (val) : "r" (val), "r" (max) );
    return (unsigned int)val;
}

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first set bit, not the number of the byte
 * containing a bit.
 */
#define find_first_bit(addr, size) find_next_bit(addr, size, 0)

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
#define find_next_bit(addr, size, off) ({                                   \
    unsigned int r__;                                                       \
    const unsigned long *a__ = (addr);                                      \
    unsigned int s__ = (size);                                              \
    unsigned int o__ = (off);                                               \
    if ( o__ >= s__ )                                                       \
        r__ = s__;                                                          \
    else if ( __builtin_constant_p(size) && s__ <= BITS_PER_LONG )          \
        r__ = o__ + __scanbit(*(const unsigned long *)(a__) >> o__, s__);   \
    else if ( __builtin_constant_p(off) && !o__ )                           \
        r__ = __find_first_bit(a__, s__);                                   \
    else                                                                    \
        r__ = __find_next_bit(a__, s__, o__);                               \
    r__;                                                                    \
})

/**
 * find_first_zero_bit - find the first zero bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first zero bit, not the number of the byte
 * containing a bit.
 */
#define find_first_zero_bit(addr, size) find_next_zero_bit(addr, size, 0)

/**
 * find_next_zero_bit - find the first zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
#define find_next_zero_bit(addr, size, off) ({                              \
    unsigned int r__;                                                       \
    const unsigned long *a__ = (addr);                                      \
    unsigned int s__ = (size);                                              \
    unsigned int o__ = (off);                                               \
    if ( o__ >= s__ )                                                       \
        r__ = s__;                                                          \
    else if ( __builtin_constant_p(size) && s__ <= BITS_PER_LONG )          \
        r__ = o__ + __scanbit(~*(const unsigned long *)(a__) >> o__, s__);  \
    else if ( __builtin_constant_p(off) && !o__ )                           \
        r__ = __find_first_zero_bit(a__, s__);                              \
    else                                                                    \
        r__ = __find_next_zero_bit(a__, s__, o__);                          \
    r__;                                                                    \
})

static always_inline unsigned int arch_ffs(unsigned int x)
{
    unsigned int r;

    if ( __builtin_constant_p(x > 0) && x > 0 )
    {
        /*
         * A common code pattern is:
         *
         *     while ( bits )
         *     {
         *         bit = ffs(bits);
         *         ...
         *
         * and the optimiser really can work with the knowledge of x being
         * non-zero without knowing it's exact value, in which case we don't
         * need to compensate for BSF's corner cases.  Otherwise...
         */
        asm ( "bsf %[val], %[res]"
              : [res] "=r" (r)
              : [val] "rm" (x) );
    }
    else
    {
        /*
         * ... the AMD manual states that BSF won't modify the destination
         * register if x=0.  The Intel manual states that the result is
         * undefined, but the architects have said that the register is
         * written back with it's old value (zero extended as normal).
         */
        asm ( "bsf %[val], %[res]"
              : [res] "=r" (r)
              : [val] "rm" (x), "[res]" (-1) );
    }

    return r + 1;
}
#define arch_ffs arch_ffs

static always_inline unsigned int arch_ffsl(unsigned long x)
{
    unsigned int r;

    /* See arch_ffs() for safety discussions. */
    if ( __builtin_constant_p(x > 0) && x > 0 )
        asm ( "bsf %[val], %q[res]"
              : [res] "=r" (r)
              : [val] "rm" (x) );
    else
        asm ( "bsf %[val], %q[res]"
              : [res] "=r" (r)
              : [val] "rm" (x), "[res]" (-1) );

    return r + 1;
}
#define arch_ffsl arch_ffsl

static always_inline unsigned int arch_fls(unsigned int x)
{
    unsigned int r;

    /* See arch_ffs() for safety discussions. */
    if ( __builtin_constant_p(x > 0) && x > 0 )
        asm ( "bsr %[val], %[res]"
              : [res] "=r" (r)
              : [val] "rm" (x) );
    else
        asm ( "bsr %[val], %[res]"
              : [res] "=r" (r)
              : [val] "rm" (x), "[res]" (-1) );

    return r + 1;
}
#define arch_fls arch_fls

static always_inline unsigned int arch_flsl(unsigned long x)
{
    unsigned int r;

    /* See arch_ffs() for safety discussions. */
    if ( __builtin_constant_p(x > 0) && x > 0 )
        asm ( "bsr %[val], %q[res]"
              : [res] "=r" (r)
              : [val] "rm" (x) );
    else
        asm ( "bsr %[val], %q[res]"
              : [res] "=r" (r)
              : [val] "rm" (x), "[res]" (-1) );

    return r + 1;
}
#define arch_flsl arch_flsl

unsigned int arch_generic_hweightl(unsigned long x);

static always_inline unsigned int arch_hweightl(unsigned long x)
{
    unsigned int r;

    /*
     * arch_generic_hweightl() is written in ASM in order to preserve all
     * registers, as the compiler can't see the call.
     *
     * This limits the POPCNT instruction to using the same ABI as a function
     * call (input in %rdi, output in %eax) but that's fine.
     */
    alternative_io("call arch_generic_hweightl",
                   "popcnt %[val], %q[res]", X86_FEATURE_POPCNT,
                   ASM_OUTPUT2([res] "=a" (r) ASM_CALL_CONSTRAINT),
                   [val] "D" (x));

    return r;
}
#define arch_hweightl arch_hweightl

#endif /* _X86_BITOPS_H */
