/*
 * Copyright 1995, Russell King.
 * Various bits and pieces copyrights include:
 *  Linus Torvalds (test_bit).
 * Big endian support: Copyright 2001, Nicolas Pitre
 *  reworked by rmk.
 */

#ifndef _ARM_BITOPS_H
#define _ARM_BITOPS_H

#include <asm/asm_defns.h>

/*
 * Non-atomic bit manipulation.
 *
 * Implemented using atomics to be interrupt safe. Could alternatively
 * implement with local interrupt masking.
 */
#define __set_bit(n,p)            set_bit(n,p)
#define __clear_bit(n,p)          clear_bit(n,p)

#define BITS_PER_WORD           32
#define BIT(nr)                 (1UL << (nr))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_WORD))
#define BIT_WORD(nr)            ((nr) / BITS_PER_WORD)
#define BITS_PER_BYTE           8

#define ADDR (*(volatile int *) addr)
#define CONST_ADDR (*(const volatile int *) addr)

#if defined(CONFIG_ARM_32)
# include <asm/arm32/bitops.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/bitops.h>
#else
# error "unknown ARM variant"
#endif

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_set_bit(int nr, volatile void *addr)
{
        unsigned int mask = BIT_MASK(nr);
        volatile unsigned int *p =
                ((volatile unsigned int *)addr) + BIT_WORD(nr);
        unsigned int old = *p;

        *p = old | mask;
        return (old & mask) != 0;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_clear_bit(int nr, volatile void *addr)
{
        unsigned int mask = BIT_MASK(nr);
        volatile unsigned int *p =
                ((volatile unsigned int *)addr) + BIT_WORD(nr);
        unsigned int old = *p;

        *p = old & ~mask;
        return (old & mask) != 0;
}

/* WARNING: non atomic and it can be reordered! */
static inline int __test_and_change_bit(int nr,
                                            volatile void *addr)
{
        unsigned int mask = BIT_MASK(nr);
        volatile unsigned int *p =
                ((volatile unsigned int *)addr) + BIT_WORD(nr);
        unsigned int old = *p;

        *p = old ^ mask;
        return (old & mask) != 0;
}

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile void *addr)
{
        const volatile unsigned int *p = (const volatile unsigned int *)addr;
        return 1UL & (p[BIT_WORD(nr)] >> (nr & (BITS_PER_WORD-1)));
}

/*
 * On ARMv5 and above those functions can be implemented around
 * the clz instruction for much better code efficiency.
 */

static inline int fls(unsigned int x)
{
        int ret;

        if (__builtin_constant_p(x))
               return generic_fls(x);

        asm("clz\t%"__OP32"0, %"__OP32"1" : "=r" (ret) : "r" (x));
        return 32 - ret;
}


#define ffs(x) ({ unsigned int __t = (x); fls(__t & -__t); })
#define ffsl(x) ({ unsigned long __t = (x); flsl(__t & -__t); })

/**
 * find_first_set_bit - find the first set bit in @word
 * @word: the word to search
 *
 * Returns the bit-number of the first set bit (first bit being 0).
 * The input must *not* be zero.
 */
static inline unsigned int find_first_set_bit(unsigned long word)
{
        return ffsl(word) - 1;
}

/**
 * hweightN - returns the hamming weight of a N-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 */
#define hweight64(x) generic_hweight64(x)
#define hweight32(x) generic_hweight32(x)
#define hweight16(x) generic_hweight16(x)
#define hweight8(x) generic_hweight8(x)

#endif /* _ARM_BITOPS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
