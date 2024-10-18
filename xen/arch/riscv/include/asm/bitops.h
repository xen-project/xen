/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2012 Regents of the University of California */

#ifndef ASM__RISCV__BITOPS_H
#define ASM__RISCV__BITOPS_H

#include <asm/system.h>

#if BITOP_BITS_PER_WORD == 64
#define __AMO(op)   "amo" #op ".d"
#elif BITOP_BITS_PER_WORD == 32
#define __AMO(op)   "amo" #op ".w"
#else
#error "Unexpected BITOP_BITS_PER_WORD"
#endif

/* Based on linux/arch/include/asm/bitops.h */

/*
 * Non-atomic bit manipulation.
 *
 * Implemented using atomics to be interrupt safe. Could alternatively
 * implement with local interrupt masking.
 */
#define __set_bit(n, p)      set_bit(n, p)
#define __clear_bit(n, p)    clear_bit(n, p)

#define test_and_op_bit_ord(op, mod, nr, addr, ord)     \
({                                                      \
    bitop_uint_t res, mask;                             \
    mask = BITOP_MASK(nr);                              \
    asm volatile (                                      \
        __AMO(op) #ord " %0, %2, %1"                    \
        : "=r" (res), "+A" (addr[BITOP_WORD(nr)])       \
        : "r" (mod(mask))                               \
        : "memory");                                    \
    ((res & mask) != 0);                                \
})

#define op_bit_ord(op, mod, nr, addr, ord)      \
    asm volatile (                              \
        __AMO(op) #ord " zero, %1, %0"          \
        : "+A" (addr[BITOP_WORD(nr)])           \
        : "r" (mod(BITOP_MASK(nr)))             \
        : "memory");

#define test_and_op_bit(op, mod, nr, addr)    \
    test_and_op_bit_ord(op, mod, nr, addr, .aqrl)
#define op_bit(op, mod, nr, addr) \
    op_bit_ord(op, mod, nr, addr, )

/* Bitmask modifiers */
#define NOP(x)    (x)
#define NOT(x)    (~(x))

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 */
static inline bool test_and_set_bit(int nr, volatile void *p)
{
    volatile bitop_uint_t *addr = p;

    return test_and_op_bit(or, NOP, nr, addr);
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 */
static inline bool test_and_clear_bit(int nr, volatile void *p)
{
    volatile bitop_uint_t *addr = p;

    return test_and_op_bit(and, NOT, nr, addr);
}

/**
 * test_and_change_bit - Toggle (change) a bit and return its old value
 * @nr: Bit to change
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline bool test_and_change_bit(int nr, volatile void *p)
{
    volatile bitop_uint_t *addr = p;

    return test_and_op_bit(xor, NOP, nr, addr);
}

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void set_bit(int nr, volatile void *p)
{
    volatile bitop_uint_t *addr = p;

    op_bit(or, NOP, nr, addr);
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 */
static inline void clear_bit(int nr, volatile void *p)
{
    volatile bitop_uint_t *addr = p;

    op_bit(and, NOT, nr, addr);
}

#undef test_and_op_bit
#undef op_bit
#undef NOP
#undef NOT
#undef __AMO

#endif /* ASM__RISCV__BITOPS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
