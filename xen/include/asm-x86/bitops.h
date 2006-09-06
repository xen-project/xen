#ifndef _X86_BITOPS_H
#define _X86_BITOPS_H

/*
 * Copyright 1992, Linus Torvalds.
 */

#include <xen/config.h>

#ifdef CONFIG_SMP
#define LOCK_PREFIX "lock ; "
#else
#define LOCK_PREFIX ""
#endif

/*
 * We use the "+m" constraint because the memory operand is both read from
 * and written to. Since the operand is in fact a word array, we also
 * specify "memory" in the clobbers list to indicate that words other than
 * the one directly addressed by the memory operand may be modified.
 */

#define ADDR (*(volatile long *) addr)

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
static __inline__ void set_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__( LOCK_PREFIX
		"btsl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static __inline__ void __set_bit(int nr, volatile void * addr)
{
	__asm__(
		"btsl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static __inline__ void clear_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__( LOCK_PREFIX
		"btrl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * __clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * Unlike clear_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static __inline__ void __clear_bit(int nr, volatile void * addr)
{
	__asm__(
		"btrl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

#define smp_mb__before_clear_bit()	barrier()
#define smp_mb__after_clear_bit()	barrier()

/**
 * __change_bit - Toggle a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike change_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static __inline__ void __change_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__(
		"btcl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * change_bit - Toggle a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __inline__ void change_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__( LOCK_PREFIX
		"btcl %1,%0"
		:"+m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static __inline__ int test_and_set_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__( LOCK_PREFIX
		"btsl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.  
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static __inline__ int __test_and_set_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__(
		"btsl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static __inline__ int test_and_clear_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__( LOCK_PREFIX
		"btrl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.  
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static __inline__ int __test_and_clear_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__(
		"btrl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

/* WARNING: non atomic and it can be reordered! */
static __inline__ int __test_and_change_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btcl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

/**
 * test_and_change_bit - Change a bit and return its new value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static __inline__ int test_and_change_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__( LOCK_PREFIX
		"btcl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"+m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}


static __inline__ int constant_test_bit(int nr, const volatile void * addr)
{
	return ((1U << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int variable_test_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit)
		:"m" (ADDR),"dIr" (nr));
	return oldbit;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))

extern unsigned int __find_first_bit(
    const unsigned long *addr, unsigned int size);
extern unsigned int __find_next_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset);
extern unsigned int __find_first_zero_bit(
    const unsigned long *addr, unsigned int size);
extern unsigned int __find_next_zero_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset);

/* return index of first bit set in val or BITS_PER_LONG when no bit is set */
static inline unsigned int __scanbit(unsigned long val)
{
	__asm__ ( "bsf %1,%0" : "=r" (val) : "r" (val), "0" (BITS_PER_LONG) );
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
#define find_first_bit(addr,size) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  (__scanbit(*(unsigned long *)addr)) : \
  __find_first_bit(addr,size)))

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
#define find_next_bit(addr,size,off) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  ((off) + (__scanbit((*(unsigned long *)addr) >> (off)))) : \
  __find_next_bit(addr,size,off)))

/**
 * find_first_zero_bit - find the first zero bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first zero bit, not the number of the byte
 * containing a bit.
 */
#define find_first_zero_bit(addr,size) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  (__scanbit(~*(unsigned long *)addr)) : \
  __find_first_zero_bit(addr,size)))

/**
 * find_next_zero_bit - find the first zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
#define find_next_zero_bit(addr,size,off) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  ((off)+(__scanbit(~(((*(unsigned long *)addr)) >> (off))))) : \
  __find_next_zero_bit(addr,size,off)))


/**
 * find_first_set_bit - find the first set bit in @word
 * @word: the word to search
 * 
 * Returns the bit-number of the first set bit. If no bits are set then the
 * result is undefined.
 */
static __inline__ unsigned int find_first_set_bit(unsigned long word)
{
	__asm__ ( "bsf %1,%0" : "=r" (word) : "r" (word) );
	return (unsigned int)word;
}

/**
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static inline unsigned long ffz(unsigned long word)
{
	__asm__("bsf %1,%0"
		:"=r" (word)
		:"r" (~word));
	return word;
}

/**
 * ffs - find first bit set
 * @x: the word to search
 *
 * This is defined the same way as
 * the libc and compiler builtin ffs routines, therefore
 * differs in spirit from the above ffz (man ffs).
 */
static inline int ffs(unsigned long x)
{
	long r;

	__asm__("bsf %1,%0\n\t"
		"jnz 1f\n\t"
		"mov $-1,%0\n"
		"1:" : "=r" (r) : "rm" (x));
	return (int)r+1;
}

/**
 * fls - find last bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 */
static inline int fls(unsigned long x)
{
	long r;

	__asm__("bsr %1,%0\n\t"
		"jnz 1f\n\t"
		"mov $-1,%0\n"
		"1:" : "=r" (r) : "rm" (x));
	return (int)r+1;
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

#endif /* _X86_BITOPS_H */
