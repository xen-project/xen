#ifndef _X86_BITOPS_H
#define _X86_BITOPS_H

/*
 * Copyright 1992, Linus Torvalds.
 */

#include <xen/config.h>

#ifndef STR
#define __STR(x) #x
#define STR(x) __STR(x)
#endif

/*
 * These have to be done with inline assembly: that way the bit-setting
 * is guaranteed to be atomic. All bit operations return 0 if the bit
 * was cleared before the operation and != 0 if it was not.
 *
 * bit 0 is the LSB of addr; bit 32 is the LSB of (addr+1).
 */

#ifdef CONFIG_SMP
#define LOCK_PREFIX "lock ; "
#else
#define LOCK_PREFIX ""
#endif

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
		:"=m" (ADDR)
		:"dIr" (nr));
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
		:"=m" (ADDR)
		:"dIr" (nr));
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
		:"=m" (ADDR)
		:"dIr" (nr));
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
		:"=m" (ADDR)
		:"dIr" (nr));
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
		:"=m" (ADDR)
		:"dIr" (nr));
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
		:"=r" (oldbit),"=m" (ADDR)
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
		:"=r" (oldbit),"=m" (ADDR)
		:"dIr" (nr));
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
		:"=r" (oldbit),"=m" (ADDR)
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
		:"=r" (oldbit),"=m" (ADDR)
		:"dIr" (nr));
	return oldbit;
}

/* WARNING: non atomic and it can be reordered! */
static __inline__ int __test_and_change_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btcl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"=m" (ADDR)
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
		:"=r" (oldbit),"=m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}


static __inline__ int constant_test_bit(int nr, const volatile void * addr)
{
	return ((1UL << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
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

/**
 * find_first_zero_bit - find the first zero bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first zero bit, not the number of the byte
 * containing a bit.
 */
static inline long find_first_zero_bit(
    const unsigned long *addr, unsigned size)
{
	long d0, d1, d2;
	long res;

	__asm__ __volatile__(
		"mov $-1,%%"__OP"ax\n\t"
		"xor %%edx,%%edx\n\t"
		"repe; scas"__OS"\n\t"
		"je 1f\n\t"
		"lea -"STR(BITS_PER_LONG/8)"(%%"__OP"di),%%"__OP"di\n\t"
		"xor (%%"__OP"di),%%"__OP"ax\n\t"
		"bsf %%"__OP"ax,%%"__OP"dx\n"
		"1:\tsub %%"__OP"bx,%%"__OP"di\n\t"
		"shl $3,%%"__OP"di\n\t"
		"add %%"__OP"di,%%"__OP"dx"
		:"=d" (res), "=&c" (d0), "=&D" (d1), "=&a" (d2)
		:"1" ((size + 31) >> 5), "2" (addr), "b" (addr) : "memory");
	return res;
}

/**
 * find_next_zero_bit - find the first zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
long find_next_zero_bit(const unsigned long *addr, int size, int offset);

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first set bit, not the number of the byte
 * containing a bit.
 */
static inline long find_first_bit(
    const unsigned long *addr, unsigned size)
{
	long d0, d1;
	long res;

	__asm__ __volatile__(
		"xor %%eax,%%eax\n\t"
		"repe; scas"__OS"\n\t"
		"je 1f\n\t"
		"lea -"STR(BITS_PER_LONG/8)"(%%"__OP"di),%%"__OP"di\n\t"
		"bsf (%%"__OP"di),%%"__OP"ax\n"
		"1:\tsub %%"__OP"bx,%%"__OP"di\n\t"
		"shl $3,%%"__OP"di\n\t"
		"add %%"__OP"di,%%"__OP"ax"
		:"=a" (res), "=&c" (d0), "=&D" (d1)
		:"1" ((size + 31) >> 5), "2" (addr), "b" (addr) : "memory");
	return res;
}

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
long find_next_bit(const unsigned long *addr, int size, int offset);

/* return index of first bet set in val or max when no bit is set */
static inline unsigned long __scanbit(unsigned long val, unsigned long max)
{
	asm("bsf %1,%0 ; cmovz %2,%0" : "=&r" (val) : "r" (val), "r" (max));
	return val;
}

#define find_first_bit(addr,size) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  (__scanbit(*(unsigned long *)addr,(size))) : \
  find_first_bit(addr,size)))

#define find_next_bit(addr,size,off) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ?         \
  ((off) + (__scanbit((*(unsigned long *)addr) >> (off),(size)-(off)))) : \
  find_next_bit(addr,size,off)))

#define find_first_zero_bit(addr,size) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ? \
  (__scanbit(~*(unsigned long *)addr,(size))) : \
  find_first_zero_bit(addr,size)))
        
#define find_next_zero_bit(addr,size,off) \
((__builtin_constant_p(size) && (size) <= BITS_PER_LONG ?         \
  ((off)+(__scanbit(~(((*(unsigned long *)addr)) >> (off)),(size)-(off)))) : \
  find_next_zero_bit(addr,size,off)))


/*
 * These are the preferred 'find first' functions in Xen.
 * Both return the appropriate bit index, with the l.s.b. having index 0.
 * If an appropriate bit is not found then the result is undefined.
 */
static __inline__ unsigned long find_first_clear_bit(unsigned long word)
{
	__asm__("bsf"__OS" %1,%0"
		:"=r" (word)
		:"r" (~word));
	return word;
}

static __inline__ unsigned long find_first_set_bit(unsigned long word)
{
	__asm__("bsf"__OS" %1,%0"
		:"=r" (word)
		:"r" (word));
	return word;
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

#define ext2_set_bit                 __test_and_set_bit
#define ext2_clear_bit               __test_and_clear_bit
#define ext2_test_bit                test_bit
#define ext2_find_first_zero_bit     find_first_zero_bit
#define ext2_find_next_zero_bit      find_next_zero_bit

/* Bitmap functions for the minix filesystem.  */
#define minix_test_and_set_bit(nr,addr) __test_and_set_bit(nr,addr)
#define minix_set_bit(nr,addr) __set_bit(nr,addr)
#define minix_test_and_clear_bit(nr,addr) __test_and_clear_bit(nr,addr)
#define minix_test_bit(nr,addr) test_bit(nr,addr)
#define minix_find_first_zero_bit(addr,size) find_first_zero_bit(addr,size)

#endif /* _X86_BITOPS_H */
