#ifndef _ARM_ARM64_BITOPS_H
#define _ARM_ARM64_BITOPS_H

/* Generic bitop support. Based on linux/include/asm-generic/bitops/atomic.h */

#include <xen/spinlock.h>
#include <xen/cache.h>          /* we use L1_CACHE_BYTES */

/* Use an array of spinlocks for our atomic_ts.
 * Hash function to index into a different SPINLOCK.
 * Since "a" is usually an address, use one spinlock per cacheline.
 */
#  define ATOMIC_HASH_SIZE 4
#  define ATOMIC_HASH(a) (&(__atomic_hash[ (((unsigned long) a)/L1_CACHE_BYTES) & (ATOMIC_HASH_SIZE-1) ]))

extern spinlock_t __atomic_hash[ATOMIC_HASH_SIZE]/* __lock_aligned*/;

#define _atomic_spin_lock_irqsave(l,f) do {     \
       spinlock_t *s = ATOMIC_HASH(l);          \
       spin_lock_irqsave(s, f);\
} while(0)

#define _atomic_spin_unlock_irqrestore(l,f) do {\
        spinlock_t *s = ATOMIC_HASH(l);         \
        spin_unlock_irqrestore(s,f);		\
} while(0)

#define FIXUP(_p, _mask)                        \
    {                                           \
        unsigned long __p = (unsigned long)_p;  \
        if (__p & 0x7) {                        \
            if (_mask > 0xffffffff) {           \
             __p = (__p+32)&~0x7; _mask >>=32;  \
            } else {                            \
                __p &= ~0x7; _mask <<= 32;      \
            }                                   \
            if (0)printk("BITOPS: Fixup misaligned ptr %p => %#lx\n", _p, __p); \
            _p = (void *)__p;                   \
        }                                       \
    }

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writing portable code,
 * make sure not to rely on its reordering guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */

static inline void set_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long flags;

        //printk("set_bit: nr %d addr %p mask %#lx p %p lock %p\n",
        //       nr, addr, mask, p, ATOMIC_HASH(p));
        FIXUP(p, mask);
        //printk("set_bit: nr %d addr %p mask %#lx p %p lock %p\n",
        //       nr, addr, mask, p, ATOMIC_HASH(p));
        //printk("before *p is %#lx\n", *p);
	_atomic_spin_lock_irqsave(p, flags);
	*p  |= mask;
	_atomic_spin_unlock_irqrestore(p, flags);
        //printk(" after *p is %#lx\n", *p);
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
static inline void clear_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long flags;

        FIXUP(p, mask);

	_atomic_spin_lock_irqsave(p, flags);
	*p &= ~mask;
	_atomic_spin_unlock_irqrestore(p, flags);
}

/**
 * change_bit - Toggle a bit in memory
 * @nr: Bit to change
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered. It may be
 * reordered on other architectures than x86.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void change_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long flags;

        FIXUP(p, mask);

	_atomic_spin_lock_irqsave(p, flags);
	*p ^= mask;
	_atomic_spin_unlock_irqrestore(p, flags);
}

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It may be reordered on other architectures than x86.
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags;

        FIXUP(p, mask);

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old | mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It can be reorderdered on other architectures other than x86.
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags;

        FIXUP(p, mask);

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old & ~mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}

/**
 * test_and_change_bit - Change a bit and return its old value
 * @nr: Bit to change
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_change_bit(int nr, volatile void *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags;

        FIXUP(p, mask);

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old ^ mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}

/* Based on linux/include/asm-generic/bitops/builtin-__ffs.h */
/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static /*__*/always_inline unsigned long __ffs(unsigned long word)
{
        return __builtin_ctzl(word);
}

/* Based on linux/include/asm-generic/bitops/ffz.h */
/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))



/* Based on linux/include/asm-generic/bitops/find.h */

#ifndef find_next_bit
/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_bit(const unsigned long *addr, unsigned long
		size, unsigned long offset);
#endif

#ifndef find_next_zero_bit
/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_zero_bit(const unsigned long *addr, unsigned
		long size, unsigned long offset);
#endif

#ifdef CONFIG_GENERIC_FIND_FIRST_BIT

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first set bit.
 */
extern unsigned long find_first_bit(const unsigned long *addr,
				    unsigned long size);

/**
 * find_first_zero_bit - find the first cleared bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first cleared bit.
 */
extern unsigned long find_first_zero_bit(const unsigned long *addr,
					 unsigned long size);
#else /* CONFIG_GENERIC_FIND_FIRST_BIT */

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)
#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

#endif /* CONFIG_GENERIC_FIND_FIRST_BIT */


#endif /* _ARM_ARM64_BITOPS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
