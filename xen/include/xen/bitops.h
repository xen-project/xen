#ifndef XEN_BITOPS_H
#define XEN_BITOPS_H

#include <xen/compiler.h>
#include <xen/types.h>

#include <asm/bitops.h>

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example GENMASK(30, 21) gives us 0x7fe00000ul.
 */
#define GENMASK(h, l) \
    (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
    (((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LLONG - 1 - (h))))

/*
 * Find First/Last Set bit (all forms).
 *
 * Bits are labelled from 1.  Returns 0 if given 0.
 */
unsigned int __pure generic_ffsl(unsigned long x);
unsigned int __pure generic_flsl(unsigned long x);

static always_inline __pure unsigned int ffs(unsigned int x)
{
    if ( __builtin_constant_p(x) )
        return __builtin_ffs(x);

#ifdef arch_ffs
    return arch_ffs(x);
#else
    return generic_ffsl(x);
#endif
}

static always_inline __pure unsigned int ffsl(unsigned long x)
{
    if ( __builtin_constant_p(x) )
        return __builtin_ffsl(x);

#ifdef arch_ffs
    return arch_ffsl(x);
#else
    return generic_ffsl(x);
#endif
}

static always_inline __pure unsigned int ffs64(uint64_t x)
{
    if ( BITS_PER_LONG == 64 )
        return ffsl(x);
    else
        return !x || (uint32_t)x ? ffs(x) : ffs(x >> 32) + 32;
}

static always_inline __pure unsigned int fls(unsigned int x)
{
    if ( __builtin_constant_p(x) )
        return x ? 32 - __builtin_clz(x) : 0;

#ifdef arch_fls
    return arch_fls(x);
#else
    return generic_flsl(x);
#endif
}

static always_inline __pure unsigned int flsl(unsigned long x)
{
    if ( __builtin_constant_p(x) )
        return x ? BITS_PER_LONG - __builtin_clzl(x) : 0;

#ifdef arch_fls
    return arch_flsl(x);
#else
    return generic_flsl(x);
#endif
}

static always_inline __pure unsigned int fls64(uint64_t x)
{
    if ( BITS_PER_LONG == 64 )
        return flsl(x);
    else
    {
        uint32_t h = x >> 32;

        return h ? fls(h) + 32 : fls(x);
    }
}

/* --------------------- Please tidy below here --------------------- */

#ifndef find_next_bit
/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_bit(const unsigned long *addr,
                                   unsigned long size,
                                   unsigned long offset);
#endif

#ifndef find_next_zero_bit
/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
extern unsigned long find_next_zero_bit(const unsigned long *addr,
                                        unsigned long size,
                                        unsigned long offset);
#endif

#ifndef find_first_bit
/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first set bit.
 */
extern unsigned long find_first_bit(const unsigned long *addr,
                                    unsigned long size);
#endif

#ifndef find_first_zero_bit
/**
 * find_first_zero_bit - find the first cleared bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit number of the first cleared bit.
 */
extern unsigned long find_first_zero_bit(const unsigned long *addr,
                                         unsigned long size);
#endif

static inline int get_bitmask_order(unsigned int count)
{
    int order;
    
    order = fls(count);
    return order;   /* We could be slightly more clever with -1 here... */
}

static inline int get_count_order(unsigned int count)
{
    int order;

    order = fls(count) - 1;
    if (count & (count - 1))
        order++;
    return order;
}

/*
 * hweightN: returns the hamming weight (i.e. the number
 * of bits set) of a N-bit word
 */

static inline unsigned int generic_hweight32(unsigned int w)
{
    w -= (w >> 1) & 0x55555555;
    w =  (w & 0x33333333) + ((w >> 2) & 0x33333333);
    w =  (w + (w >> 4)) & 0x0f0f0f0f;

    if ( IS_ENABLED(CONFIG_HAS_FAST_MULTIPLY) )
        return (w * 0x01010101) >> 24;

    w += w >> 8;

    return (w + (w >> 16)) & 0xff;
}

static inline unsigned int generic_hweight16(unsigned int w)
{
    w -= ((w >> 1) & 0x5555);
    w =  (w & 0x3333) + ((w >> 2) & 0x3333);
    w =  (w + (w >> 4)) & 0x0f0f;

    return (w + (w >> 8)) & 0xff;
}

static inline unsigned int generic_hweight8(unsigned int w)
{
    w -= ((w >> 1) & 0x55);
    w =  (w & 0x33) + ((w >> 2) & 0x33);

    return (w + (w >> 4)) & 0x0f;
}

static inline unsigned int generic_hweight64(uint64_t w)
{
    if ( BITS_PER_LONG < 64 )
        return generic_hweight32(w >> 32) + generic_hweight32(w);

    w -= (w >> 1) & 0x5555555555555555UL;
    w =  (w & 0x3333333333333333UL) + ((w >> 2) & 0x3333333333333333UL);
    w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0fUL;

    if ( IS_ENABLED(CONFIG_HAS_FAST_MULTIPLY) )
        return (w * 0x0101010101010101UL) >> 56;

    w += w >> 8;
    w += w >> 16;

    return (w + (w >> 32)) & 0xFF;
}

static inline unsigned int hweight_long(unsigned long w)
{
    return sizeof(w) == 4 ? generic_hweight32(w) : generic_hweight64(w);
}

/*
 * rol32 - rotate a 32-bit value left
 *
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}

/*
 * ror32 - rotate a 32-bit value right
 *
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 ror32(__u32 word, unsigned int shift)
{
    return (word >> shift) | (word << (32 - shift));
}

/* base-2 logarithm */
#define __L2(x)  (((x) & 0x00000002U) ?   1                     : 0)
#define __L4(x)  (((x) & 0x0000000cU) ? ( 2 + __L2( (x) >> 2))  : __L2( x))
#define __L8(x)  (((x) & 0x000000f0U) ? ( 4 + __L4( (x) >> 4))  : __L4( x))
#define __L16(x) (((x) & 0x0000ff00U) ? ( 8 + __L8( (x) >> 8))  : __L8( x))
#define ilog2(x) (((x) & 0xffff0000U) ? (16 + __L16((x) >> 16)) : __L16(x))

/**
 * for_each_set_bit - iterate over every set bit in a memory region
 * @bit: The integer iterator
 * @addr: The address to base the search on
 * @size: The maximum size to search
 */
#define for_each_set_bit(bit, addr, size)               \
    for ( (bit) = find_first_bit(addr, size);           \
          (bit) < (size);                               \
          (bit) = find_next_bit(addr, size, (bit) + 1) )

#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#endif /* XEN_BITOPS_H */
