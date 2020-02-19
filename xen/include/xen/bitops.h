#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H
#include <asm/types.h>

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK(30, 21) gives us the 32bit vector 0x01fe00000.
 */
#define GENMASK(h, l) \
    (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
    (((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LLONG - 1 - (h))))

/*
 * ffs: find first bit set. This is defined the same way as
 * the libc and compiler builtin ffs routines, therefore
 * differs in spirit from the above ffz (man ffs).
 */

static inline int generic_ffs(int x)
{
    int r = 1;

    if (!x)
        return 0;
    if (!(x & 0xffff)) {
        x >>= 16;
        r += 16;
    }
    if (!(x & 0xff)) {
        x >>= 8;
        r += 8;
    }
    if (!(x & 0xf)) {
        x >>= 4;
        r += 4;
    }
    if (!(x & 3)) {
        x >>= 2;
        r += 2;
    }
    if (!(x & 1)) {
        x >>= 1;
        r += 1;
    }
    return r;
}

/*
 * fls: find last bit set.
 */

static __inline__ int generic_fls(int x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

#if BITS_PER_LONG == 64

static inline int generic_ffsl(unsigned long x)
{
    return !x || (u32)x ? generic_ffs(x) : generic_ffs(x >> 32) + 32;
}

static inline int generic_flsl(unsigned long x)
{
    u32 h = x >> 32;

    return h ? generic_fls(h) + 32 : generic_fls(x);
}

#else
# define generic_ffsl generic_ffs
# define generic_flsl generic_fls
#endif

/*
 * Include this here because some architectures need generic_ffs/fls in
 * scope
 */
#include <asm/bitops.h>

#if BITS_PER_LONG == 64
# define fls64 flsl
# define ffs64 ffsl
#else
# ifndef ffs64
static inline int generic_ffs64(__u64 x)
{
    return !x || (__u32)x ? ffs(x) : ffs(x >> 32) + 32;
}
#  define ffs64 generic_ffs64
# endif
# ifndef fls64
static inline int generic_fls64(__u64 x)
{
    __u32 h = x >> 32;

    return h ? fls(h) + 32 : fls(x);
}
#  define fls64 generic_fls64
# endif
#endif

static __inline__ int get_bitmask_order(unsigned int count)
{
    int order;
    
    order = fls(count);
    return order;   /* We could be slightly more clever with -1 here... */
}

static __inline__ int get_count_order(unsigned int count)
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

    w -= (w >> 1) & 0x5555555555555555ul;
    w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
    w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;

    if ( IS_ENABLED(CONFIG_HAS_FAST_MULTIPLY) )
        return (w * 0x0101010101010101ul) >> 56;

    w += w >> 8;
    w += w >> 16;

    return (w + (w >> 32)) & 0xFF;
}

static inline unsigned long hweight_long(unsigned long w)
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
#define __L2(_x)  (((_x) & 0x00000002) ?   1 : 0)
#define __L4(_x)  (((_x) & 0x0000000c) ? ( 2 + __L2( (_x)>> 2)) : __L2( _x))
#define __L8(_x)  (((_x) & 0x000000f0) ? ( 4 + __L4( (_x)>> 4)) : __L4( _x))
#define __L16(_x) (((_x) & 0x0000ff00) ? ( 8 + __L8( (_x)>> 8)) : __L8( _x))
#define ilog2(_x) (((_x) & 0xffff0000) ? (16 + __L16((_x)>>16)) : __L16(_x))

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

#endif
