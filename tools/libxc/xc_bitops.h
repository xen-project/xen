#ifndef XC_BITOPS_H
#define XC_BITOPS_H 1

/* bitmap operations for single threaded access */

#include <stdlib.h>
#include <string.h>

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define ORDER_LONG (sizeof(unsigned long) == 4 ? 5 : 6)

#define BITMAP_ENTRY(_nr,_bmap) ((_bmap))[(_nr)/BITS_PER_LONG]
#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

/* calculate required space for number of longs needed to hold nr_bits */
static inline int bitmap_size(int nr_bits)
{
    int nr_long, nr_bytes;
    nr_long = (nr_bits + BITS_PER_LONG - 1) >> ORDER_LONG;
    nr_bytes = nr_long * sizeof(unsigned long);
    return nr_bytes;
}

static inline unsigned long *bitmap_alloc(int nr_bits)
{
    return calloc(1, bitmap_size(nr_bits));
}

static inline void bitmap_clear(unsigned long *addr, int nr_bits)
{
    memset(addr, 0, bitmap_size(nr_bits));
}

static inline int test_bit(int nr, unsigned long *addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit(int nr, unsigned long *addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit(int nr, unsigned long *addr)
{
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

static inline int test_and_clear_bit(int nr, unsigned long *addr)
{
    int oldbit = test_bit(nr, addr);
    clear_bit(nr, addr);
    return oldbit;
}

static inline int test_and_set_bit(int nr, unsigned long *addr)
{
    int oldbit = test_bit(nr, addr);
    set_bit(nr, addr);
    return oldbit;
}

static inline void bitmap_or(unsigned long *dst, const unsigned long *other,
                             int nr_bits)
{
    int i, nr_longs = (bitmap_size(nr_bits) / sizeof(unsigned long));
    for ( i = 0; i < nr_longs; ++i )
        dst[i] |= other[i];
}

#endif  /* XC_BITOPS_H */
