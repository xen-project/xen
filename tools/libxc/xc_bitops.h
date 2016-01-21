#ifndef XC_BITOPS_H
#define XC_BITOPS_H 1

/* bitmap operations for single threaded access */

#include <stdlib.h>
#include <string.h>

/* Needed by several includees, but no longer used for bitops. */
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define ORDER_LONG (sizeof(unsigned long) == 4 ? 5 : 6)

#define BITMAP_ENTRY(_nr,_bmap) ((_bmap))[(_nr) / 8]
#define BITMAP_SHIFT(_nr) ((_nr) % 8)

/* calculate required space for number of longs needed to hold nr_bits */
static inline int bitmap_size(int nr_bits)
{
    return (nr_bits + 7) / 8;
}

static inline void *bitmap_alloc(int nr_bits)
{
    return calloc(1, bitmap_size(nr_bits));
}

static inline void bitmap_set(void *addr, int nr_bits)
{
    memset(addr, 0xff, bitmap_size(nr_bits));
}

static inline void bitmap_clear(void *addr, int nr_bits)
{
    memset(addr, 0, bitmap_size(nr_bits));
}

static inline int test_bit(int nr, const void *_addr)
{
    const char *addr = _addr;
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit(int nr, void *_addr)
{
    char *addr = _addr;
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit(int nr, void *_addr)
{
    char *addr = _addr;
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

static inline int test_and_clear_bit(int nr, void *addr)
{
    int oldbit = test_bit(nr, addr);
    clear_bit(nr, addr);
    return oldbit;
}

static inline int test_and_set_bit(int nr, void *addr)
{
    int oldbit = test_bit(nr, addr);
    set_bit(nr, addr);
    return oldbit;
}

static inline void bitmap_or(void *_dst, const void *_other,
                             int nr_bits)
{
    char *dst = _dst;
    const char *other = _other;
    int i;
    for ( i = 0; i < bitmap_size(nr_bits); ++i )
        dst[i] |= other[i];
}

#endif  /* XC_BITOPS_H */
