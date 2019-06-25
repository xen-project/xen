/*
 * lib/bitmap.c
 * Helper functions for bitmap.h.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/bitmap.h>
#include <xen/bitops.h>
#include <asm/byteorder.h>

/*
 * bitmaps provide an array of bits, implemented using an an
 * array of unsigned longs.  The number of valid bits in a
 * given bitmap does _not_ need to be an exact multiple of
 * BITS_PER_LONG.
 *
 * The possible unused bits in the last, partially used word
 * of a bitmap are 'don't care'.  The implementation makes
 * no particular effort to keep them zero.  It ensures that
 * their value will not affect the results of any operation.
 * The bitmap operations that return Boolean (bitmap_empty,
 * for example) or scalar (bitmap_weight, for example) results
 * carefully filter out these unused bits from impacting their
 * results.
 *
 * These operations actually hold to a slightly stronger rule:
 * if you don't input any bitmaps to these ops that have some
 * unused bits set, then they won't output any set unused bits
 * in output bitmaps.
 *
 * The byte ordering of bitmaps is more natural on little
 * endian architectures.  See the big-endian headers
 * include/asm-ppc64/bitops.h and include/asm-s390/bitops.h
 * for the best explanations of this ordering.
 */

/*
 * If a bitmap has a number of bits which is not a multiple of 8 then
 * the last few bits of the last byte of the bitmap can be
 * unexpectedly set which can confuse consumers (e.g. in the tools)
 * who also round up their loops to 8 bits. Ensure we clear those left
 * over bits so as to prevent surprises.
 */
static void clamp_last_byte(uint8_t *bp, unsigned int nbits)
{
	unsigned int remainder = nbits % 8;

	if (remainder)
		bp[nbits/8] &= (1U << remainder) - 1;
}

int __bitmap_empty(const unsigned long *bitmap, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap[k])
			return 0;

	if (bits % BITS_PER_LONG)
		if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}
EXPORT_SYMBOL(__bitmap_empty);

int __bitmap_full(const unsigned long *bitmap, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (~bitmap[k])
			return 0;

	if (bits % BITS_PER_LONG)
		if (~bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}
EXPORT_SYMBOL(__bitmap_full);

int __bitmap_equal(const unsigned long *bitmap1,
		const unsigned long *bitmap2, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap1[k] != bitmap2[k])
			return 0;

	if (bits % BITS_PER_LONG)
		if ((bitmap1[k] ^ bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}
EXPORT_SYMBOL(__bitmap_equal);

void __bitmap_complement(unsigned long *dst, const unsigned long *src, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		dst[k] = ~src[k];

	if (bits % BITS_PER_LONG)
		dst[k] = ~src[k] & BITMAP_LAST_WORD_MASK(bits);
}
EXPORT_SYMBOL(__bitmap_complement);

void __bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] & bitmap2[k];
}
EXPORT_SYMBOL(__bitmap_and);

void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] | bitmap2[k];
}
EXPORT_SYMBOL(__bitmap_or);

void __bitmap_xor(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] ^ bitmap2[k];
}
EXPORT_SYMBOL(__bitmap_xor);

void __bitmap_andnot(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] & ~bitmap2[k];
}
EXPORT_SYMBOL(__bitmap_andnot);

int __bitmap_intersects(const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap1[k] & bitmap2[k])
			return 1;

	if (bits % BITS_PER_LONG)
		if ((bitmap1[k] & bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
			return 1;
	return 0;
}
EXPORT_SYMBOL(__bitmap_intersects);

int __bitmap_subset(const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap1[k] & ~bitmap2[k])
			return 0;

	if (bits % BITS_PER_LONG)
		if ((bitmap1[k] & ~bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
			return 0;
	return 1;
}
EXPORT_SYMBOL(__bitmap_subset);

#if BITS_PER_LONG == 32
int __bitmap_weight(const unsigned long *bitmap, int bits)
{
	int k, w = 0, lim = bits/BITS_PER_LONG;

	for (k = 0; k < lim; k++)
		w += hweight32(bitmap[k]);

	if (bits % BITS_PER_LONG)
		w += hweight32(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

	return w;
}
#else
int __bitmap_weight(const unsigned long *bitmap, int bits)
{
	int k, w = 0, lim = bits/BITS_PER_LONG;

	for (k = 0; k < lim; k++)
		w += hweight64(bitmap[k]);

	if (bits % BITS_PER_LONG)
		w += hweight64(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

	return w;
}
#endif
EXPORT_SYMBOL(__bitmap_weight);


/**
 *	bitmap_find_free_region - find a contiguous aligned mem region
 *	@bitmap: an array of unsigned longs corresponding to the bitmap
 *	@bits: number of bits in the bitmap
 *	@order: region size to find (size is actually 1<<order)
 *
 * This is used to allocate a memory region from a bitmap.  The idea is
 * that the region has to be 1<<order sized and 1<<order aligned (this
 * makes the search algorithm much faster).
 *
 * The region is marked as set bits in the bitmap if a free one is
 * found.
 *
 * Returns either beginning of region or negative error
 */
int bitmap_find_free_region(unsigned long *bitmap, int bits, int order)
{
	unsigned long mask;
	int pages = 1 << order;
	int i;

	if(pages > BITS_PER_LONG)
		return -EINVAL;

	/* make a mask of the order */
	mask = (1ul << (pages - 1));
	mask += mask - 1;

	/* run up the bitmap pages bits at a time */
	for (i = 0; i < bits; i += pages) {
		int index = i/BITS_PER_LONG;
		int offset = i - (index * BITS_PER_LONG);
		if((bitmap[index] & (mask << offset)) == 0) {
			/* set region in bimap */
			bitmap[index] |= (mask << offset);
			return i;
		}
	}
	return -ENOMEM;
}
EXPORT_SYMBOL(bitmap_find_free_region);

/**
 *	bitmap_release_region - release allocated bitmap region
 *	@bitmap: a pointer to the bitmap
 *	@pos: the beginning of the region
 *	@order: the order of the bits to release (number is 1<<order)
 *
 * This is the complement to __bitmap_find_free_region and releases
 * the found region (by clearing it in the bitmap).
 */
void bitmap_release_region(unsigned long *bitmap, int pos, int order)
{
	int pages = 1 << order;
	unsigned long mask = (1ul << (pages - 1));
	int index = pos/BITS_PER_LONG;
	int offset = pos - (index * BITS_PER_LONG);
	mask += mask - 1;
	bitmap[index] &= ~(mask << offset);
}
EXPORT_SYMBOL(bitmap_release_region);

int bitmap_allocate_region(unsigned long *bitmap, int pos, int order)
{
	int pages = 1 << order;
	unsigned long mask = (1ul << (pages - 1));
	int index = pos/BITS_PER_LONG;
	int offset = pos - (index * BITS_PER_LONG);

	/* We don't do regions of pages > BITS_PER_LONG.  The
	 * algorithm would be a simple look for multiple zeros in the
	 * array, but there's no driver today that needs this.  If you
	 * trip this BUG(), you get to code it... */
	BUG_ON(pages > BITS_PER_LONG);
	mask += mask - 1;
	if (bitmap[index] & (mask << offset))
		return -EBUSY;
	bitmap[index] |= (mask << offset);
	return 0;
}
EXPORT_SYMBOL(bitmap_allocate_region);

#ifdef __BIG_ENDIAN

void bitmap_long_to_byte(uint8_t *bp, const unsigned long *lp, int nbits)
{
	unsigned long l;
	int i, j, b;

	for (i = 0, b = 0; nbits > 0; i++, b += sizeof(l)) {
		l = lp[i];
		for (j = 0; (j < sizeof(l)) && (nbits > 0); j++) {
			bp[b+j] = l;
			l >>= 8;
			nbits -= 8;
		}
	}
	clamp_last_byte(bp, nbits);
}

void bitmap_byte_to_long(unsigned long *lp, const uint8_t *bp, int nbits)
{
	unsigned long l;
	int i, j, b;

	for (i = 0, b = 0; nbits > 0; i++, b += sizeof(l)) {
		l = 0;
		for (j = 0; (j < sizeof(l)) && (nbits > 0); j++) {
			l |= (unsigned long)bp[b+j] << (j*8);
			nbits -= 8;
		}
		lp[i] = l;
	}
}

#elif defined(__LITTLE_ENDIAN)

void bitmap_long_to_byte(uint8_t *bp, const unsigned long *lp, int nbits)
{
	memcpy(bp, lp, (nbits+7)/8);
	clamp_last_byte(bp, nbits);
}

void bitmap_byte_to_long(unsigned long *lp, const uint8_t *bp, int nbits)
{
	/* We may need to pad the final longword with zeroes. */
	if (nbits & (BITS_PER_LONG-1))
		lp[BITS_TO_LONGS(nbits)-1] = 0;
	memcpy(lp, bp, (nbits+7)/8);
}

#endif
