/*
 * lib/bitmap.c
 * Helper functions for bitmap.h.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
#include <xen/config.h>
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

/*
 * __bitmap_shift_right - logical right shift of the bits in a bitmap
 *   @dst - destination bitmap
 *   @src - source bitmap
 *   @nbits - shift by this many bits
 *   @bits - bitmap size, in bits
 *
 * Shifting right (dividing) means moving bits in the MS -> LS bit
 * direction.  Zeros are fed into the vacated MS positions and the
 * LS bits shifted off the bottom are lost.
 */
void __bitmap_shift_right(unsigned long *dst,
			const unsigned long *src, int shift, int bits)
{
	int k, lim = BITS_TO_LONGS(bits), left = bits % BITS_PER_LONG;
	int off = shift/BITS_PER_LONG, rem = shift % BITS_PER_LONG;
	unsigned long mask = (1UL << left) - 1;
	for (k = 0; off + k < lim; ++k) {
		unsigned long upper, lower;

		/*
		 * If shift is not word aligned, take lower rem bits of
		 * word above and make them the top rem bits of result.
		 */
		if (!rem || off + k + 1 >= lim)
			upper = 0;
		else {
			upper = src[off + k + 1];
			if (off + k + 1 == lim - 1 && left)
				upper &= mask;
		}
		lower = src[off + k];
		if (left && off + k == lim - 1)
			lower &= mask;
		dst[k] = rem
		         ? (upper << (BITS_PER_LONG - rem)) | (lower >> rem)
		         : lower;
		if (left && k == lim - 1)
			dst[k] &= mask;
	}
	if (off)
		memset(&dst[lim - off], 0, off*sizeof(unsigned long));
}
EXPORT_SYMBOL(__bitmap_shift_right);


/*
 * __bitmap_shift_left - logical left shift of the bits in a bitmap
 *   @dst - destination bitmap
 *   @src - source bitmap
 *   @nbits - shift by this many bits
 *   @bits - bitmap size, in bits
 *
 * Shifting left (multiplying) means moving bits in the LS -> MS
 * direction.  Zeros are fed into the vacated LS bit positions
 * and those MS bits shifted off the top are lost.
 */

void __bitmap_shift_left(unsigned long *dst,
			const unsigned long *src, int shift, int bits)
{
	int k, lim = BITS_TO_LONGS(bits), left = bits % BITS_PER_LONG;
	int off = shift/BITS_PER_LONG, rem = shift % BITS_PER_LONG;
	for (k = lim - off - 1; k >= 0; --k) {
		unsigned long upper, lower;

		/*
		 * If shift is not word aligned, take upper rem bits of
		 * word below and make them the bottom rem bits of result.
		 */
		if (rem && k > 0)
			lower = src[k - 1];
		else
			lower = 0;
		upper = src[k];
		if (left && k == lim - 1)
			upper &= (1UL << left) - 1;
		dst[k + off] = rem ? (lower >> (BITS_PER_LONG - rem))
		                      | (upper << rem)
		                   : upper;
		if (left && k + off == lim - 1)
			dst[k + off] &= (1UL << left) - 1;
	}
	if (off)
		memset(dst, 0, off*sizeof(unsigned long));
}
EXPORT_SYMBOL(__bitmap_shift_left);

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

/*
 * Bitmap printing & parsing functions: first version by Bill Irwin,
 * second version by Paul Jackson, third by Joe Korty.
 */

#define CHUNKSZ				32
#define nbits_to_hold_value(val)	fls(val)
#define roundup_power2(val,modulus)	(((val) + (modulus) - 1) & ~((modulus) - 1))
#define unhex(c)			(isdigit(c) ? (c - '0') : (toupper(c) - 'A' + 10))
#define BASEDEC 10		/* fancier cpuset lists input in decimal */

/**
 * bitmap_scnprintf - convert bitmap to an ASCII hex string.
 * @buf: byte buffer into which string is placed
 * @buflen: reserved size of @buf, in bytes
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 *
 * Exactly @nmaskbits bits are displayed.  Hex digits are grouped into
 * comma-separated sets of eight digits per set.
 */
int bitmap_scnprintf(char *buf, unsigned int buflen,
	const unsigned long *maskp, int nmaskbits)
{
	int i, word, bit, len = 0;
	unsigned long val;
	const char *sep = "";
	int chunksz;
	u32 chunkmask;

	chunksz = nmaskbits & (CHUNKSZ - 1);
	if (chunksz == 0)
		chunksz = CHUNKSZ;

	i = roundup_power2(nmaskbits, CHUNKSZ) - CHUNKSZ;
	for (; i >= 0; i -= CHUNKSZ) {
		chunkmask = ((1ULL << chunksz) - 1);
		word = i / BITS_PER_LONG;
		bit = i % BITS_PER_LONG;
		val = (maskp[word] >> bit) & chunkmask;
		len += scnprintf(buf+len, buflen-len, "%s%0*lx", sep,
			(chunksz+3)/4, val);
		chunksz = CHUNKSZ;
		sep = ",";
	}
	return len;
}
EXPORT_SYMBOL(bitmap_scnprintf);

/*
 * bscnl_emit(buf, buflen, rbot, rtop, bp)
 *
 * Helper routine for bitmap_scnlistprintf().  Write decimal number
 * or range to buf, suppressing output past buf+buflen, with optional
 * comma-prefix.  Return len of what would be written to buf, if it
 * all fit.
 */
static inline int bscnl_emit(char *buf, int buflen, int rbot, int rtop, int len)
{
	if (len > 0)
		len += scnprintf(buf + len, buflen - len, ",");
	if (rbot == rtop)
		len += scnprintf(buf + len, buflen - len, "%d", rbot);
	else
		len += scnprintf(buf + len, buflen - len, "%d-%d", rbot, rtop);
	return len;
}

/**
 * bitmap_scnlistprintf - convert bitmap to list format ASCII string
 * @buf: byte buffer into which string is placed
 * @buflen: reserved size of @buf, in bytes
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 *
 * Output format is a comma-separated list of decimal numbers and
 * ranges.  Consecutively set bits are shown as two hyphen-separated
 * decimal numbers, the smallest and largest bit numbers set in
 * the range.  Output format is compatible with the format
 * accepted as input by bitmap_parselist().
 *
 * The return value is the number of characters which were output,
 * excluding the trailing '\0'.
 */
int bitmap_scnlistprintf(char *buf, unsigned int buflen,
	const unsigned long *maskp, int nmaskbits)
{
	int len = 0;
	/* current bit is 'cur', most recently seen range is [rbot, rtop] */
	int cur, rbot, rtop;

	rbot = cur = find_first_bit(maskp, nmaskbits);
	while (cur < nmaskbits) {
		rtop = cur;
		cur = find_next_bit(maskp, nmaskbits, cur+1);
		if (cur >= nmaskbits || cur > rtop + 1) {
			len = bscnl_emit(buf, buflen, rbot, rtop, len);
			rbot = cur;
		}
	}
	if (!len && buflen)
		*buf = 0;
	return len;
}
EXPORT_SYMBOL(bitmap_scnlistprintf);

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
