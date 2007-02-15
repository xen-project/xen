/*
 * Done by Dietmar Hahn <dietmar.hahn@fujitsu-siemens.com>
 * Parts are taken from FreeBSD.
 *
 ****************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */


#if !defined(_ENDIAN_H_)
#define _ENDIAN_H_

#include "types.h"


#if !defined(__ASSEMBLY__)

#if defined(BIG_ENDIAN)

static __inline uint64_t
__bswap64(uint64_t __x)
{
	uint64_t __r;
	asm __volatile("mux1 %0=%1,@rev" : "=r" (__r) : "r"(__x));
	return __r;
}

static __inline uint32_t
__bswap32(uint32_t __x)
{
	return (__bswap64(__x) >> 32);
}

static __inline uint16_t
__bswap16(uint16_t __x)
{
	return (__bswap64(__x) >> 48);
}

#define doswap(x,sz)  ( \
	((sz)==1)? (uint8_t)(x): \
	((sz)==2)? __bswap16(x): \
	((sz)==4)? __bswap32(x): \
	((sz)==8)? __bswap64(x): \
	~0l )

#define SWAP(x)	doswap((x), sizeof((x)))


#else /* defined(BIG_ENDIAN) */

#define SWAP(x) (x)

#endif /* defined(BIG_ENDIAN) */

#endif /* !defined(__ASSEMBLY__) */


#endif /* !defined(_ENDIAN_H_) */
