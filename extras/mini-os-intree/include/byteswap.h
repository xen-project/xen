#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_

/* Unfortunately not provided by newlib.  */

#include <mini-os/types.h>

#define bswap_16(x) ((uint16_t)(                         \
	         (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |                  \
	         (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

/* Use gcc optimized versions if they exist */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#define bswap_32(v) __builtin_bswap32(v)
#define bswap_64(v) __builtin_bswap64(v)
#else

#define bswap_32(x) ((uint32_t)(                         \
	         (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |            \
	         (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |            \
	         (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |            \
	         (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define bswap_64(x) ((uint64_t)(                         \
	         (((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) |   \
	         (((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) |   \
	         (((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) |   \
	         (((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) |   \
	         (((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) |   \
	         (((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) |   \
	         (((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) |   \
	         (((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56)))

#endif




#endif /* _BYTESWAP_H */
