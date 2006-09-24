/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _FLATDEVTREE_ENV_H_
#define _FLATDEVTREE_ENV_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#define MAX_PATH_LEN 1024

#define _ALIGN(addr,size)       (((addr)+(size)-1)&(~((size)-1)))

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

static inline u16 swab16(u16 x)
{
	return  (((u16)(x) & (u16)0x00ffU) << 8) |
			(((u16)(x) & (u16)0xff00U) >> 8);
}

static inline u32 swab32(u32 x)
{
	return  (((u32)(x) & (u32)0x000000ffUL) << 24) |
			(((u32)(x) & (u32)0x0000ff00UL) <<  8) |
			(((u32)(x) & (u32)0x00ff0000UL) >>  8) |
			(((u32)(x) & (u32)0xff000000UL) >> 24);
}

static inline u64 swab64(u64 x)
{
	return  (u64)(((u64)(x) & (u64)0x00000000000000ffULL) << 56) |
			(u64)(((u64)(x) & (u64)0x000000000000ff00ULL) << 40) |
			(u64)(((u64)(x) & (u64)0x0000000000ff0000ULL) << 24) |
			(u64)(((u64)(x) & (u64)0x00000000ff000000ULL) <<  8) |
			(u64)(((u64)(x) & (u64)0x000000ff00000000ULL) >>  8) |
			(u64)(((u64)(x) & (u64)0x0000ff0000000000ULL) >> 24) |
			(u64)(((u64)(x) & (u64)0x00ff000000000000ULL) >> 40) |
			(u64)(((u64)(x) & (u64)0xff00000000000000ULL) >> 56);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be16(x) swab16(x)
#define be16_to_cpu(x) swab16(x)
#define cpu_to_be32(x) swab32(x)
#define be32_to_cpu(x) swab32(x)
#define cpu_to_be64(x) swab64(x)
#define be64_to_cpu(x) swab64(x)
#else
#define cpu_to_be16(x) (x)
#define be16_to_cpu(x) (x)
#define cpu_to_be32(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_be64(x) (x)
#define be64_to_cpu(x) (x)
#endif

static inline void ft_exit(int code)
{
	exit(code);
}

static inline void ft_free(void *ptr, int len)
{
	free(ptr);
}

static inline u32 min(u32 a, u32 b)
{
	if (a < b)
		return a;
	return b;
}

#endif /* _FLATDEVTREE_ENV_H_ */
