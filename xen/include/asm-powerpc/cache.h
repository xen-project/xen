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
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __ASM_CACHE_H
#define __ASM_CACHE_H

#include <xen/config.h>
#include <asm/processor.h>

/* L1 cache line size */
#define L1_CACHE_SHIFT (CONFIG_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)

static __inline__ void dcbst(ulong line)
{
    __asm__ __volatile__ ("dcbst 0, %0" : : "r"(line) : "memory");
}

static __inline__ void icbi(ulong line)
{
    __asm__ __volatile__ ("icbi 0, %0" : : "r"(line) : "memory");
}

static __inline__ void synchronize_caches(ulong start, size_t len)
{
    ulong addr;

    for (addr = start; addr < start + len; addr += L1_CACHE_BYTES) {
        dcbst(addr);
    }

    /* allow dcbsts to complete */
    sync();

    for (addr = start; addr < start + len; addr += L1_CACHE_BYTES) {
        icbi(addr);
    }

    /* discard instructions partially decoded from old icache contents */
    isync();
}

#define __read_mostly

struct cpu_caches {
    u32 dsize;          /* L1 d-cache size */
    u32 dline_size;     /* L1 d-cache line size */
    u32 log_dline_size;
    u32 dlines_per_page;
    u32 isize;          /* L1 i-cache size */
    u32 iline_size;     /* L1 i-cache line size */
    u32 log_iline_size;
    u32 ilines_per_page;
};
extern struct cpu_caches cpu_caches;
extern void cpu_flush_icache(void);
#endif
