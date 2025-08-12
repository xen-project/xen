/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for PDX compression.
 *
 * Copyright (C) 2025 Cloud Software Group
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#define __init
#define __initdata
#define __ro_after_init
#define cf_check

#define printk printf
#define XENLOG_INFO
#define XENLOG_DEBUG
#define XENLOG_WARNING
#define KERN_INFO

#define BITS_PER_LONG (unsigned int)(sizeof(unsigned long) * 8)

#define PAGE_SHIFT    12
/* Some libcs define PAGE_SIZE in limits.h. */
#undef  PAGE_SIZE
#define PAGE_SIZE     (1L << PAGE_SHIFT)
#define MAX_ORDER     18 /* 2 * PAGETABLE_ORDER (9) */

#define PFN_DOWN(x)   ((x) >> PAGE_SHIFT)
#define PFN_UP(x)     (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))

#define MAX_RANGES 16
#define MAX_PFN_RANGES MAX_RANGES
#define CONFIG_PDX_OFFSET_TBL_ORDER 6

#define ASSERT assert
#define ASSERT_UNREACHABLE() assert(0)

#define CONFIG_DEBUG

static inline unsigned int find_next(
    const unsigned long *addr, unsigned int size, unsigned int off, bool value)
{
    unsigned int i;

    ASSERT(size <= BITS_PER_LONG);

    for ( i = off; i < size; i++ )
        if ( !!(*addr & (1UL << i)) == value )
            return i;

    return size;
}

#define find_next_zero_bit(a, s, o) find_next(a, s, o, false)
#define find_next_bit(a, s, o)      find_next(a, s, o, true)

#define flsl(x) ((x) ? BITS_PER_LONG - __builtin_clzl(x) : 0)
#define ffsl(x) __builtin_ffsl(x)

#define boolean_param(name, func)

typedef uint64_t paddr_t;

#define SWAP(a, b) \
   do { typeof(a) t_ = (a); (a) = (b); (b) = t_; } while ( 0 )

#define sort(elem, nr, size, cmp, swp) ({                               \
    /* Consume swp() so compiler doesn't complain it's unused. */       \
    (void)(swp);                                                        \
    qsort(elem, nr, size, cmp);                                         \
})

#include "pdx.h"

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
