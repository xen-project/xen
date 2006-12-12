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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _ASM_PAGE_H
#define _ASM_PAGE_H

#define PAGE_SHIFT 12
#define PAGE_SIZE (1<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))

#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <asm/cache.h>

#define PFN_DOWN(x)   ((x) >> PAGE_SHIFT)
#define PFN_UP(x)     (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

typedef struct { unsigned long l1_lo; } l1_pgentry_t;
#define linear_l1_table                                                 \
    ((l1_pgentry_t *)(LINEAR_PT_VIRT_START))

#define l1_linear_offset(_a) ((_a) >> PAGE_SHIFT)

/*
 * NB. We don't currently track I/O holes in the physical RAM space.
 */
#define mfn_valid(mfn)      ((mfn) < max_page)

#define virt_to_maddr(va)   ((unsigned long)(va))
#define maddr_to_virt(ma)   ((void *)((unsigned long)(ma)))
/* Shorthand versions of the above functions. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define virt_to_mfn(va)     (virt_to_maddr(va) >> PAGE_SHIFT)
#define mfn_to_virt(mfn)    (maddr_to_virt(mfn << PAGE_SHIFT))

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)    (frame_table + (mfn))
#define page_to_mfn(pg)     ((unsigned long)((pg) - frame_table))

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma)   (frame_table + ((ma) >> PAGE_SHIFT))
#define page_to_maddr(pg)   ((paddr_t)((pg) - frame_table) << PAGE_SHIFT)

/* Convert between Xen-heap virtual addresses and page-info structures. */
#define virt_to_page(va)    (frame_table + (__pa(va) >> PAGE_SHIFT))
#define page_to_virt(pg)    (maddr_to_virt(page_to_maddr(pg)))

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn)   ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)    ((unsigned long)((pa) >> PAGE_SHIFT))

static __inline__ void clear_page(void *addr)
{
    unsigned long lines, line_size;

    line_size = cpu_caches.dline_size;
    lines = cpu_caches.dlines_per_page;

    __asm__ __volatile__(
    "mtctr  %1      # clear_page\n\
1:  dcbz    0,%0\n\
    add     %0,%0,%3\n\
    bdnz+   1b"
    : "=r" (addr)
    : "r" (lines), "0" (addr), "r" (line_size)
    : "ctr", "memory");
}

extern void copy_page(void *dp, void *sp);

#define linear_pg_table linear_l1_table

static inline int get_order(unsigned long size)
{
    int order;
    
    size = (size-1) >> (PAGE_SHIFT-1);
    order = -1;
    do {
        size >>= 1;
        order++;
    } while (size);
    return order;
}

/* XXX combine with get_order() above */
#define get_order_from_bytes get_order
static inline int get_order_from_pages(unsigned long nr_pages)
{
    int order;
    nr_pages--;
    for ( order = 0; nr_pages; order++ )
        nr_pages >>= 1;
    return order;
}

#define __flush_tlb_one(__addr) \
    __asm__ __volatile__("tlbie %0": :"r" (__addr): "memory")

#define _PAGE_PRESENT  0x001UL
#define _PAGE_RW       0x002UL
#define _PAGE_USER     0x004UL
#define _PAGE_PWT      0x008UL
#define _PAGE_PCD      0x010UL
#define _PAGE_ACCESSED 0x020UL
#define _PAGE_DIRTY    0x040UL
#define _PAGE_PAT      0x080UL
#define _PAGE_PSE      0x080UL
#define _PAGE_GLOBAL   0x100UL

#endif  /* ! __ASSEMBLY__ */
#endif
