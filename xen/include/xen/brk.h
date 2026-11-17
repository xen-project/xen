/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Early Boot memory allocator.
 *
 * Subsystems which conditionally need memory prior to the boot allocator
 * (or the main heap) being set up may use DEFINE_BRK() to reserve BSS space
 * in Xen.
 *
 * During boot, brk_alloc() allocates memory from the reserved space.  Such
 * allocations are good for the lifetime of Xen.  Subsystems MUST NOT
 * brk_alloc() more memory than they reserved.
 *
 * When the main heap is set up, brk allocations become unavailable.  Reserved
 * but unallocated space is, as far as possible, handed to the main heap, so it
 * doesn't go to waste.
 */

#ifndef XEN_BRK_H
#define XEN_BRK_H

#include <xen/types.h>

#define DEFINE_BRK(var, size) \
    static char __section(".bss..brk.page_aligned") __aligned(PAGE_SIZE) \
        __used var ## _brk_[size]

void *brk_alloc(size_t size);
unsigned long brk_cease(void);
void brk_free_unused(void);

#endif /* XEN_BRK_H */
