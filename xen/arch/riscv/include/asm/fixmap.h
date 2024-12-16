/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fixmap.h: compile-time virtual memory allocation
 */
#ifndef ASM__RISCV__FIXMAP_H
#define ASM__RISCV__FIXMAP_H

#include <xen/bug.h>
#include <xen/page-size.h>
#include <xen/pmap.h>

#include <asm/page.h>

#define FIXMAP_ADDR(n) (FIXMAP_BASE + (n) * PAGE_SIZE)

/* Fixmap slots */
#define FIX_PMAP_BEGIN (0) /* Start of PMAP */
#define FIX_PMAP_END (FIX_PMAP_BEGIN + NUM_FIX_PMAP - 1) /* End of PMAP */
#define FIX_MISC (FIX_PMAP_END + 1)  /* Ephemeral mappings of hardware */

#define FIX_LAST FIX_MISC

#define FIXADDR_START FIXMAP_ADDR(0)
#define FIXADDR_TOP FIXMAP_ADDR(FIX_LAST + 1)

#ifndef __ASSEMBLY__

/*
 * Direct access to xen_fixmap[] should only happen when {set,
 * clear}_fixmap() is unusable (e.g. where we would end up to
 * recursively call the helpers).
 */
extern pte_t xen_fixmap[];

/* Map a page in a fixmap entry */
void set_fixmap(unsigned int map, mfn_t mfn, unsigned int flags);
/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned int map);

#define fix_to_virt(slot) ((void *)FIXMAP_ADDR(slot))

static inline unsigned int virt_to_fix(vaddr_t vaddr)
{
    BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);

    return ((vaddr - FIXADDR_START) >> PAGE_SHIFT);
}

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__FIXMAP_H */
