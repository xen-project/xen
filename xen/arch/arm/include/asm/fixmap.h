/*
 * fixmap.h: compile-time virtual memory allocation
 */
#ifndef __ASM_FIXMAP_H
#define __ASM_FIXMAP_H

#include <xen/acpi.h>
#include <xen/pmap.h>

/* Fixmap slots */
#define FIXMAP_CONSOLE  0  /* The primary UART */
#define FIXMAP_MISC     1  /* Ephemeral mappings of hardware */
#define FIXMAP_ACPI_BEGIN  2  /* Start mappings of ACPI tables */
#define FIXMAP_ACPI_END    (FIXMAP_ACPI_BEGIN + NUM_FIXMAP_ACPI_PAGES - 1)  /* End mappings of ACPI tables */
#define FIXMAP_PMAP_BEGIN (FIXMAP_ACPI_END + 1) /* Start of PMAP */
#define FIXMAP_PMAP_END (FIXMAP_PMAP_BEGIN + NUM_FIX_PMAP - 1) /* End of PMAP */

#define FIXMAP_LAST FIXMAP_PMAP_END

#define FIXADDR_START FIXMAP_ADDR(0)
#define FIXADDR_TOP FIXMAP_ADDR(FIXMAP_LAST)

#ifndef __ASSEMBLY__

/*
 * Direct access to xen_fixmap[] should only happen when {set,
 * clear}_fixmap() is unusable (e.g. where we would end up to
 * recursively call the helpers).
 */
extern lpae_t xen_fixmap[XEN_PT_LPAE_ENTRIES];

/* Map a page in a fixmap entry */
extern void set_fixmap(unsigned int map, mfn_t mfn, unsigned int flags);
/* Remove a mapping from a fixmap entry */
extern void clear_fixmap(unsigned int map);

#define fix_to_virt(slot) ((void *)FIXMAP_ADDR(slot))

static inline unsigned int virt_to_fix(vaddr_t vaddr)
{
    BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);

    return ((vaddr - FIXADDR_START) >> PAGE_SHIFT);
}

#endif /* __ASSEMBLY__ */

#endif /* __ASM_FIXMAP_H */
