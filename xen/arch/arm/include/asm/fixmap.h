/*
 * fixmap.h: compile-time virtual memory allocation
 */
#ifndef __ASM_FIXMAP_H
#define __ASM_FIXMAP_H

#include <xen/acpi.h>

/* Fixmap slots */
#define FIXMAP_CONSOLE  0  /* The primary UART */
#define FIXMAP_MISC     1  /* Ephemeral mappings of hardware */
#define FIXMAP_ACPI_BEGIN  2  /* Start mappings of ACPI tables */
#define FIXMAP_ACPI_END    (FIXMAP_ACPI_BEGIN + NUM_FIXMAP_ACPI_PAGES - 1)  /* End mappings of ACPI tables */

#ifndef __ASSEMBLY__

/* Map a page in a fixmap entry */
extern void set_fixmap(unsigned map, mfn_t mfn, unsigned attributes);
/* Remove a mapping from a fixmap entry */
extern void clear_fixmap(unsigned map);

#endif /* __ASSEMBLY__ */

#endif /* __ASM_FIXMAP_H */
