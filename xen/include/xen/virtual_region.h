/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_VIRTUAL_REGION_H__
#define __XEN_VIRTUAL_REGION_H__

#include <xen/list.h>
#include <xen/symbols.h>

/*
 * Despite it's name, this is a module(ish) description.
 *
 * There's one region for the runtime .text/etc, one region for .init during
 * boot only, and one region per livepatch.
 */
struct virtual_region
{
    struct list_head list;

    const void *text_start;                /* .text virtual address start. */
    const void *text_end;                  /* .text virtual address end. */

    const void *rodata_start;              /* .rodata virtual address start (optional). */
    const void *rodata_end;                /* .rodata virtual address end. */

    /* If this is NULL the default lookup mechanism is used. */
    symbols_lookup_t *symbols_lookup;

    struct {
        const struct bug_frame *start, *stop; /* Pointers to array of bug frames. */
    } frame[BUGFRAME_NR];

#ifdef CONFIG_HAS_EX_TABLE
    const struct exception_table_entry *ex;
    const struct exception_table_entry *ex_end;
#endif
};

const struct virtual_region *find_text_region(unsigned long addr);
void unregister_init_virtual_region(void);
void register_virtual_region(struct virtual_region *r);
void unregister_virtual_region(struct virtual_region *r);

void relax_virtual_region_perms(void);
void tighten_virtual_region_perms(void);

#endif /* __XEN_VIRTUAL_REGION_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
