/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_VIRTUAL_REGION_H__
#define __XEN_VIRTUAL_REGION_H__

#include <xen/list.h>
#include <xen/symbols.h>

struct virtual_region
{
    struct list_head list;
    const void *start;                /* Virtual address start. */
    const void *end;                  /* Virtual address end. */

    /* If this is NULL the default lookup mechanism is used. */
    symbols_lookup_t *symbols_lookup;

    struct {
        const struct bug_frame *bugs; /* The pointer to array of bug frames. */
        size_t n_bugs;          /* The number of them. */
    } frame[BUGFRAME_NR];

    const struct exception_table_entry *ex;
    const struct exception_table_entry *ex_end;
};

const struct virtual_region *find_text_region(unsigned long addr);
void setup_virtual_regions(const struct exception_table_entry *start,
                           const struct exception_table_entry *end);
void unregister_init_virtual_region(void);
void register_virtual_region(struct virtual_region *r);
void unregister_virtual_region(struct virtual_region *r);

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
