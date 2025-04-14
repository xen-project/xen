/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/mm-frame.h>
#include <xen/types.h>

void *map_domain_page_global(mfn_t mfn)
{
    BUG_ON("unimplemented");
    return NULL;
}

/* Map a page of domheap memory */
void *map_domain_page(mfn_t mfn)
{
    BUG_ON("unimplemented");
    return NULL;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *ptr)
{
    BUG_ON("unimplemented");
}

mfn_t domain_page_map_to_mfn(const void *ptr)
{
    BUG_ON("unimplemented");
    return INVALID_MFN;
}

void unmap_domain_page_global(const void *va)
{
    BUG_ON("unimplemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
