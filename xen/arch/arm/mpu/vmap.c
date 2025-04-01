/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/mm-frame.h>
#include <xen/types.h>
#include <xen/vmap.h>

void *vmap_contig(mfn_t mfn, unsigned int nr)
{
    BUG_ON("unimplemented");
    return NULL;
}

void vunmap(const void *va)
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
