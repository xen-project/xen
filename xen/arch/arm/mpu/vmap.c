/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/mm.h>
#include <xen/mm-frame.h>
#include <xen/types.h>
#include <xen/vmap.h>

void *vmap_contig(mfn_t mfn, unsigned int nr)
{
    paddr_t base = mfn_to_maddr(mfn);

    if ( map_pages_to_xen(base, mfn, nr, PAGE_HYPERVISOR ) )
        return NULL;

    return maddr_to_virt(base);
}

void vunmap(const void *va)
{
    paddr_t base = virt_to_maddr(va);

    if ( destroy_xen_mapping_containing(base) )
        panic("Failed to vunmap region\n");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
