/* SPDX-License-Identifier: GPL-2.0 */

#include <xen/init.h>
#include <asm/fixmap.h>

/*
 * Set up the direct-mapped xenheap:
 * up to 1GB of contiguous, always-mapped memory.
 */
void __init setup_directmap_mappings(unsigned long base_mfn,
                                     unsigned long nr_mfns)
{
    int rc;

    rc = map_pages_to_xen(XENHEAP_VIRT_START, _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");

    /* Record where the directmap is, for translation routines. */
    directmap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
