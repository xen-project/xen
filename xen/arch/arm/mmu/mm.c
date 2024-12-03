/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/mm.h>
#include <xen/mm-frame.h>
#include <xen/pdx.h>
#include <xen/string.h>

unsigned long frametable_virt_end __read_mostly;

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pdxs = mfn_to_pdx(mfn_add(maddr_to_mfn(pe), -1)) -
                            mfn_to_pdx(maddr_to_mfn(ps)) + 1;
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    mfn_t base_mfn;
    const unsigned long mapping_size = frametable_size < MB(32) ? MB(2)
                                                                : MB(32);
    int rc;

    /*
     * The size of paddr_t should be sufficient for the complete range of
     * physical address.
     */
    BUILD_BUG_ON((sizeof(paddr_t) * BITS_PER_BYTE) < PADDR_BITS);
    BUILD_BUG_ON(sizeof(struct page_info) != PAGE_INFO_SIZE);

    if ( frametable_size > FRAMETABLE_SIZE )
        panic("The frametable cannot cover the physical region %#"PRIpaddr" - %#"PRIpaddr"\n",
              ps, pe);

    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ps));
    /* Round up to 2M or 32M boundary, as appropriate. */
    frametable_size = ROUNDUP(frametable_size, mapping_size);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));

    rc = map_pages_to_xen(FRAMETABLE_VIRT_START, base_mfn,
                          frametable_size >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the frametable mappings.\n");

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs *
                                                   sizeof(struct page_info));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
