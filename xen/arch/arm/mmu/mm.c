/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/mm.h>
#include <xen/mm-frame.h>
#include <xen/pdx.h>
#include <xen/sizes.h>
#include <xen/string.h>

static void __init init_frametable_chunk(unsigned long pdx_s,
                                         unsigned long pdx_e)
{
    unsigned long nr_pdxs = pdx_e - pdx_s;
    unsigned long chunk_size = nr_pdxs * sizeof(struct page_info);
    unsigned long pfn_align;
    struct page_info *pg;
    int rc;
    mfn_t base_mfn;

    /*
     * In-loop chunks span whole PDX groups, which are always page-size
     * aligned. The last chunk ending at max_pdx may not be, so round up.
     */
    chunk_size = ROUNDUP(chunk_size, PAGE_SIZE);

    /*
     * Try to align the allocation to the contiguous mapping size so that
     * map_pages_to_xen() can use the contiguous bit.
     */
    pfn_align = ((chunk_size >= MB(32)) ? MB(32) : MB(2)) >> PAGE_SHIFT;

    base_mfn = alloc_boot_pages(chunk_size >> PAGE_SHIFT, pfn_align);

    /*
     * Resolve the frametable VA via mfn_to_page(pdx_to_mfn(...)) rather
     * than pdx_to_page() because the generic pdx_to_page() does not subtract
     * frametable_base_pdx. There's more work to be done to make it generic, so
     * for now route through mfn_to_page(), which on Arm applies the
     * frametable_base_pdx offset and yields the correct VA.
     */
    pg = mfn_to_page(pdx_to_mfn(pdx_s));
    rc = map_pages_to_xen((unsigned long)pg, base_mfn,
                          chunk_size >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the frametable mappings\n");

    memset(pg, 0, nr_pdxs * sizeof(struct page_info));
    memset(pg + nr_pdxs, -1,
           chunk_size - nr_pdxs * sizeof(struct page_info));
}

void __init init_frametable(paddr_t ram_start)
{
    unsigned int sidx, nidx, max_idx;

    /*
     * The size of paddr_t should be sufficient for the complete range of
     * physical address.
     */
    BUILD_BUG_ON((sizeof(paddr_t) * BITS_PER_BYTE) < PADDR_BITS);
    BUILD_BUG_ON(sizeof(struct page_info) != PAGE_INFO_SIZE);

    /* init_frametable_chunk() allocation alignment assumes 4KB granule */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);

    /* In-loop chunks must produce page-aligned frametable regions */
    BUILD_BUG_ON((PDX_GROUP_COUNT * sizeof(struct page_info)) % PAGE_SIZE);

    max_idx = DIV_ROUND_UP(max_pdx, PDX_GROUP_COUNT);
    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ram_start));

    /*
     * Mapping address in init_frametable_chunk must be page-aligned
     * for map_pages_to_xen(). Aligning to PDX_GROUP_COUNT guarantees this
     * because PDX_GROUP_COUNT * sizeof(page_info) is always a multiple of
     * PAGE_SIZE by construction.
     */
    frametable_base_pdx = ROUNDDOWN(frametable_base_pdx, PDX_GROUP_COUNT);

    if ( (max_pdx - frametable_base_pdx) > FRAMETABLE_NR )
        panic("Frametable too small\n");

    for ( sidx = (frametable_base_pdx / PDX_GROUP_COUNT); ; sidx = nidx )
    {
        unsigned int eidx;

        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);

        if ( nidx >= max_idx )
            break;

        init_frametable_chunk(sidx * PDX_GROUP_COUNT, eidx * PDX_GROUP_COUNT);
    }

    init_frametable_chunk(sidx * PDX_GROUP_COUNT, max_pdx);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
