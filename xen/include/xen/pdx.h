#ifndef __XEN_PDX_H__
#define __XEN_PDX_H__

/*
 * PDX (Page inDeX)
 *
 * This file deals with optimisations pertaining to frame table and
 * directmap indexing, A pdx is an index into the frame table, which
 * typically also means an index into the directmap[1]. However, having an
 * identity relationship between mfn and pdx could waste copious amounts of
 * memory in empty frame table entries and page tables. There are some
 * techniques to bring memory wastage down.
 *
 * [1] Some ports apply further modifications to a pdx before indexing the
 *     directmap. This doesn't change the fact that the same compression
 *     present in the frame table is also present in the directmap
 *     whenever said map is present.
 *
 * ## PDX grouping
 *
 * The frame table may have some sparsity even on systems where the memory
 * banks are tightly packed. This is due to system quirks (like the PCI
 * hole) which might introduce several GiB of unused page frame numbers
 * that uselessly waste memory in the frame table. PDX grouping addresses
 * this by keeping a bitmap of the ranges in the frame table containing
 * invalid entries and not allocating backing memory for them.
 *
 * ## PDX compression
 *
 * This is a technique to avoid wasting memory on machines known to have
 * split their machine address space in several big discontinuous and highly
 * disjoint chunks.
 *
 * In its uncompressed form the frame table must have book-keeping metadata
 * structures for every page between [0, max_mfn) (whether they are backed
 * by RAM or not), and a similar condition exists for the direct map. We
 * know some systems, however, that have some sparsity in their address
 * space, leading to a lot of wastage in the form of unused frame table
 * entries.
 *
 * This is where compression becomes useful. The idea is to note that if
 * you have several big chunks of memory sufficiently far apart you can
 * ignore the middle part of the address because it will always contain
 * zeroes.
 *
 * i.e:
 *   Consider 2 regions of memory. One starts at 0 while the other starts
 *   at offset 2^off_h. Furthermore, let's assume both regions are smaller
 *   than 2^off_l. This means that all addresses between [2^off_l, 2^off_h)
 *   are invalid and we can assume them to be zero on all valid addresses.
 *
 *                 off_h     off_l
 *                 |         |
 *                 V         V
 *         --------------------------
 *         |HHHHHHH|000000000|LLLLLL| <--- mfn
 *         --------------------------
 *           ^ |
 *           | | (de)compression by adding/removing "useless" zeroes
 *           | V
 *         ---------------
 *         |HHHHHHHLLLLLL| <--- pdx
 *         ---------------
 *
 * This scheme also holds for multiple regions, where HHHHHHH acts as
 * the region identifier and LLLLLL fully contains the span of every
 * region involved.
 */

#ifdef CONFIG_HAS_PDX

extern unsigned long max_pdx;
extern unsigned long pfn_pdx_bottom_mask, ma_va_bottom_mask;
extern unsigned int pfn_pdx_hole_shift;
extern unsigned long pfn_hole_mask;
extern unsigned long pfn_top_mask, ma_top_mask;

#define PDX_GROUP_COUNT ((1 << PDX_GROUP_SHIFT) / \
                         (sizeof(*frame_table) & -sizeof(*frame_table)))
extern unsigned long pdx_group_valid[];

/**
 * Calculates a mask covering "moving" bits of all addresses of a region
 *
 * The i-th bit of the mask must be set if there's 2 different addresses
 * in the region that have different j-th bits. where j >= i.
 *
 * e.g:
 *       base=0x1B00000000
 *   len+base=0x1B00042000
 *
 *   ought to return 0x000007FFFF, which implies that every bit position
 *   with a zero in the mask remains unchanged in every address of the
 *   region.
 *
 * @param base Base address of the region
 * @param len  Size in octets of the region
 * @return Mask of moving bits at the bottom of all the region addresses
 */
uint64_t pdx_region_mask(uint64_t base, uint64_t len);

/**
 * Creates the mask to start from when calculating non-compressible bits
 *
 * This function is intimately related to pdx_region_mask(), and together
 * they are meant to calculate the mask of non-compressible bits given the
 * current memory map.
 *
 * @param base_addr Address of the first maddr in the system
 * @return An integer of the form 2^n - 1
 */
uint64_t pdx_init_mask(uint64_t base_addr);

/**
 * Mark [smfn, emfn) as accesible in the frame table
 *
 * @param smfn Start mfn
 * @param emfn End mfn
 */
void set_pdx_range(unsigned long smfn, unsigned long emfn);

#define page_to_pdx(pg)  ((pg) - frame_table)
#define pdx_to_page(pdx) gcc11_wrap(frame_table + (pdx))

/**
 * Invoked to determine if an mfn has an associated valid frame table entry
 *
 * In order for it to be legal it must pass bounds, grouping and
 * compression sanity checks.
 *
 * @param mfn To-be-checked mfn
 * @return True iff all checks pass
 */
bool __mfn_valid(unsigned long mfn);

/**
 * Map pfn to its corresponding pdx
 *
 * @param pfn Frame number
 * @return Obtained pdx after compressing the pfn
 */
static inline unsigned long pfn_to_pdx(unsigned long pfn)
{
    return (pfn & pfn_pdx_bottom_mask) |
           ((pfn & pfn_top_mask) >> pfn_pdx_hole_shift);
}

/**
 * Map a pdx to its corresponding pfn
 *
 * @param pdx Page index
 * @return Obtained pfn after decompressing the pdx
 */
static inline unsigned long pdx_to_pfn(unsigned long pdx)
{
    return (pdx & pfn_pdx_bottom_mask) |
           ((pdx << pfn_pdx_hole_shift) & pfn_top_mask);
}

#define mfn_to_pdx(mfn) pfn_to_pdx(mfn_x(mfn))
#define pdx_to_mfn(pdx) _mfn(pdx_to_pfn(pdx))

/**
 * Computes the offset into the direct map of an maddr
 *
 * @param ma Machine address
 * @return Offset on the direct map where that
 *         machine address can be accessed
 */
static inline unsigned long maddr_to_directmapoff(paddr_t ma)
{
    return (((ma & ma_top_mask) >> pfn_pdx_hole_shift) |
            (ma & ma_va_bottom_mask));
}

/**
 * Computes a machine address given a direct map offset
 *
 * @param offset Offset into the direct map
 * @return Corresponding machine address of that virtual location
 */
static inline paddr_t directmapoff_to_maddr(unsigned long offset)
{
    return ((((paddr_t)offset << pfn_pdx_hole_shift) & ma_top_mask) |
            (offset & ma_va_bottom_mask));
}

/**
 * Initializes global variables with information about the compressible
 * range of the current memory regions.
 *
 * @param mask This mask is the biggest pdx_mask of every region in the
 *             system ORed with all base addresses of every region in the
 *             system. This results in a mask where every zero in a bit
 *             position marks a potentially compressible bit.
 */
void pfn_pdx_hole_setup(unsigned long mask);

#endif /* HAS_PDX */
#endif /* __XEN_PDX_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
