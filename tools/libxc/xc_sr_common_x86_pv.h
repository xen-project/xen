#ifndef __COMMON_X86_PV_H
#define __COMMON_X86_PV_H

#include "xc_sr_common_x86.h"

/*
 * Convert an mfn to a pfn, given Xen's m2p table.
 *
 * Caller must ensure that the requested mfn is in range.
 */
xen_pfn_t mfn_to_pfn(struct xc_sr_context *ctx, xen_pfn_t mfn);

/*
 * Query whether a particular mfn is valid in the physmap of a guest.
 */
bool mfn_in_pseudophysmap(struct xc_sr_context *ctx, xen_pfn_t mfn);

/*
 * Debug a particular mfn by walking the p2m and m2p.
 */
void dump_bad_pseudophysmap_entry(struct xc_sr_context *ctx, xen_pfn_t mfn);

/*
 * Convert a PV cr3 field to an mfn.
 *
 * Adjusts for Xen's extended-cr3 format to pack a 44bit physical address into
 * a 32bit architectural cr3.
 */
xen_pfn_t cr3_to_mfn(struct xc_sr_context *ctx, uint64_t cr3);

/*
 * Convert an mfn to a PV cr3 field.
 *
 * Adjusts for Xen's extended-cr3 format to pack a 44bit physical address into
 * a 32bit architectural cr3.
 */
uint64_t mfn_to_cr3(struct xc_sr_context *ctx, xen_pfn_t mfn);

/* Bits 12 through 51 of a PTE point at the frame */
#define PTE_FRAME_MASK 0x000ffffffffff000ULL

/*
 * Extract an mfn from a Pagetable Entry.  May return INVALID_MFN if the pte
 * would overflow a 32bit xen_pfn_t.
 */
static inline xen_pfn_t pte_to_frame(uint64_t pte)
{
    uint64_t frame = (pte & PTE_FRAME_MASK) >> PAGE_SHIFT;

#ifdef __i386__
    if ( frame >= INVALID_MFN )
        return INVALID_MFN;
#endif

    return frame;
}

/*
 * Change the frame in a Pagetable Entry while leaving the flags alone.
 */
static inline uint64_t merge_pte(uint64_t pte, xen_pfn_t mfn)
{
    return (pte & ~PTE_FRAME_MASK) | ((uint64_t)mfn << PAGE_SHIFT);
}

/*
 * Get current domain information.
 *
 * Fills ctx->x86_pv
 * - .width
 * - .levels
 * - .fpp
 * - .p2m_frames
 *
 * Used by the save side to create the X86_PV_INFO record, and by the restore
 * side to verify the incoming stream.
 *
 * Returns 0 on success and non-zero on error.
 */
int x86_pv_domain_info(struct xc_sr_context *ctx);

/*
 * Maps the Xen M2P.
 *
 * Fills ctx->x86_pv.
 * - .max_mfn
 * - .m2p
 *
 * Returns 0 on success and non-zero on error.
 */
int x86_pv_map_m2p(struct xc_sr_context *ctx);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
