#ifndef __ASM_X86_PT_CONTIG_MARKERS_H
#define __ASM_X86_PT_CONTIG_MARKERS_H

/*
 * Short of having function templates in C, the function defined below is
 * intended to be used by multiple parties interested in recording the
 * degree of contiguity in mappings by a single page table.
 *
 * Scheme: Every entry records the order of contiguous successive entries,
 * up to the maximum order covered by that entry (which is the number of
 * clear low bits in its index, with entry 0 being the exception using
 * the base-2 logarithm of the number of entries in a single page table).
 * While a few entries need touching upon update, knowing whether the
 * table is fully contiguous (and can hence be replaced by a higher level
 * leaf entry) is then possible by simply looking at entry 0's marker.
 *
 * Prereqs:
 * - CONTIG_MASK needs to be #define-d, to a value having at least 4
 *   contiguous bits (ignored by hardware), before including this file (or
 *   else only CONTIG_LEVEL_SHIFT and CONTIG_NR will become available),
 * - page tables to be passed to the helper need to be initialized with
 *   correct markers,
 * - not-present entries need to be entirely clear except for the marker.
 */

/* This is the same for all anticipated users, so doesn't need passing in. */
#define CONTIG_LEVEL_SHIFT 9
#define CONTIG_NR          (1 << CONTIG_LEVEL_SHIFT)

#ifdef CONTIG_MASK

#include <xen/bitops.h>
#include <xen/lib.h>
#include <xen/page-size.h>

#define GET_MARKER(e) MASK_EXTR(e, CONTIG_MASK)
#define SET_MARKER(e, m) \
    ((void)((e) = ((e) & ~CONTIG_MASK) | MASK_INSR(m, CONTIG_MASK)))

#define IS_CONTIG(kind, pt, i, idx, shift, b) \
    ((kind) == PTE_kind_leaf \
     ? (((pt)[i] ^ (pt)[idx]) & ~CONTIG_MASK) == (1ULL << ((b) + (shift))) \
     : !((pt)[i] & ~CONTIG_MASK))

enum PTE_kind {
    PTE_kind_null,
    PTE_kind_leaf,
    PTE_kind_table,
};

static bool pt_update_contig_markers(uint64_t *pt, unsigned int idx,
                                     unsigned int level, enum PTE_kind kind)
{
    unsigned int b, i = idx;
    unsigned int shift = (level - 1) * CONTIG_LEVEL_SHIFT + PAGE_SHIFT;

    ASSERT(idx < CONTIG_NR);
    ASSERT(!(pt[idx] & CONTIG_MASK));

    /* Step 1: Reduce markers in lower numbered entries. */
    while ( i )
    {
        b = ffs(i) - 1;
        i &= ~(1U << b);
        if ( GET_MARKER(pt[i]) <= b )
            break;
        SET_MARKER(pt[i], b);
    }

    /* An intermediate table is never contiguous with anything. */
    if ( kind == PTE_kind_table )
        return false;

    /*
     * Present entries need in-sync index and address to be a candidate
     * for being contiguous: What we're after is whether ultimately the
     * intermediate table can be replaced by a superpage.
     */
    if ( kind != PTE_kind_null &&
         idx != ((pt[idx] >> shift) & (CONTIG_NR - 1)) )
        return false;

    /* Step 2: Check higher numbered entries for contiguity. */
    for ( b = 0; b < CONTIG_LEVEL_SHIFT && !(idx & (1U << b)); ++b )
    {
        i = idx | (1U << b);
        if ( !IS_CONTIG(kind, pt, i, idx, shift, b) || GET_MARKER(pt[i]) != b )
            break;
    }

    /* Step 3: Update markers in this and lower numbered entries. */
    for ( ; SET_MARKER(pt[idx], b), b < CONTIG_LEVEL_SHIFT; ++b )
    {
        i = idx ^ (1U << b);
        if ( !IS_CONTIG(kind, pt, i, idx, shift, b) || GET_MARKER(pt[i]) != b )
            break;
        idx &= ~(1U << b);
    }

    return b == CONTIG_LEVEL_SHIFT;
}

#undef IS_CONTIG
#undef SET_MARKER
#undef GET_MARKER
#undef CONTIG_MASK

#endif /* CONTIG_MASK */

#endif /* __ASM_X86_PT_CONTIG_MARKERS_H */
