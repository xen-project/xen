/******************************************************************************
 * Original code extracted from arch/x86/x86_64/mm.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/bitops.h>
#include <xen/nospec.h>

/**
 * Maximum (non-inclusive) usable pdx. Must be
 * modifiable after init due to memory hotplug
 */
unsigned long __read_mostly max_pdx;

unsigned long __read_mostly pdx_group_valid[BITS_TO_LONGS(
    (FRAMETABLE_NR + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT)] = { [0] = 1 };

bool __mfn_valid(unsigned long mfn)
{
    bool invalid = mfn >= max_page;

#ifdef CONFIG_PDX_COMPRESSION
    invalid |= mfn & pfn_hole_mask;
#endif

    if ( unlikely(evaluate_nospec(invalid)) )
        return false;

    return test_bit(pfn_to_pdx(mfn) / PDX_GROUP_COUNT, pdx_group_valid);
}

void set_pdx_range(unsigned long smfn, unsigned long emfn)
{
    unsigned long idx, eidx;

    idx = pfn_to_pdx(smfn) / PDX_GROUP_COUNT;
    eidx = (pfn_to_pdx(emfn - 1) + PDX_GROUP_COUNT) / PDX_GROUP_COUNT;

    for ( ; idx < eidx; ++idx )
        __set_bit(idx, pdx_group_valid);
}

#ifdef CONFIG_PDX_COMPRESSION

/*
 * Diagram to make sense of the following variables. The masks and shifts
 * are done on mfn values in order to convert to/from pdx:
 *
 *                      pfn_hole_mask
 *                      pfn_pdx_hole_shift (mask bitsize)
 *                      |
 *                 |---------|
 *                 |         |
 *                 V         V
 *         --------------------------
 *         |HHHHHHH|000000000|LLLLLL| <--- mfn
 *         --------------------------
 *         ^       ^         ^      ^
 *         |       |         |------|
 *         |       |             |
 *         |       |             pfn_pdx_bottom_mask
 *         |       |
 *         |-------|
 *             |
 *             pfn_top_mask
 *
 * ma_{top,va_bottom}_mask is simply a shifted pfn_{top,pdx_bottom}_mask,
 * where ma_top_mask has zeroes shifted in while ma_va_bottom_mask has
 * ones.
 */

/** Mask for the lower non-compressible bits of an mfn */
unsigned long __ro_after_init pfn_pdx_bottom_mask = ~0UL;

/** Mask for the lower non-compressible bits of an maddr or vaddr */
unsigned long __ro_after_init ma_va_bottom_mask = ~0UL;

/** Mask for the higher non-compressible bits of an mfn */
unsigned long __ro_after_init pfn_top_mask = 0;

/** Mask for the higher non-compressible bits of an maddr or vaddr */
unsigned long __ro_after_init ma_top_mask = 0;

/**
 * Mask for a pdx compression bit slice.
 *
 *  Invariant: valid(mfn) implies (mfn & pfn_hole_mask) == 0
 */
unsigned long __ro_after_init pfn_hole_mask = 0;

/** Number of bits of the "compressible" bit slice of an mfn */
unsigned int __ro_after_init pfn_pdx_hole_shift = 0;

/* Sets all bits from the most-significant 1-bit down to the LSB */
static uint64_t fill_mask(uint64_t mask)
{
    while (mask & (mask + 1))
        mask |= mask + 1;

    return mask;
}

bool pdx_is_region_compressible(paddr_t base, unsigned long npages)
{
    return !(paddr_to_pfn(base) & pfn_hole_mask) &&
           !(pdx_region_mask(base, npages * PAGE_SIZE) & ~ma_va_bottom_mask);
}

/* We don't want to compress the low MAX_ORDER bits of the addresses. */
uint64_t __init pdx_init_mask(uint64_t base_addr)
{
    return fill_mask(max(base_addr,
                         (uint64_t)1 << (MAX_ORDER + PAGE_SHIFT)) - 1);
}

uint64_t pdx_region_mask(uint64_t base, uint64_t len)
{
    /*
     * We say a bit "moves" in a range if there exist 2 addresses in that
     * range that have that bit both set and cleared respectively. We want
     * to create a mask of _all_ moving bits in this range. We do this by
     * comparing the first and last addresses in the range, discarding the
     * bits that remain the same (this is logically an XOR operation). The
     * MSB of the resulting expression is the most significant moving bit
     * in the range. Then it's a matter of setting every bit in lower
     * positions in order to get the mask of moving bits.
     */
    return fill_mask(base ^ (base + len - 1));
}

void __init pfn_pdx_hole_setup(unsigned long mask)
{
    unsigned int i, j, bottom_shift = 0, hole_shift = 0;

    /*
     * We skip the first MAX_ORDER bits, as we never want to compress them.
     * This guarantees that page-pointer arithmetic remains valid within
     * contiguous aligned ranges of 2^MAX_ORDER pages. Among others, our
     * buddy allocator relies on this assumption.
     *
     * If the logic changes here, we might have to update the ARM specific
     * init_pdx too.
     */
    for ( j = MAX_ORDER-1; ; )
    {
        i = find_next_zero_bit(&mask, BITS_PER_LONG, j + 1);
        if ( i >= BITS_PER_LONG )
            break;
        j = find_next_bit(&mask, BITS_PER_LONG, i + 1);
        if ( j >= BITS_PER_LONG )
            break;
        if ( j - i > hole_shift )
        {
            hole_shift = j - i;
            bottom_shift = i;
        }
    }
    if ( !hole_shift )
        return;

    printk(KERN_INFO "PFN compression on bits %u...%u\n",
           bottom_shift, bottom_shift + hole_shift - 1);

    pfn_pdx_hole_shift  = hole_shift;
    pfn_pdx_bottom_mask = (1UL << bottom_shift) - 1;
    ma_va_bottom_mask   = (PAGE_SIZE << bottom_shift) - 1;
    pfn_hole_mask       = ((1UL << hole_shift) - 1) << bottom_shift;
    pfn_top_mask        = ~(pfn_pdx_bottom_mask | pfn_hole_mask);
    ma_top_mask         = pfn_top_mask << PAGE_SHIFT;
}

#endif /* CONFIG_PDX_COMPRESSION */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
