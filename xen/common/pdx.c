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

/* Parameters for PFN/MADDR compression. */
unsigned long __read_mostly max_pdx;
unsigned long __read_mostly pfn_pdx_bottom_mask = ~0UL;
unsigned long __read_mostly ma_va_bottom_mask = ~0UL;
unsigned long __read_mostly pfn_top_mask = 0;
unsigned long __read_mostly ma_top_mask = 0;
unsigned long __read_mostly pfn_hole_mask = 0;
unsigned int __read_mostly pfn_pdx_hole_shift = 0;

unsigned long __read_mostly pdx_group_valid[BITS_TO_LONGS(
    (FRAMETABLE_NR + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT)] = { [0] = 1 };

bool __mfn_valid(unsigned long mfn)
{
    return likely(mfn < max_page) &&
           likely(!(mfn & pfn_hole_mask)) &&
           likely(test_bit(pfn_to_pdx(mfn) / PDX_GROUP_COUNT,
                           pdx_group_valid));
}

/* Sets all bits from the most-significant 1-bit down to the LSB */
static u64 __init fill_mask(u64 mask)
{
        while (mask & (mask + 1))
                mask |= mask + 1;
        return mask;
}

u64 __init pdx_init_mask(u64 base_addr)
{
	return fill_mask(base_addr - 1);
}

u64 __init pdx_region_mask(u64 base, u64 len)
{
	return fill_mask(base ^ (base + len - 1));
}

void set_pdx_range(unsigned long smfn, unsigned long emfn)
{
    unsigned long idx, eidx;

    idx = pfn_to_pdx(smfn) / PDX_GROUP_COUNT;
    eidx = (pfn_to_pdx(emfn - 1) + PDX_GROUP_COUNT) / PDX_GROUP_COUNT;

    for ( ; idx < eidx; ++idx )
        __set_bit(idx, pdx_group_valid);
}

void __init pfn_pdx_hole_setup(unsigned long mask)
{
    unsigned int i, j, bottom_shift = 0, hole_shift = 0;

    /*
     * We skip the first MAX_ORDER bits, as we never want to compress them.
     * This guarantees that page-pointer arithmetic remains valid within
     * contiguous aligned ranges of 2^MAX_ORDER pages. Among others, our
     * buddy allocator relies on this assumption.
     */
    for ( j = MAX_ORDER-1; ; )
    {
        i = find_next_zero_bit(&mask, BITS_PER_LONG, j);
        j = find_next_bit(&mask, BITS_PER_LONG, i);
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


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
