/******************************************************************************
 * arch/x86/mm/physmap.c
 *
 * Parts of this code are Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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

#include <asm/p2m.h>

#include "mm-locks.h"

int
guest_physmap_add_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int page_order)
{
    /* IOMMU for PV guests is handled in get_page_type() and put_page(). */
    if ( !paging_mode_translate(d) )
    {
        struct page_info *page = mfn_to_page(mfn);
        unsigned long i;

        /*
         * Our interface for PV guests wrt IOMMU entries hasn't been very
         * clear; but historically, pages have started out with IOMMU mappings,
         * and only lose them when changed to a different page type.
         *
         * Retain this property by grabbing a writable type ref and then
         * dropping it immediately.  The result will be pages that have a
         * writable type (and an IOMMU entry), but a count of 0 (such that
         * any guest-requested type changes succeed and remove the IOMMU
         * entry).
         */
        for ( i = 0; i < (1UL << page_order); ++i, ++page )
        {
            if ( !need_iommu_pt_sync(d) )
                /* nothing */;
            else if ( get_page_and_type(page, d, PGT_writable_page) )
                put_page_and_type(page);
            else
                return -EINVAL;

            set_gpfn_from_mfn(mfn_x(mfn) + i, gfn_x(gfn) + i);
        }

        return 0;
    }

    return p2m_add_page(d, gfn, mfn, page_order, p2m_ram_rw);
}

int
guest_physmap_remove_page(struct domain *d, gfn_t gfn,
                          mfn_t mfn, unsigned int page_order)
{
    /* IOMMU for PV guests is handled in get_page_type() and put_page(). */
    if ( !paging_mode_translate(d) )
        return 0;

    return p2m_remove_page(d, gfn, mfn, page_order);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
