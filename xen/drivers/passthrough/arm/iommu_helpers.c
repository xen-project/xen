/*
 * xen/drivers/passthrough/arm/iommu_helpers.c
 *
 * Contains various helpers to be used by IOMMU drivers.
 *
 * Based on Xen's SMMU driver:
 *    xen/drivers/passthrough/arm/smmu.c
 *
 * Copyright (C) 2014 Linaro Limited.
 *
 * Copyright (C) 2019 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/iommu.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/device.h>

/* Should only be used if P2M Table is shared between the CPU and the IOMMU. */
int __must_check arm_iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                                    unsigned int flags,
                                    unsigned int *flush_flags)
{
    p2m_type_t t;

    BUG_ON(!domain_use_host_layout(d));
    BUG_ON(mfn_x(mfn) != dfn_x(dfn));

    /* We only support readable and writable flags */
    if ( !(flags & (IOMMUF_readable | IOMMUF_writable)) )
        return -EINVAL;

    t = (flags & IOMMUF_writable) ? p2m_iommu_map_rw : p2m_iommu_map_ro;

    /*
     * The function guest_physmap_add_entry replaces the current mapping
     * if there is already one...
     */
    return guest_physmap_add_entry(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)),
                                   IOMMUF_order(flags), t);
}

/* Should only be used if P2M Table is shared between the CPU and the IOMMU. */
int __must_check arm_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                      unsigned int order,
                                      unsigned int *flush_flags)
{
    if ( !domain_use_host_layout(d) )
        return -EINVAL;

    return guest_physmap_remove_page(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)),
                                     order);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
