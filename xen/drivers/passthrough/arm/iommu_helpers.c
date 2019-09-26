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

    /*
     * Grant mappings can be used for DMA requests. The dev_bus_addr
     * returned by the hypercall is the MFN (not the IPA). For device
     * protected by an IOMMU, Xen needs to add a 1:1 mapping in the domain
     * p2m to allow DMA request to work.
     * This is only valid when the domain is directed mapped. Hence this
     * function should only be used by gnttab code with gfn == mfn == dfn.
     */
    BUG_ON(!is_domain_direct_mapped(d));
    BUG_ON(mfn_x(mfn) != dfn_x(dfn));

    /* We only support readable and writable flags */
    if ( !(flags & (IOMMUF_readable | IOMMUF_writable)) )
        return -EINVAL;

    t = (flags & IOMMUF_writable) ? p2m_iommu_map_rw : p2m_iommu_map_ro;

    /*
     * The function guest_physmap_add_entry replaces the current mapping
     * if there is already one...
     */
    return guest_physmap_add_entry(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)), 0, t);
}

/* Should only be used if P2M Table is shared between the CPU and the IOMMU. */
int __must_check arm_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                      unsigned int *flush_flags)
{
    /*
     * This function should only be used by gnttab code when the domain
     * is direct mapped (i.e. gfn == mfn == dfn).
     */
    if ( !is_domain_direct_mapped(d) )
        return -EINVAL;

    return guest_physmap_remove_page(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)), 0);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
