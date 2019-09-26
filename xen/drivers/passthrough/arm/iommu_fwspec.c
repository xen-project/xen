/*
 * xen/drivers/passthrough/arm/iommu_fwspec.c
 *
 * Contains functions to maintain per-device firmware data
 *
 * Based on Linux's iommu_fwspec support you can find at:
 *    drivers/iommu/iommu.c
 *
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
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

#include <asm/device.h>
#include <asm/iommu_fwspec.h>

int iommu_fwspec_init(struct device *dev, struct device *iommu_dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    if ( fwspec )
    {
        /* We expect the device to be protected by only one IOMMU. */
        if ( fwspec->iommu_dev != iommu_dev )
            return -EINVAL;

        return 0;
    }

    /*
     * Allocate with ids[1] to avoid the re-allocation in the common case
     * where a device has a single device ID.
     */
    fwspec = xzalloc_flex_struct(struct iommu_fwspec, ids, 1);
    if ( !fwspec )
        return -ENOMEM;

    fwspec->iommu_dev = iommu_dev;
    dev_iommu_fwspec_set(dev, fwspec);

    return 0;
}

void iommu_fwspec_free(struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    xfree(fwspec);
    dev_iommu_fwspec_set(dev, NULL);
}

int iommu_fwspec_add_ids(struct device *dev, const uint32_t *ids,
                         unsigned int num_ids)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    unsigned int i;

    if ( !fwspec )
        return -EINVAL;

    fwspec = xrealloc_flex_struct(fwspec, ids, fwspec->num_ids + num_ids);
    if ( !fwspec )
        return -ENOMEM;

    dev_iommu_fwspec_set(dev, fwspec);

    for ( i = 0; i < num_ids; i++ )
        fwspec->ids[fwspec->num_ids + i] = ids[i];

    fwspec->num_ids += num_ids;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
