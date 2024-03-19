/*
 * Copyright (C) 2011 Advanced Micro Devices, Inc.
 * Author: Wei Wang <wei.wang2@amd.com>
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

#include "iommu.h"

#define reg_to_u64(reg) (((uint64_t)reg.hi << 32) | reg.lo )

static uint16_t get_guest_bdf(struct domain *d, uint16_t machine_bdf)
{
    return machine_bdf;
}

static inline struct guest_iommu *domain_iommu(struct domain *d)
{
    return dom_iommu(d)->arch.amd.g_iommu;
}

static unsigned long get_gfn_from_base_reg(uint64_t base_raw)
{
    base_raw &= PADDR_MASK;
    ASSERT ( base_raw != 0 );
    return base_raw >> PAGE_SHIFT;
}

static void guest_iommu_deliver_msi(struct domain *d)
{
    uint8_t vector, dest, dest_mode, delivery_mode, trig_mode;
    struct guest_iommu *iommu = domain_iommu(d);

    vector = iommu->msi.vector;
    dest = iommu->msi.dest;
    dest_mode = iommu->msi.dest_mode;
    delivery_mode = iommu->msi.delivery_mode;
    trig_mode = iommu->msi.trig_mode;

    vmsi_deliver(d, vector, dest, dest_mode, delivery_mode, trig_mode);
}

static unsigned long guest_iommu_get_table_mfn(struct domain *d,
                                               uint64_t base_raw,
                                               unsigned int pos)
{
    unsigned long idx, gfn, mfn;
    p2m_type_t p2mt;

    gfn = get_gfn_from_base_reg(base_raw);
    idx = pos >> PAGE_SHIFT;

    mfn = mfn_x(get_gfn(d, gfn + idx, &p2mt));
    put_gfn(d, gfn);

    return mfn;
}

void guest_iommu_add_ppr_log(struct domain *d, u32 entry[])
{
    uint16_t gdev_id;
    unsigned long mfn, tail, head;
    ppr_entry_t *log;
    struct guest_iommu *iommu;

    if ( !is_hvm_domain(d) )
        return;

    iommu = domain_iommu(d);
    if ( !iommu )
        return;

    tail = iommu->ppr_log.reg_tail.lo;
    head = iommu->ppr_log.reg_head.lo;

    if ( tail >= iommu->ppr_log.size || head >= iommu->ppr_log.size )
    {
        AMD_IOMMU_DEBUG("Error: guest iommu ppr log overflows\n");
        iommu->enabled = 0;
        return;
    }

    mfn = guest_iommu_get_table_mfn(d, reg_to_u64(iommu->ppr_log.reg_base),
                                    tail);
    ASSERT(mfn_valid(_mfn(mfn)));

    log = map_domain_page(_mfn(mfn)) + (tail & ~PAGE_MASK);

    /* Convert physical device id back into virtual device id */
    gdev_id = get_guest_bdf(d, iommu_get_devid_from_cmd(entry[0]));
    iommu_set_devid_to_cmd(&entry[0], gdev_id);

    memcpy(log, entry, sizeof(ppr_entry_t));

    /* Now shift ppr log tail pointer */
    tail += sizeof(ppr_entry_t);
    if ( tail >= iommu->ppr_log.size )
    {
        tail = 0;
        iommu->reg_status.lo |= IOMMU_STATUS_PPR_LOG_OVERFLOW;
    }

    iommu->ppr_log.reg_tail.lo = tail;
    unmap_domain_page(log);

    guest_iommu_deliver_msi(d);
}
