/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#undef DEBUG

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include <public/xen.h>
#include "tce.h"
#include "iommu.h"

struct iommu_funcs {
    int (*iommu_put)(ulong, union tce);
};

/* individual host bridges */
static struct iommu_funcs iommu_phbs[16];
static u32 iommu_phbs_num = ARRAY_SIZE(iommu_phbs);

int iommu_put(u32 buid, ulong ioba, union tce tce)
{
    struct vcpu *v = get_current();
    struct domain *d = v->domain;

    if (buid < iommu_phbs_num && iommu_phbs[buid].iommu_put != NULL) {
        ulong pfn;
        ulong mfn;
        int mtype;

        pfn = tce.tce_bits.tce_rpn;
        mfn = pfn2mfn(d, pfn, &mtype);
        if (mfn != INVALID_MFN) {
#ifdef DEBUG
            printk("%s: ioba=0x%lx pfn=0x%lx mfn=0x%lx\n", __func__,
                   ioba, pfn, mfn);
#endif
            tce.tce_bits.tce_rpn = mfn;
            return iommu_phbs[buid].iommu_put(ioba, tce);
        }
    }
    return -1;
}

int iommu_register(u32 buid, int (*put)(ulong ioba, union tce ltce))
{

    if (buid < iommu_phbs_num && iommu_phbs[buid].iommu_put == NULL) {
        iommu_phbs[0].iommu_put = put;
        return 0;
    }
    panic("bad IOMMU registration\n");
    return -1;
}
