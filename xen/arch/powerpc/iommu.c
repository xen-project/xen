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
 * Copyright IBM Corp. 2005, 2007
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

#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

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
        ulong gmfn;
        ulong mfn;
        int mtype;

        gmfn = tce.tce_bits.tce_rpn;

        
        mfn = pfn2mfn(d, gmfn, &mtype);
        if (mfn != INVALID_MFN) {
            switch (mtype) {
            case PFN_TYPE_LOGICAL:
                break;
            case PFN_TYPE_FOREIGN:
                DBG("%s: assigning to Foriegn page: "
                    "gmfn: 0x%lx mfn: 0x%lx\n",  __func__, gmfn, mfn);
                break;
            default:
                printk("%s: unsupported type[%d]: gmfn: 0x%lx mfn: 0x%lx\n",
                       __func__, mtype, gmfn, mfn);
                return -1;
            break;
            }
            DBG("%s: ioba=0x%lx gmfn=0x%lx mfn=0x%lx\n", __func__,
                ioba, gmfn, mfn);
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
