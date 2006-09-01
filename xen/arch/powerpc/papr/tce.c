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

#define DEBUG

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include "../tce.h"
#include "../iommu.h"

static void h_put_tce(struct cpu_user_regs *regs)
{
    u32 liobn = regs->gprs[4];
    ulong ioba = regs->gprs[5];
    u64 tce_dword = regs->gprs[6];
    union tce tce;

    tce.tce_dword = tce_dword;

    if (iommu_put(liobn, ioba, tce) == -1) {
        regs->gprs[3] = H_Parameter;
    } else {
        regs->gprs[3] = H_Success;
    }
}

static void h_get_tce(struct cpu_user_regs *regs)
{
    u32 liobn = regs->gprs[4];
    ulong ioba = regs->gprs[5];

#ifdef DEBUG
    printk("%s: liobn: 0x%x ioba: 0x%lx \n", __func__, liobn, ioba);
#endif
    regs->gprs[3] = H_Function;
    BUG();
}

static void h_stuff_tce(struct cpu_user_regs *regs)
{
    u32 liobn = regs->gprs[4];
    ulong ioba = regs->gprs[5];
    u64 tce_dword = regs->gprs[6];
    ulong count = regs->gprs[7];
    union tce tce;

    tce.tce_dword = tce_dword;
#ifdef DEBUG
    printk("%s: liobn: 0x%x ioba: 0x%lx tce: 0x%"
            PRIx64"(0x%"PRIx64") count: %lu\n",
           __func__, liobn, ioba, tce.tce_dword, (long)tce.tce_bits.tce_rpn,
            count);
#endif
    regs->gprs[3] = H_Function;
    BUG();
}
   
__init_papr_hcall(H_PUT_TCE, h_put_tce);
__init_papr_hcall(H_GET_TCE, h_get_tce);
__init_papr_hcall(H_STUFF_TCE, h_stuff_tce);
