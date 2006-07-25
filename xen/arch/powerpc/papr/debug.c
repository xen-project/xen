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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>

#define DABR_BT (1UL << 2)
#define DABR_DW (1UL << 1)
#define DABR_DR (1UL << 0)

#define DABRX_BT (1UL << 3)
#define DABRX_HYP (1UL << 2)
#define DABRX_PNH (1UL << 1)
#define DABRX_PRO (1UL << 0)

static inline int has_dabrx(void) { return 1; }

static void h_set_dabr(struct cpu_user_regs *regs)
{
    ulong dabr = regs->gprs[4];

    if (!has_dabrx()) {
        if (!(dabr & DABR_BT)) {
            regs->gprs[3] = H_Parameter;
            return;
        }
    } else {
        asm volatile("mtspr %0,%1" : : "I" (SPRN_DABRX), "r" (2) : "memory");
    }
    asm volatile("mtspr %0,%1" : : "I" (SPRN_DABR), "r" (dabr) : "memory");
    regs->gprs[3] = H_Success;
}

static void h_set_xdabr(struct cpu_user_regs *regs)
{
    ulong dabr = regs->gprs[4];
    ulong dabrx = regs->gprs[5];

    if (!has_dabrx()) {
        regs->gprs[3] = H_Function;
        return;
    }
    /* make sure reserved bits are 0 */
    if ((dabrx & ~((DABRX_BT << 1) - 1)) != 0) {
        regs->gprs[3] = H_Parameter;
        return;
    }
    if ((dabrx & DABRX_HYP) || dabrx == 0) {
        regs->gprs[3] = H_Parameter;
        return;
    }
    asm volatile("mtspr %0,%1; mtspr %2,%3"
            : /* output */ :
            "I" (SPRN_DABR), "r" (dabr),
            "I" (SPRN_DABRX), "r" (dabrx) : "memory");

    regs->gprs[3] = H_Success;
}

__init_papr_hcall(H_SET_DABR, h_set_dabr);
__init_papr_hcall(H_SET_XDABR, h_set_xdabr);
