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
 * Copyright IBM Corp. 2005, 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/multicall.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include <asm/debugger.h>
#include <asm/msr.h>
#include "exceptions.h"

u32 *papr_hcalls;               /* PAPR Hypervisor Calls */
u32 *hypercall_table;           /* Xen Hypervisor Calls */

static void hcall_papr(ulong num, struct cpu_user_regs *regs)
{
    u32 address;

    if (regs->msr & MSR_PR) {
        regs->gprs[3] = H_Privilege;
        return;
    }

    if ((num & 0x3) || (num > RPA_HCALL_END)) {
        regs->gprs[3] = H_Parameter;
        return;
    }

    address = papr_hcalls[num/4];
    papr_hcall_jump(regs, address);
}

static void hcall_xen(ulong num, struct cpu_user_regs *regs)
{
    u32 address;

    if (regs->msr & MSR_PR) {
        regs->gprs[3] = -EPERM;
        return;
    }

    if ((num >= NR_hypercalls)) {
        regs->gprs[3] = -ENOSYS;
        return;
    }
    address = hypercall_table[num];
    if (address == 0) {
        printk("unsupported Xen hypercall: 0x%lx\n", num);
        regs->gprs[3] = -ENOSYS;
        return;
    }

    regs->gprs[3] = xen_hvcall_jump(regs, address);
}

void do_multicall_call(multicall_entry_t *call)
{
    struct cpu_user_regs regs;

    regs.gprs[3] = call->args[0];
    regs.gprs[4] = call->args[1];
    regs.gprs[5] = call->args[2];
    regs.gprs[6] = call->args[3];
    regs.gprs[7] = call->args[4];
    regs.gprs[8] = call->args[5];

    hcall_xen(call->op, &regs);

    call->result = regs.gprs[3];
}

void do_hcall(struct cpu_user_regs *regs)
{
    ulong num = regs->gprs[3];

    local_irq_enable();

    if ((num & XEN_MARK(0)) == XEN_MARK(0)) {
        /* it's a Xen call */
        num &= ~XEN_MARK(0);
        hcall_xen(num, regs);
    } else {
        /* it's a PAPR call */
        hcall_papr(num, regs);
    }
}

static void do_ni_papr_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *v = get_current();

    printk("unsupported PAPR hcall 0x%lx was called by dom0x%x\n",
            regs->gprs[3], v->domain->domain_id);

    regs->gprs[3] = H_Parameter;
}

/* store low 32 bits of 64-bit address in hcall table (this is safe because we
 * know we will not link above 4GB). We don't need to preserve the TOC
 * because that only changes when calling dynamically linked objects. */
static void register_papr_hcall(ulong num, hcall_handler_t handler)
{
    int index = num/4;

    papr_hcalls[index] = (u32)(*(u64 *)handler);
}

static void init_papr_hcalls(void)
{
    init_hcall_t *hcall;
    int i;

    /* initialize PAPR hcall table */
    papr_hcalls = xmalloc_array(u32, RPA_HCALL_END/4);
    ASSERT(papr_hcalls != NULL);
    for (i = 0; i <= RPA_HCALL_END; i += 4)
        register_papr_hcall(i, do_ni_papr_hypercall);

    /* register the PAPR hcalls */
    for (hcall = &__init_hcall_start; hcall < &__init_hcall_end; hcall++) {
        register_papr_hcall(hcall->number, hcall->handler);
    }
}

static void init_hypercall_table(void)
{
    int i;

    hypercall_table = xmalloc_array(u32, NR_hypercalls);
    ASSERT(hypercall_table != NULL);

    for (i = 0; i < NR_hypercalls; i++) {
        if (__hypercall_table[i] == NULL ) {
            hypercall_table[i] = 0;
        } else {
            hypercall_table[i] = (u32)(*__hypercall_table[i]);
        }
    }
}

static int init_hcalls(void)
{
    init_papr_hcalls();
    init_hypercall_table();

    return 0;
}
__initcall(init_hcalls);
