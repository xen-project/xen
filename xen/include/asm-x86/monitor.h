/*
 * include/asm-x86/monitor.h
 *
 * Arch-specific monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_MONITOR_H__
#define __ASM_X86_MONITOR_H__

#include <xen/sched.h>
#include <public/domctl.h>
#include <asm/cpufeature.h>
#include <asm/hvm/hvm.h>

#define monitor_ctrlreg_bitmask(ctrlreg_index) (1U << (ctrlreg_index))

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    switch ( mop->op )
    {
    case XEN_DOMCTL_MONITOR_OP_EMULATE_EACH_REP:
        domain_pause(d);
        d->arch.mem_access_emulate_each_rep = !!mop->event;
        domain_unpause(d);
        break;

    default:
        return -EOPNOTSUPP;
    }

    return 0;
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

#endif /* __ASM_X86_MONITOR_H__ */
