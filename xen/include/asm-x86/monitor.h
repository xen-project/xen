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

#define monitor_ctrlreg_bitmask(ctrlreg_index) (1U << (ctrlreg_index))

struct monitor_msr_bitmap {
    DECLARE_BITMAP(low, 8192);
    DECLARE_BITMAP(hypervisor, 8192);
    DECLARE_BITMAP(high, 8192);
};

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    int rc = 0;

    switch ( mop->op )
    {
    case XEN_DOMCTL_MONITOR_OP_EMULATE_EACH_REP:
        domain_pause(d);
        /*
         * Enabling mem_access_emulate_each_rep without a vm_event subscriber
         * is meaningless.
         */
        if ( d->max_vcpus && d->vcpu[0] && d->vcpu[0]->arch.vm_event )
            d->arch.mem_access_emulate_each_rep = !!mop->event;
        else
            rc = -EINVAL;

        domain_unpause(d);
        break;

    default:
        rc = -EOPNOTSUPP;
    }

    return rc;
}

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    uint32_t capabilities = 0;

    /*
     * At the moment only Intel HVM domains are supported. However, event
     * delivery could be extended to AMD and PV domains.
     */
    if ( !is_hvm_domain(d) || !cpu_has_vmx )
        return capabilities;

    capabilities = (1U << XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_DEBUG_EXCEPTION) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_CPUID);

    /* Since we know this is on VMX, we can just call the hvm func */
    if ( hvm_is_singlestep_supported() )
        capabilities |= (1U << XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP);

    return capabilities;
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

int arch_monitor_init_domain(struct domain *d);

void arch_monitor_cleanup_domain(struct domain *d);

bool_t monitored_msr(const struct domain *d, u32 msr);

#endif /* __ASM_X86_MONITOR_H__ */
