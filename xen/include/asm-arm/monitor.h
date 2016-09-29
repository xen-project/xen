/*
 * include/asm-arm/monitor.h
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

#ifndef __ASM_ARM_MONITOR_H__
#define __ASM_ARM_MONITOR_H__

#include <xen/sched.h>
#include <public/domctl.h>

static inline
int arch_monitor_domctl_op(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    /* No arch-specific monitor ops on ARM. */
    return -EOPNOTSUPP;
}

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

static inline
int arch_monitor_init_domain(struct domain *d)
{
    /* No arch-specific domain initialization on ARM. */
    return 0;
}

static inline
void arch_monitor_cleanup_domain(struct domain *d)
{
    /* No arch-specific domain cleanup on ARM. */
}

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    uint32_t capabilities = 0;

    capabilities = (1U << XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST |
                    1U << XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL);

    return capabilities;
}

int monitor_smc(void);

#endif /* __ASM_ARM_MONITOR_H__ */
