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

#define HAS_ARCH_MONITOR_DOMCTL_EVENT

#include <asm-generic/monitor.h>

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop);

static inline uint32_t arch_monitor_get_capabilities(struct domain *d)
{
    uint32_t capabilities = 0;

    capabilities = (1U << XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST |
                    1U << XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL);

    return capabilities;
}

int monitor_smc(void);

#endif /* __ASM_ARM_MONITOR_H__ */
