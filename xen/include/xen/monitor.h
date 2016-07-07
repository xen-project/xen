/*
 * include/xen/monitor.h
 *
 * Common monitor_op domctl handler.
 *
 * Copyright (c) 2015-2016 Tamas K Lengyel (tamas@tklengyel.com)
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

#ifndef __XEN_MONITOR_H__
#define __XEN_MONITOR_H__

#include <public/vm_event.h>

struct domain;
struct xen_domctl_monitor_op;

int monitor_domctl(struct domain *d, struct xen_domctl_monitor_op *op);
void monitor_guest_request(void);

int monitor_traps(struct vcpu *v, bool_t sync, vm_event_request_t *req);

#endif /* __XEN_MONITOR_H__ */
