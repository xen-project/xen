/******************************************************************************
 * include/asm-x86/guest/vixen.h
 *
 * Support for detecting and running under Xen HVM.
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2017-2018 Amazon.com, Inc. or its affiliates.
 */

#ifndef XEN_VIXEN_H
#define XEN_VIXEN_H

#include <asm/guest.h>
#include <public/xen.h>
#include <xen/sched.h>

static inline int
HYPERVISOR_xen_version(int cmd, void *arg)
{
    return _hypercall64_2(int, __HYPERVISOR_xen_version, cmd, arg);
}

static inline unsigned long
HYPERVISOR_hvm_op(int op, void *arg)
{
   return _hypercall64_2(unsigned long, __HYPERVISOR_hvm_op, op, arg);
}

static inline int
HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count)
{
    return _hypercall64_3(int, __HYPERVISOR_grant_table_op, cmd, uop, count);
}

static inline long
HYPERVISOR_memory_op(unsigned int cmd, void *arg)
{
    return _hypercall64_2(long, __HYPERVISOR_memory_op, cmd, arg);
}

static inline int
HYPERVISOR_event_channel_op(int cmd, void *arg)
{
    return _hypercall64_2(int, __HYPERVISOR_event_channel_op, cmd, arg);
}

static inline int
HYPERVISOR_sched_op(int cmd, void *arg)
{
    return _hypercall64_2(int, __HYPERVISOR_sched_op, cmd, arg);
}

static inline int
HYPERVISOR_vcpu_op(int cmd, int vcpuid, void *extra_args)
{
	return _hypercall64_3(int, __HYPERVISOR_vcpu_op, cmd, vcpuid, extra_args);
}

bool is_vixen(void);

void __init init_vixen(void);

void __init early_vixen_init(void);

u64 vixen_get_cpu_freq(void);

bool vixen_has_per_cpu_notifications(void);

void vixen_vcpu_initialize(struct vcpu *v);

void __init vixen_transform(struct domain *dom0);

#endif
