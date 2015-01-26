/******************************************************************************
 * arch/x86/hypercall.c
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
 * Copyright (c) 2015,2016 Citrix Systems Ltd.
 */

#include <xen/hypercall.h>

#define ARGS(x, n)                              \
    [ __HYPERVISOR_ ## x ] = (n)

const uint8_t hypercall_args_table[NR_hypercalls] =
{
    ARGS(set_trap_table, 1),
    ARGS(mmu_update, 4),
    ARGS(set_gdt, 2),
    ARGS(stack_switch, 2),
    ARGS(set_callbacks, 3),
    ARGS(fpu_taskswitch, 1),
    ARGS(sched_op_compat, 2),
    ARGS(platform_op, 1),
    ARGS(set_debugreg, 2),
    ARGS(get_debugreg, 1),
    ARGS(update_descriptor, 2),
    ARGS(memory_op, 2),
    ARGS(multicall, 2),
    ARGS(update_va_mapping, 3),
    ARGS(set_timer_op, 1),
    ARGS(event_channel_op_compat, 1),
    ARGS(xen_version, 2),
    ARGS(console_io, 3),
    ARGS(physdev_op_compat, 1),
    ARGS(grant_table_op, 3),
    ARGS(vm_assist, 2),
    ARGS(update_va_mapping_otherdomain, 4),
    ARGS(vcpu_op, 3),
    ARGS(set_segment_base, 2),
    ARGS(mmuext_op, 4),
    ARGS(xsm_op, 1),
    ARGS(nmi_op, 2),
    ARGS(sched_op, 2),
    ARGS(callback_op, 2),
    ARGS(xenoprof_op, 2),
    ARGS(event_channel_op, 2),
    ARGS(physdev_op, 2),
    ARGS(hvm_op, 2),
    ARGS(sysctl, 1),
    ARGS(domctl, 1),
    ARGS(kexec_op, 2),
    ARGS(tmem_op, 1),
    ARGS(xenpmu_op, 2),
    ARGS(mca, 1),
    ARGS(arch_1, 1),
};

const uint8_t compat_hypercall_args_table[NR_hypercalls] =
{
    ARGS(set_trap_table, 1),
    ARGS(mmu_update, 4),
    ARGS(set_gdt, 2),
    ARGS(stack_switch, 2),
    ARGS(set_callbacks, 4),
    ARGS(fpu_taskswitch, 1),
    ARGS(sched_op_compat, 2),
    ARGS(platform_op, 1),
    ARGS(set_debugreg, 2),
    ARGS(get_debugreg, 1),
    ARGS(update_descriptor, 4),
    ARGS(memory_op, 2),
    ARGS(multicall, 2),
    ARGS(update_va_mapping, 4),
    ARGS(set_timer_op, 2),
    ARGS(event_channel_op_compat, 1),
    ARGS(xen_version, 2),
    ARGS(console_io, 3),
    ARGS(physdev_op_compat, 1),
    ARGS(grant_table_op, 3),
    ARGS(vm_assist, 2),
    ARGS(update_va_mapping_otherdomain, 5),
    ARGS(vcpu_op, 3),
    ARGS(mmuext_op, 4),
    ARGS(xsm_op, 1),
    ARGS(nmi_op, 2),
    ARGS(sched_op, 2),
    ARGS(callback_op, 2),
    ARGS(xenoprof_op, 2),
    ARGS(event_channel_op, 2),
    ARGS(physdev_op, 2),
    ARGS(hvm_op, 2),
    ARGS(sysctl, 1),
    ARGS(domctl, 1),
    ARGS(kexec_op, 2),
    ARGS(tmem_op, 1),
    ARGS(xenpmu_op, 2),
    ARGS(mca, 1),
    ARGS(arch_1, 1),
};

#undef ARGS

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

