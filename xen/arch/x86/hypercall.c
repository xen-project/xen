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

#include <xen/compiler.h>
#include <xen/hypercall.h>
#include <xen/trace.h>

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

#define HYPERCALL(x)                                                \
    [ __HYPERVISOR_ ## x ] = (hypercall_fn_t *) do_ ## x

#define do_arch_1             paging_domctl_continuation

hypercall_fn_t *const hypercall_table[NR_hypercalls] = {
    HYPERCALL(set_trap_table),
    HYPERCALL(mmu_update),
    HYPERCALL(set_gdt),
    HYPERCALL(stack_switch),
    HYPERCALL(set_callbacks),
    HYPERCALL(fpu_taskswitch),
    HYPERCALL(sched_op_compat),
    HYPERCALL(platform_op),
    HYPERCALL(set_debugreg),
    HYPERCALL(get_debugreg),
    HYPERCALL(update_descriptor),
    HYPERCALL(memory_op),
    HYPERCALL(multicall),
    HYPERCALL(update_va_mapping),
    HYPERCALL(set_timer_op),
    HYPERCALL(event_channel_op_compat),
    HYPERCALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(physdev_op_compat),
    HYPERCALL(grant_table_op),
    HYPERCALL(vm_assist),
    HYPERCALL(update_va_mapping_otherdomain),
    HYPERCALL(iret),
    HYPERCALL(vcpu_op),
    HYPERCALL(set_segment_base),
    HYPERCALL(mmuext_op),
    HYPERCALL(xsm_op),
    HYPERCALL(nmi_op),
    HYPERCALL(sched_op),
    HYPERCALL(callback_op),
#ifdef CONFIG_XENOPROF
    HYPERCALL(xenoprof_op),
#endif
    HYPERCALL(event_channel_op),
    HYPERCALL(physdev_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_KEXEC
    HYPERCALL(kexec_op),
#endif
#ifdef CONFIG_TMEM
    HYPERCALL(tmem_op),
#endif
    HYPERCALL(xenpmu_op),
    HYPERCALL(mca),
    HYPERCALL(arch_1),
};

#define COMPAT_CALL(x)                                              \
    [ __HYPERVISOR_ ## x ] = (hypercall_fn_t *) compat_ ## x

hypercall_fn_t *const compat_hypercall_table[NR_hypercalls] = {
    COMPAT_CALL(set_trap_table),
    HYPERCALL(mmu_update),
    COMPAT_CALL(set_gdt),
    HYPERCALL(stack_switch),
    COMPAT_CALL(set_callbacks),
    HYPERCALL(fpu_taskswitch),
    HYPERCALL(sched_op_compat),
    COMPAT_CALL(platform_op),
    HYPERCALL(set_debugreg),
    HYPERCALL(get_debugreg),
    COMPAT_CALL(update_descriptor),
    COMPAT_CALL(memory_op),
    COMPAT_CALL(multicall),
    COMPAT_CALL(update_va_mapping),
    COMPAT_CALL(set_timer_op),
    HYPERCALL(event_channel_op_compat),
    COMPAT_CALL(xen_version),
    HYPERCALL(console_io),
    COMPAT_CALL(physdev_op_compat),
    COMPAT_CALL(grant_table_op),
    COMPAT_CALL(vm_assist),
    COMPAT_CALL(update_va_mapping_otherdomain),
    COMPAT_CALL(iret),
    COMPAT_CALL(vcpu_op),
    HYPERCALL(set_segment_base),
    COMPAT_CALL(mmuext_op),
    COMPAT_CALL(xsm_op),
    COMPAT_CALL(nmi_op),
    COMPAT_CALL(sched_op),
    COMPAT_CALL(callback_op),
#ifdef CONFIG_XENOPROF
    COMPAT_CALL(xenoprof_op),
#endif
    HYPERCALL(event_channel_op),
    COMPAT_CALL(physdev_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_KEXEC
    COMPAT_CALL(kexec_op),
#endif
#ifdef CONFIG_TMEM
    HYPERCALL(tmem_op),
#endif
    HYPERCALL(xenpmu_op),
    HYPERCALL(mca),
    HYPERCALL(arch_1),
};

#undef do_arch_1
#undef COMPAT_CALL
#undef HYPERCALL

void pv_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
#ifndef NDEBUG
    unsigned long old_rip = regs->rip;
#endif
    unsigned long eax;

    ASSERT(guest_kernel_mode(curr, regs));

    eax = is_pv_32bit_vcpu(curr) ? regs->_eax : regs->eax;

    if ( (eax >= NR_hypercalls) || !hypercall_table[eax] )
    {
        regs->eax = -ENOSYS;
        return;
    }

    if ( !is_pv_32bit_vcpu(curr) )
    {
        unsigned long rdi = regs->rdi;
        unsigned long rsi = regs->rsi;
        unsigned long rdx = regs->rdx;
        unsigned long r10 = regs->r10;
        unsigned long r8 = regs->r8;
        unsigned long r9 = regs->r9;

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( hypercall_args_table[eax] )
        {
        case 0: rdi = 0xdeadbeefdeadf00dUL;
        case 1: rsi = 0xdeadbeefdeadf00dUL;
        case 2: rdx = 0xdeadbeefdeadf00dUL;
        case 3: r10 = 0xdeadbeefdeadf00dUL;
        case 4: r8 = 0xdeadbeefdeadf00dUL;
        case 5: r9 = 0xdeadbeefdeadf00dUL;
        }
#endif
        if ( unlikely(tb_init_done) )
        {
            unsigned long args[6] = { rdi, rsi, rdx, r10, r8, r9 };

            __trace_hypercall(TRC_PV_HYPERCALL_V2, eax, args);
        }

        regs->eax = hypercall_table[eax](rdi, rsi, rdx, r10, r8, r9);

#ifndef NDEBUG
        if ( regs->rip == old_rip )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax] )
            {
            case 6: regs->r9  = 0xdeadbeefdeadf00dUL;
            case 5: regs->r8  = 0xdeadbeefdeadf00dUL;
            case 4: regs->r10 = 0xdeadbeefdeadf00dUL;
            case 3: regs->rdx = 0xdeadbeefdeadf00dUL;
            case 2: regs->rsi = 0xdeadbeefdeadf00dUL;
            case 1: regs->rdi = 0xdeadbeefdeadf00dUL;
            }
        }
#endif
    }
    else
    {
        unsigned int ebx = regs->_ebx;
        unsigned int ecx = regs->_ecx;
        unsigned int edx = regs->_edx;
        unsigned int esi = regs->_esi;
        unsigned int edi = regs->_edi;
        unsigned int ebp = regs->_ebp;

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( compat_hypercall_args_table[eax] )
        {
        case 0: ebx = 0xdeadf00d;
        case 1: ecx = 0xdeadf00d;
        case 2: edx = 0xdeadf00d;
        case 3: esi = 0xdeadf00d;
        case 4: edi = 0xdeadf00d;
        case 5: ebp = 0xdeadf00d;
        }
#endif

        if ( unlikely(tb_init_done) )
        {
            unsigned long args[6] = { ebx, ecx, edx, esi, edi, ebp };

            __trace_hypercall(TRC_PV_HYPERCALL_V2, eax, args);
        }

        regs->_eax = compat_hypercall_table[eax](ebx, ecx, edx, esi, edi, ebp);

#ifndef NDEBUG
        if ( regs->rip == old_rip )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( compat_hypercall_args_table[eax] )
            {
            case 6: regs->_ebp = 0xdeadf00d;
            case 5: regs->_edi = 0xdeadf00d;
            case 4: regs->_esi = 0xdeadf00d;
            case 3: regs->_edx = 0xdeadf00d;
            case 2: regs->_ecx = 0xdeadf00d;
            case 1: regs->_ebx = 0xdeadf00d;
            }
        }
#endif
    }

    perfc_incr(hypercalls);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

