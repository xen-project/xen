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
    [ __HYPERVISOR_ ## x ] = { n, n }
#define COMP(x, n, c)                           \
    [ __HYPERVISOR_ ## x ] = { n, c }

const hypercall_args_t hypercall_args_table[NR_hypercalls] =
{
    ARGS(set_trap_table, 1),
    ARGS(mmu_update, 4),
    ARGS(set_gdt, 2),
    ARGS(stack_switch, 2),
    COMP(set_callbacks, 3, 4),
    ARGS(fpu_taskswitch, 1),
    ARGS(sched_op_compat, 2),
    ARGS(platform_op, 1),
    ARGS(set_debugreg, 2),
    ARGS(get_debugreg, 1),
    COMP(update_descriptor, 2, 4),
    ARGS(memory_op, 2),
    ARGS(multicall, 2),
    COMP(update_va_mapping, 3, 4),
    COMP(set_timer_op, 1, 2),
    ARGS(event_channel_op_compat, 1),
    ARGS(xen_version, 2),
    ARGS(console_io, 3),
    ARGS(physdev_op_compat, 1),
    ARGS(grant_table_op, 3),
    ARGS(vm_assist, 2),
    COMP(update_va_mapping_otherdomain, 4, 5),
    ARGS(vcpu_op, 3),
    COMP(set_segment_base, 2, 0),
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

#undef COMP
#undef ARGS

#define HYPERCALL(x)                                                \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,         \
                               (hypercall_fn_t *) do_ ## x }
#define COMPAT_CALL(x)                                              \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,         \
                               (hypercall_fn_t *) compat_ ## x }

#define do_arch_1             paging_domctl_continuation

static const hypercall_table_t pv_hypercall_table[] = {
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

    BUILD_BUG_ON(ARRAY_SIZE(pv_hypercall_table) >
                 ARRAY_SIZE(hypercall_args_table));

    if ( (eax >= ARRAY_SIZE(pv_hypercall_table)) ||
         !pv_hypercall_table[eax].native )
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
        switch ( hypercall_args_table[eax].native )
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

        regs->eax = pv_hypercall_table[eax].native(rdi, rsi, rdx, r10, r8, r9);

#ifndef NDEBUG
        if ( regs->rip == old_rip )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].native )
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
        switch ( hypercall_args_table[eax].compat )
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

        regs->_eax = pv_hypercall_table[eax].compat(ebx, ecx, edx, esi, edi, ebp);

#ifndef NDEBUG
        if ( regs->rip == old_rip )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].compat )
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

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    struct vcpu *curr = current;
    unsigned long op;

    if ( !is_pv_32bit_vcpu(curr) )
    {
        struct multicall_entry *call = &state->call;

        op = call->op;
        if ( (op < ARRAY_SIZE(pv_hypercall_table)) &&
             pv_hypercall_table[op].native )
            call->result = pv_hypercall_table[op].native(
                call->args[0], call->args[1], call->args[2],
                call->args[3], call->args[4], call->args[5]);
        else
            call->result = -ENOSYS;
    }
#ifdef CONFIG_COMPAT
    else
    {
        struct compat_multicall_entry *call = &state->compat_call;

        op = call->op;
        if ( (op < ARRAY_SIZE(pv_hypercall_table)) &&
             pv_hypercall_table[op].compat )
            call->result = pv_hypercall_table[op].compat(
                call->args[0], call->args[1], call->args[2],
                call->args[3], call->args[4], call->args[5]);
        else
            call->result = -ENOSYS;
    }
#endif

    return unlikely(op == __HYPERVISOR_iret)
           ? mc_exit
           : likely(guest_kernel_mode(curr, guest_cpu_user_regs()))
             ? mc_continue : mc_preempt;
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

