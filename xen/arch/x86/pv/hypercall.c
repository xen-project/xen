/******************************************************************************
 * arch/x86/pv/hypercall.c
 *
 * PV hypercall dispatching routines
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
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/compiler.h>
#include <xen/hypercall.h>
#include <xen/nospec.h>
#include <xen/trace.h>

#define HYPERCALL(x)                                                \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,         \
                               (hypercall_fn_t *) do_ ## x }
#define COMPAT_CALL(x)                                              \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,         \
                               (hypercall_fn_t *) compat_ ## x }

#define do_arch_1             paging_domctl_continuation

const hypercall_table_t pv_hypercall_table[] = {
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
#ifdef CONFIG_GRANT_TABLE
    COMPAT_CALL(grant_table_op),
#endif
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
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_KEXEC
    COMPAT_CALL(kexec_op),
#endif
#ifdef CONFIG_ARGO
    COMPAT_CALL(argo_op),
#endif
    HYPERCALL(xenpmu_op),
#ifdef CONFIG_HVM
    HYPERCALL(hvm_op),
    COMPAT_CALL(dm_op),
#endif
    HYPERCALL(mca),
    HYPERCALL(arch_1),
};

#undef do_arch_1
#undef COMPAT_CALL
#undef HYPERCALL

void pv_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    unsigned long eax;

    ASSERT(guest_kernel_mode(curr, regs));

    eax = is_pv_32bit_vcpu(curr) ? regs->eax : regs->rax;

    BUILD_BUG_ON(ARRAY_SIZE(pv_hypercall_table) >
                 ARRAY_SIZE(hypercall_args_table));

    if ( eax >= ARRAY_SIZE(pv_hypercall_table) )
    {
        regs->rax = -ENOSYS;
        return;
    }

    eax = array_index_nospec(eax, ARRAY_SIZE(pv_hypercall_table));

    if ( !pv_hypercall_table[eax].native )
    {
        regs->rax = -ENOSYS;
        return;
    }

    curr->hcall_preempted = false;

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

        regs->rax = pv_hypercall_table[eax].native(rdi, rsi, rdx, r10, r8, r9);

#ifndef NDEBUG
        if ( !curr->hcall_preempted )
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
        unsigned int ebx = regs->ebx;
        unsigned int ecx = regs->ecx;
        unsigned int edx = regs->edx;
        unsigned int esi = regs->esi;
        unsigned int edi = regs->edi;
        unsigned int ebp = regs->ebp;

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

        curr->hcall_compat = true;
        regs->eax = pv_hypercall_table[eax].compat(ebx, ecx, edx, esi, edi, ebp);
        curr->hcall_compat = false;

#ifndef NDEBUG
        if ( !curr->hcall_preempted )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].compat )
            {
            case 6: regs->ebp = 0xdeadf00d;
            case 5: regs->edi = 0xdeadf00d;
            case 4: regs->esi = 0xdeadf00d;
            case 3: regs->edx = 0xdeadf00d;
            case 2: regs->ecx = 0xdeadf00d;
            case 1: regs->ebx = 0xdeadf00d;
            }
        }
#endif
    }

    /*
     * PV guests use SYSCALL or INT $0x82 to make a hypercall, both of which
     * have trap semantics.  If the hypercall has been preempted, rewind the
     * instruction pointer to reexecute the instruction.
     */
    if ( curr->hcall_preempted )
        regs->rip -= 2;

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

void pv_ring3_init_hypercall_page(void *p)
{
    unsigned int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++, p += 32 )
    {
        if ( unlikely(i == __HYPERVISOR_iret) )
        {
            /*
             * HYPERVISOR_iret is special because it doesn't return and
             * expects a special stack frame. Guests jump at this transfer
             * point instead of calling it.
             */
            *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
            *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
            *(u8  *)(p+ 3) = 0x50;    /* push %rax */
            *(u8  *)(p+ 4) = 0xb8;    /* mov  $__HYPERVISOR_iret, %eax */
            *(u32 *)(p+ 5) = __HYPERVISOR_iret;
            *(u16 *)(p+ 9) = 0x050f;  /* syscall */

            continue;
        }

        *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
        *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
        *(u8  *)(p+ 3) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 4) = i;
        *(u16 *)(p+ 8) = 0x050f;  /* syscall */
        *(u16 *)(p+10) = 0x5b41;  /* pop  %r11 */
        *(u8  *)(p+12) = 0x59;    /* pop  %rcx */
        *(u8  *)(p+13) = 0xc3;    /* ret */
    }
}

void pv_ring1_init_hypercall_page(void *p)
{
    unsigned int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++, p += 32 )
    {
        if ( unlikely(i == __HYPERVISOR_iret) )
        {
            /*
             * HYPERVISOR_iret is special because it doesn't return and
             * expects a special stack frame. Guests jump at this transfer
             * point instead of calling it.
             */
            *(u8  *)(p+ 0) = 0x50;    /* push %eax */
            *(u8  *)(p+ 1) = 0xb8;    /* mov  $__HYPERVISOR_iret, %eax */
            *(u32 *)(p+ 2) = __HYPERVISOR_iret;
            *(u16 *)(p+ 6) = (HYPERCALL_VECTOR << 8) | 0xcd; /* int  $xx */

            continue;
        }

        *(u8  *)(p+ 0) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 1) = i;
        *(u16 *)(p+ 5) = (HYPERCALL_VECTOR << 8) | 0xcd; /* int  $xx */
        *(u8  *)(p+ 7) = 0xc3;    /* ret */
    }
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

