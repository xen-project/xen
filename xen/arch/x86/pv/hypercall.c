/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/hypercall.c
 *
 * PV hypercall dispatching routines
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/compiler.h>
#include <xen/hypercall.h>
#include <xen/nospec.h>
#include <xen/trace.h>

#include <asm/apic.h>
#include <asm/irq-vectors.h>
#include <asm/multicall.h>

/* Forced inline to cause 'compat' to be evaluated at compile time. */
static void always_inline
_pv_hypercall(struct cpu_user_regs *regs, bool compat)
{
    struct vcpu *curr = current;
    unsigned long eax = -1; /* Clang -Wsometimes-uninitialized */

    ASSERT(guest_kernel_mode(curr, regs));

    curr->hcall_preempted = false;

    if ( !compat )
    {
        unsigned long rdi = regs->rdi;
        unsigned long rsi = regs->rsi;
        unsigned long rdx = regs->rdx;
        unsigned long r10 = regs->r10;
        unsigned long r8 = regs->r8;

        eax = regs->rax;

        if ( unlikely(tb_init_done) )
        {
            unsigned long args[5] = { rdi, rsi, rdx, r10, r8 };

            __trace_hypercall(TRC_PV_HYPERCALL_V2, eax, args);
        }

        call_handlers_pv64(eax, regs->rax, rdi, rsi, rdx, r10, r8);

        if ( !curr->hcall_preempted && regs->rax != -ENOSYS )
            clobber_regs(regs, eax, pv, 64);
    }
#ifdef CONFIG_PV32
    else
    {
        unsigned int ebx = regs->ebx;
        unsigned int ecx = regs->ecx;
        unsigned int edx = regs->edx;
        unsigned int esi = regs->esi;
        unsigned int edi = regs->edi;

        eax = regs->eax;

        if ( unlikely(tb_init_done) )
        {
            unsigned long args[5] = { ebx, ecx, edx, esi, edi };

            __trace_hypercall(TRC_PV_HYPERCALL_V2, eax, args);
        }

        curr->hcall_compat = true;
        call_handlers_pv32(eax, regs->eax, ebx, ecx, edx, esi, edi);
        curr->hcall_compat = false;

        if ( !curr->hcall_preempted && regs->eax != -ENOSYS )
            clobber_regs(regs, eax, pv, 32);
    }
#endif /* CONFIG_PV32 */

    /*
     * PV guests use SYSCALL or INT $0x82 to make a hypercall, both of which
     * have trap semantics.  If the hypercall has been preempted, rewind the
     * instruction pointer to reexecute the instruction.
     */
    if ( curr->hcall_preempted )
        regs->rip -= 2;

    perfc_incra(hypercalls, eax);
}

enum mc_disposition pv_do_multicall_call(struct mc_state *state)
{
    struct vcpu *curr = current;
    unsigned long op;

#ifdef CONFIG_PV32
    if ( is_pv_32bit_vcpu(curr) )
    {
        struct compat_multicall_entry *call = &state->compat_call;

        op = call->op;
        call_handlers_pv32(op, call->result, call->args[0], call->args[1],
                           call->args[2], call->args[3], call->args[4]);
    }
    else
#endif
    {
        struct multicall_entry *call = &state->call;

        op = call->op;
        call_handlers_pv64(op, call->result, call->args[0], call->args[1],
                           call->args[2], call->args[3], call->args[4]);
    }

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

#ifdef CONFIG_PV32
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

void do_entry_int82(struct cpu_user_regs *regs)
{
    if ( unlikely(untrusted_msi) )
        check_for_unexpected_msi((uint8_t)regs->entry_vector);

    _pv_hypercall(regs, true /* compat */);
}
#endif

void pv_hypercall(struct cpu_user_regs *regs)
{
    _pv_hypercall(regs, false /* native */);
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

