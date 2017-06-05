/******************************************************************************
 * arch/x86/pv/traps.c
 *
 * PV low level entry points.
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

#include <xen/hypercall.h>
#include <xen/lib.h>
#include <xen/trace.h>

#include <asm/apic.h>
#include <asm/shared.h>
#include <asm/traps.h>

void do_entry_int82(struct cpu_user_regs *regs)
{
    if ( unlikely(untrusted_msi) )
        check_for_unexpected_msi((uint8_t)regs->entry_vector);

    pv_hypercall(regs);
}

void pv_inject_event(const struct x86_event *event)
{
    struct vcpu *curr = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct trap_bounce *tb;
    const struct trap_info *ti;
    const uint8_t vector = event->vector;
    unsigned int error_code = event->error_code;
    bool use_error_code;

    ASSERT(vector == event->vector); /* Confirm no truncation. */
    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION )
    {
        ASSERT(vector < 32);
        use_error_code = TRAP_HAVE_EC & (1u << vector);
    }
    else
    {
        ASSERT(event->type == X86_EVENTTYPE_SW_INTERRUPT);
        use_error_code = false;
    }
    if ( use_error_code )
        ASSERT(error_code != X86_EVENT_NO_EC);
    else
        ASSERT(error_code == X86_EVENT_NO_EC);

    tb = &curr->arch.pv_vcpu.trap_bounce;
    ti = &curr->arch.pv_vcpu.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION &&
         vector == TRAP_page_fault )
    {
        curr->arch.pv_vcpu.ctrlreg[2] = event->cr2;
        arch_set_cr2(curr, event->cr2);

        /* Re-set error_code.user flag appropriately for the guest. */
        error_code &= ~PFEC_user_mode;
        if ( !guest_kernel_mode(curr, regs) )
            error_code |= PFEC_user_mode;

        trace_pv_page_fault(event->cr2, error_code);
    }
    else
        trace_pv_trap(vector, regs->rip, use_error_code, error_code);

    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = error_code;
    }

    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;

    if ( unlikely(null_trap_bounce(curr, tb)) )
    {
        gprintk(XENLOG_WARNING,
                "Unhandled %s fault/trap [#%d, ec=%04x]\n",
                trapstr(vector), vector, error_code);

        if ( vector == TRAP_page_fault )
            show_page_walk(event->cr2);
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
