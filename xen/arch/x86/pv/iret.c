/*
 * pv/iret.c
 *
 * iret hypercall handling code
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/current.h>
#include <asm/traps.h>

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
    {
        gprintk(XENLOG_ERR,
                "Fault while reading IRET context from guest stack\n");
        goto exit_and_crash;
    }

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_is_null(v->arch.guest_table_user)) )
        {
            gprintk(XENLOG_ERR,
                    "Guest switching to user mode with no user page tables\n");
            goto exit_and_crash;
        }
        toggle_guest_mode(v);
    }

    if ( VM_ASSIST(v->domain, architectural_iopl) )
        v->arch.pv_vcpu.iopl = iret_saved.rflags & X86_EFLAGS_IOPL;

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = ((iret_saved.rflags & ~(X86_EFLAGS_IOPL|X86_EFLAGS_VM))
                    | X86_EFLAGS_IF);
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_in_syscall) )
    {
        regs->entry_vector &= ~TRAP_syscall;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(iret_saved.rflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
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
