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

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

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

unsigned int compat_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct vcpu *v = current;
    u32 eflags;

    /* Trim stack pointer to 32 bits. */
    regs->rsp = (u32)regs->rsp;

    /* Restore EAX (clobbered by hypercall). */
    if ( unlikely(__get_user(regs->eax, (u32 *)regs->rsp)) )
    {
        domain_crash(v->domain);
        return 0;
    }

    /* Restore CS and EIP. */
    if ( unlikely(__get_user(regs->eip, (u32 *)regs->rsp + 1)) ||
        unlikely(__get_user(regs->cs, (u32 *)regs->rsp + 2)) )
    {
        domain_crash(v->domain);
        return 0;
    }

    /*
     * Fix up and restore EFLAGS. We fix up in a local staging area
     * to avoid firing the BUG_ON(IOPL) check in arch_get_info_guest.
     */
    if ( unlikely(__get_user(eflags, (u32 *)regs->rsp + 3)) )
    {
        domain_crash(v->domain);
        return 0;
    }

    if ( VM_ASSIST(v->domain, architectural_iopl) )
        v->arch.pv_vcpu.iopl = eflags & X86_EFLAGS_IOPL;

    regs->eflags = (eflags & ~X86_EFLAGS_IOPL) | X86_EFLAGS_IF;

    if ( unlikely(eflags & X86_EFLAGS_VM) )
    {
        /*
         * Cannot return to VM86 mode: inject a GP fault instead. Note that
         * the GP fault is reported on the first VM86 mode instruction, not on
         * the IRET (which is why we can simply leave the stack frame as-is
         * (except for perhaps having to copy it), which in turn seems better
         * than teaching create_bounce_frame() to needlessly deal with vm86
         * mode frames).
         */
        const struct trap_info *ti;
        u32 x, ksp = v->arch.pv_vcpu.kernel_sp - 40;
        unsigned int i;
        int rc = 0;

        gdprintk(XENLOG_ERR, "VM86 mode unavailable (ksp:%08X->%08X)\n",
                 regs->esp, ksp);
        if ( ksp < regs->esp )
        {
            for (i = 1; i < 10; ++i)
            {
                rc |= __get_user(x, (u32 *)regs->rsp + i);
                rc |= __put_user(x, (u32 *)(unsigned long)ksp + i);
            }
        }
        else if ( ksp > regs->esp )
        {
            for ( i = 9; i > 0; --i )
            {
                rc |= __get_user(x, (u32 *)regs->rsp + i);
                rc |= __put_user(x, (u32 *)(unsigned long)ksp + i);
            }
        }
        if ( rc )
        {
            domain_crash(v->domain);
            return 0;
        }
        regs->esp = ksp;
        regs->ss = v->arch.pv_vcpu.kernel_ss;

        ti = &v->arch.pv_vcpu.trap_ctxt[TRAP_gp_fault];
        if ( TI_GET_IF(ti) )
            eflags &= ~X86_EFLAGS_IF;
        regs->eflags &= ~(X86_EFLAGS_VM|X86_EFLAGS_RF|
                          X86_EFLAGS_NT|X86_EFLAGS_TF);
        if ( unlikely(__put_user(0, (u32 *)regs->rsp)) )
        {
            domain_crash(v->domain);
            return 0;
        }
        regs->eip = ti->address;
        regs->cs = ti->cs;
    }
    else if ( unlikely(ring_0(regs)) )
    {
        domain_crash(v->domain);
        return 0;
    }
    else if ( ring_1(regs) )
        regs->esp += 16;
    /* Return to ring 2/3: restore ESP and SS. */
    else if ( __get_user(regs->ss, (u32 *)regs->rsp + 5) ||
              __get_user(regs->esp, (u32 *)regs->rsp + 4) )
    {
        domain_crash(v->domain);
        return 0;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(eflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /*
     * The hypercall exit path will overwrite EAX with this return
     * value.
     */
    return regs->eax;
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
