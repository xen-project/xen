#include <asm/current.h>
#include <asm/regs.h>
#include <asm/alternative.h>
#include <asm/smccc.h>
#include <public/xen.h>

#define IFLAGS_D_BIT    8
#define IFLAGS_A_BIT    4
#define IFLAGS_I_BIT    2
#define IFLAGS_F_BIT    1

/*
 * Short-hands to define the interrupts (D, A, I, F)
 *
 * _ means the interrupt state will not change
 * X means the state of interrupt X will change
 *
 * To be used with msr daif{set, clr} only.
 *
 */
#define IFLAGS__AI_     IFLAGS_A_BIT | IFLAGS_I_BIT
#define IFLAGS__A__     IFLAGS_A_BIT
#define IFLAGS___I_     IFLAGS_I_BIT

/*
 * Stack pushing/popping (register pairs only). Equivalent to store decrement
 * before, load increment after.
 */
        .macro  push, xreg1, xreg2
        stp     \xreg1, \xreg2, [sp, #-16]!
        .endm

        .macro  pop, xreg1, xreg2
        ldp     \xreg1, \xreg2, [sp], #16
        .endm

/*
 * Save/restore guest mode specific state, outer stack frame
 */
        .macro  entry_guest, compat

        add     x21, sp, #UREGS_SPSR_el1
        mrs     x23, SPSR_el1
        str     x23, [x21]

        .if \compat == 0 /* Aarch64 mode */

        add     x21, sp, #UREGS_SP_el0
        mrs     x22, SP_el0
        str     x22, [x21]

        add     x21, sp, #UREGS_SP_el1
        mrs     x22, SP_el1
        mrs     x23, ELR_el1
        stp     x22, x23, [x21]

        .else            /* Aarch32 mode */

        add     x21, sp, #UREGS_SPSR_fiq
        mrs     x22, SPSR_fiq
        mrs     x23, SPSR_irq
        stp     w22, w23, [x21]

        add     x21, sp, #UREGS_SPSR_und
        mrs     x22, SPSR_und
        mrs     x23, SPSR_abt
        stp     w22, w23, [x21]

        .endif

        .endm

        .macro  exit_guest, compat

        add     x21, sp, #UREGS_SPSR_el1
        ldr     x23, [x21]
        msr     SPSR_el1, x23

        .if \compat == 0 /* Aarch64 mode */

        add     x21, sp, #UREGS_SP_el0
        ldr     x22, [x21]
        msr     SP_el0, x22

        add     x21, sp, #UREGS_SP_el1
        ldp     x22, x23, [x21]
        msr     SP_el1, x22
        msr     ELR_el1, x23

        .else            /* Aarch32 mode */

        add     x21, sp, #UREGS_SPSR_fiq
        ldp     w22, w23, [x21]
        msr     SPSR_fiq, x22
        msr     SPSR_irq, x23

        add     x21, sp, #UREGS_SPSR_und
        ldp     w22, w23, [x21]
        msr     SPSR_und, x22
        msr     SPSR_abt, x23

        .endif

        .endm

/*
 * Clobber top 32 bits of gp registers when switching from AArch32
 */
        .macro clobber_gp_top_halves, compat, save_x0_x1

        .if \compat == 1      /* AArch32 mode */

        /*
         * At the moment, no-one is using save_x0_x1 == 0 with compat == 1.
         * So the code is not handling it to simplify the implementation.
         */
        .if \save_x0_x1 == 0
        .error "save_x0_x1 is 0 but compat is 1"
        .endif

        .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
        mov w\n, w\n
        .endr

        .endif

        .endm

/*
 * Save state on entry to hypervisor, restore on exit
 *
 * save_x0_x1: Does the macro needs to save x0/x1? Defaults to 1
 * If 0, we rely on the on x0/x1 to have been saved at the correct
 * position on the stack before.
 */
        .macro  entry, hyp, compat, save_x0_x1=1

        /*
         * Ensure any PAR_EL1 reads complete, in case we were interrupted
         * between the PAR_EL1 read and the memory barrier for the erratum
         * 1508412 workaround.
         */
        alternative_if ARM64_WORKAROUND_1508412
        dmb sy
        alternative_else_nop_endif

        sub     sp, sp, #(UREGS_SPSR_el1 - UREGS_LR) /* CPSR, PC, SP, LR */

        .if \hyp == 0         /* Guest mode */
        clobber_gp_top_halves compat=\compat, save_x0_x1=\save_x0_x1
        .endif

        push    x28, x29
        push    x26, x27
        push    x24, x25
        push    x22, x23
        push    x20, x21
        push    x18, x19
        push    x16, x17
        push    x14, x15
        push    x12, x13
        push    x10, x11
        push    x8, x9
        push    x6, x7
        push    x4, x5
        push    x2, x3
        /*
         * The caller may already have saved x0/x1 on the stack at the
         * correct address and corrupt them with another value. Only
         * save them if save_x0_x1 == 1.
         */
        .if \save_x0_x1 == 1
        push    x0, x1
        .else
        sub     sp, sp, #16
        .endif

        .if \hyp == 1        /* Hypervisor mode */

        add     x21, sp, #UREGS_kernel_sizeof

        .else                /* Guest mode */

        entry_guest \compat
        mov     x21, ~0 /* sp only valid for hyp frame XXX */

        .endif

        stp     lr, x21, [sp, #UREGS_LR]

        mrs     x21, elr_el2
        str     x21, [sp, #UREGS_PC]

        add     x21, sp, #UREGS_CPSR
        mrs     x22, spsr_el2
        mrs     x23, esr_el2
        stp     x22, x23, [x21]

        .endm

        .macro  exit, hyp, compat

        .if \hyp == 0         /* Guest mode */

        bl      leave_hypervisor_to_guest /* Mask IRQ on return */

        exit_guest \compat

        .endif

        b       return_from_trap

        .endm

        /*
         * Generate a guest vector.
         *
         * iflags: Correspond to the list of interrupts to unmask
         * save_x0_x1: See the description on top of the macro 'entry'
         */
        .macro  guest_vector compat, iflags, trap, save_x0_x1=1
        entry   hyp=0, compat=\compat, save_x0_x1=\save_x0_x1
        /*
         * We may have entered the hypervisor with pending SErrors
         * generated by the guest. If we need to categorize them, then
         * we need to check any outstanding SErrors will be consumed.
         *
         * The function check_pending_guest_serror() will unmask SError
         * exception temporarily. This is fine to do before enter_*
         * helpers are called because we fully control the state of the
         * processor and only limited code willl be executed (see
         * do_trap_hyp_serror()).
         *
         * When a SError has been consumed (x19 != 0), we may have injected a
         * virtual SError to the guest.
         *
         * In this case, the initial exception will be discarded (PC has
         * been adjusted by inject_vabt_exception()). However, we still
         * want to give an opportunity to reschedule the vCPU. So we
         * only want to skip the handling of the initial exception (i.e.
         * do_trap_*()).
         *
         * TODO: The SErrors path should be reworked to inject the vSError in
         * enter_hypervisor_* rather than do_trap_hyp_serror. This should make
         * easier to understand the path.
         */
        alternative_if_not SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
        bl      check_pending_guest_serror
        alternative_else_nop_endif

        bl      enter_hypervisor_from_guest_preirq
        msr     daifclr, \iflags
        bl      enter_hypervisor_from_guest

        /*
         * CBNZ can only address an offset of +/- 1MB. This means, it is
         * not possible to jump outside of an alternative because
         * the .text section and .altinstr_replacement may be further
         * apart. The easiest way is to duplicate the few instructions
         * that need to be skipped.
         */
        alternative_if_not SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
        cbnz      x19, 1f
        mov       x0, sp
        bl        do_trap_\trap
1:
        alternative_else
        nop
        mov       x0, sp
        bl        do_trap_\trap
        alternative_endif

        exit    hyp=0, compat=\compat
        .endm


/*
 * Bad Abort numbers
 *-----------------
 */
#define BAD_SYNC        0
#define BAD_IRQ         1
#define BAD_FIQ         2
#define BAD_ERROR       3

        .macro  invalid, reason
        mov     x0, sp
        mov     x1, #\reason
        b       do_bad_mode
        .endm

FUNC_LOCAL(hyp_sync_invalid)
        entry   hyp=1
        invalid BAD_SYNC
END(hyp_sync_invalid)

FUNC_LOCAL(hyp_irq_invalid)
        entry   hyp=1
        invalid BAD_IRQ
END(hyp_irq_invalid)

FUNC_LOCAL(hyp_fiq_invalid)
        entry   hyp=1
        invalid BAD_FIQ
END(hyp_fiq_invalid)

FUNC_LOCAL(hyp_error_invalid)
        entry   hyp=1
        invalid BAD_ERROR
END(hyp_error_invalid)

/*
 * SError received while running in the hypervisor mode.
 *
 * Technically, we could unmask the IRQ if it were unmasked in the
 * interrupted context. However, this require to check the PSTATE. For
 * simplicity, as SError should be rare and potentially fatal,
 * all interrupts are kept masked.
 */
FUNC_LOCAL(hyp_error)
        entry   hyp=1
        mov     x0, sp
        bl      do_trap_hyp_serror
        exit    hyp=1
END(hyp_error)

/*
 * Synchronous exception received while running in the hypervisor mode.
 *
 * While the exception could be executed with all the interrupts (e.g.
 * IRQ) unmasked, the interrupted context may have purposefully masked
 * some of them. So we want to inherit the state from the interrupted
 * context.
 */
FUNC_LOCAL(hyp_sync)
        entry   hyp=1

        /* Inherit interrupts */
        mrs     x0, SPSR_el2
        and     x0, x0, #(PSR_DBG_MASK | PSR_ABT_MASK | PSR_IRQ_MASK | PSR_FIQ_MASK)
        msr     daif, x0

        mov     x0, sp
        bl      do_trap_hyp_sync
        exit    hyp=1
END(hyp_sync)

/*
 * IRQ received while running in the hypervisor mode.
 *
 * While the exception could be executed with all the interrupts but IRQ
 * unmasked, the interrupted context may have purposefully masked some
 * of them. So we want to inherit the state from the interrupt context
 * and keep IRQ masked.
 *
 * XXX: We may want to consider an ordering between interrupts (e.g. if
 * SError are masked, then IRQ should be masked too). However, this
 * would require some rework in some paths (e.g. panic, livepatch) to
 * ensure the ordering is enforced everywhere.
 */
FUNC_LOCAL(hyp_irq)
        entry   hyp=1

        /* Inherit D, A, F interrupts and keep I masked */
        mrs     x0, SPSR_el2
        mov     x1, #(PSR_DBG_MASK | PSR_ABT_MASK | PSR_FIQ_MASK)
        and     x0, x0, x1
        orr     x0, x0, #PSR_IRQ_MASK
        msr     daif, x0

        mov     x0, sp
        bl      do_trap_irq
        exit    hyp=1
END(hyp_irq)

FUNC_LOCAL(guest_sync)
        /*
         * Save x0, x1 in advance
         */
        stp     x0, x1, [sp, #-(UREGS_kernel_sizeof - UREGS_X0)]

        /*
         * x1 is used because x0 may contain the function identifier.
         * This avoids to restore x0 from the stack.
         */
        mrs     x1, esr_el2
        lsr     x1, x1, #HSR_EC_SHIFT           /* x1 = ESR_EL2.EC */
        cmp     x1, #HSR_EC_HVC64
        b.ne    guest_sync_slowpath             /* Not a HVC skip fastpath. */

        mrs     x1, esr_el2
        and     x1, x1, #0xffff                 /* Check the immediate [0:16] */
        cbnz    x1, guest_sync_slowpath         /* should be 0 for HVC #0 */

        /*
         * Fastest path possible for ARM_SMCCC_ARCH_WORKAROUND_1 and
         * ARM_SMCCC_ARCH_WORKAROUND_3.
         * The workaround needed has already been applied on the exception
         * entry from the guest, so let's quickly get back to the guest.
         *
         * Note that eor is used because the function identifier cannot
         * be encoded as an immediate for cmp.
         */
        eor     w0, w0, #ARM_SMCCC_ARCH_WORKAROUND_1_FID
        cbz     w0, fastpath_out_workaround

        /* ARM_SMCCC_ARCH_WORKAROUND_2 handling */
        eor     w0, w0, #(ARM_SMCCC_ARCH_WORKAROUND_1_FID ^ ARM_SMCCC_ARCH_WORKAROUND_2_FID)
        cbz     w0, wa2_ssbd

        /* Fastpath out for ARM_SMCCC_ARCH_WORKAROUND_3 */
        eor     w0, w0, #(ARM_SMCCC_ARCH_WORKAROUND_2_FID ^ ARM_SMCCC_ARCH_WORKAROUND_3_FID)
        cbnz    w0, guest_sync_slowpath

fastpath_out_workaround:
        /*
         * Clobber both x0 and x1 to prevent leakage. Note that thanks
         * the eor, x0 = 0.
         */
        mov     x1, xzr
        eret
        sb
END(guest_sync)

FUNC_LOCAL(wa2_ssbd)
#ifdef CONFIG_ARM_SSBD
alternative_cb arm_enable_wa2_handling
        b       wa2_end
alternative_cb_end
        /* Sanitize the argument */
        mov     x0, #-(UREGS_kernel_sizeof - UREGS_X1)  /* x0 := offset of guest's x1 on the stack */
        ldr     x1, [sp, x0]                            /* Load guest's x1 */
        cmp     w1, wzr
        cset    x1, ne

        /*
         * Update the guest flag. At this stage sp point after the field
         * guest_cpu_user_regs in cpu_info.
         */
        adr_cpu_info x2
        ldr     x0, [x2, #CPUINFO_flags]
        bfi     x0, x1, #CPUINFO_WORKAROUND_2_FLAG_SHIFT, #1
        str     x0, [x2, #CPUINFO_flags]

        /* Check that we actually need to perform the call */
        ldr_this_cpu x0, ssbd_callback_required, x2
        cbz     x0, wa2_end

        mov     w0, #ARM_SMCCC_ARCH_WORKAROUND_2_FID
        smc     #0

wa2_end:
        /* Don't leak data from the SMC call */
        mov     x1, xzr
        mov     x2, xzr
        mov     x3, xzr
#endif /* !CONFIG_ARM_SSBD */
        mov     x0, xzr
        eret
        sb
END(wa2_ssbd)

FUNC_LOCAL(guest_sync_slowpath)
        /*
         * x0/x1 may have been scratch by the fast path above, so avoid
         * to save them.
         */
        guest_vector compat=0, iflags=IFLAGS__AI_, trap=guest_sync, save_x0_x1=0
END(guest_sync_slowpath)

FUNC_LOCAL(guest_irq)
        guest_vector compat=0, iflags=IFLAGS__A__, trap=irq
END(guest_irq)

FUNC_LOCAL(guest_fiq_invalid)
        entry   hyp=0, compat=0
        invalid BAD_FIQ
END(guest_fiq_invalid)

FUNC_LOCAL(guest_error)
        guest_vector compat=0, iflags=IFLAGS__AI_, trap=guest_serror
END(guest_error)

FUNC_LOCAL(guest_sync_compat)
        guest_vector compat=1, iflags=IFLAGS__AI_, trap=guest_sync
END(guest_sync_compat)

FUNC_LOCAL(guest_irq_compat)
        guest_vector compat=1, iflags=IFLAGS__A__, trap=irq
END(guest_irq_compat)

FUNC_LOCAL(guest_fiq_invalid_compat)
        entry   hyp=0, compat=1
        invalid BAD_FIQ
END(guest_fiq_invalid_compat)

FUNC_LOCAL(guest_error_compat)
        guest_vector compat=1, iflags=IFLAGS__AI_, trap=guest_serror
END(guest_error_compat)

FUNC(return_to_new_vcpu32)
        exit    hyp=0, compat=1
END(return_to_new_vcpu32)

FUNC(return_to_new_vcpu64)
        exit    hyp=0, compat=0
END(return_to_new_vcpu64)

FUNC_LOCAL(return_from_trap)
        msr     daifset, #IFLAGS___I_ /* Mask interrupts */

        ldr     x21, [sp, #UREGS_PC]            /* load ELR */
        ldr     x22, [sp, #UREGS_CPSR]          /* load SPSR */

        pop     x0, x1
        pop     x2, x3
        pop     x4, x5
        pop     x6, x7
        pop     x8, x9

        msr     elr_el2, x21                    /* set up the return data */
        msr     spsr_el2, x22

        pop     x10, x11
        pop     x12, x13
        pop     x14, x15
        pop     x16, x17
        pop     x18, x19
        pop     x20, x21
        pop     x22, x23
        pop     x24, x25
        pop     x26, x27
        pop     x28, x29

        ldr     lr, [sp], #(UREGS_SPSR_el1 - UREGS_LR) /* CPSR, PC, SP, LR */

        /*
         * Ensure any device/NC reads complete, in case we were interrupted
         * between the memory barrier for the erratum 1508412 workaround and
         * any PAR_EL1 read.
         */
        alternative_if ARM64_WORKAROUND_1508412
        dmb sy
        alternative_else_nop_endif

        eret
        sb
END(return_from_trap)

/*
 * Consume pending SError generated by the guest if any.
 *
 * @return:
 *  x19: Set to a non-zero value if a pending Abort exception took place.
 *       Otherwise, it will be set to zero.
 *
 * Without RAS extension, the only way to consume a SError is to unmask
 * it. So the function will unmask SError exception for a small window and
 * then mask it again.
 */
FUNC_LOCAL(check_pending_guest_serror)
        /*
         * Save elr_el2 to check whether the pending SError exception takes
         * place while we are doing this sync exception.
         */
        mrs     x0, elr_el2

        /* Synchronize against in-flight ld/st */
        dsb     sy

        /*
         * Unmask PSTATE asynchronous abort bit. If there is a pending
         * SError, the EL2 error exception will happen after PSTATE.A
         * is cleared.
         */
        msr     daifclr, #IFLAGS__A__

        /*
         * This is our single instruction exception window. A pending
         * SError is guaranteed to occur at the earliest when we unmask
         * it, and at the latest just after the ISB.
         *
         * If a pending SError occurs, the program will jump to EL2 error
         * exception handler, and the elr_el2 will be set to
         * abort_guest_exit_start or abort_guest_exit_end.
         */
LABEL(abort_guest_exit_start)

        isb

LABEL(abort_guest_exit_end)
        /* Mask PSTATE asynchronous abort bit, close the checking window. */
        msr     daifset, #IFLAGS__A__

        /*
         * Compare elr_el2 and the saved value to check whether we are
         * returning from a valid exception caused by pending SError.
         */
        mrs     x1, elr_el2
        cmp     x0, x1

        /*
         * Not equal, the pending SError exception took place, set
         * x19 to non-zero.
         */
        cset    x19, ne

        ret
END(check_pending_guest_serror)

/*
 * Exception vectors.
 */
        .macro  ventry  label
        .align  7
        b       \label
        .endm

        .align  11
FUNC(hyp_traps_vector)
        ventry  hyp_sync_invalid            /* Synchronous EL2t */
        ventry  hyp_irq_invalid             /* IRQ EL2t */
        ventry  hyp_fiq_invalid             /* FIQ EL2t */
        ventry  hyp_error_invalid           /* Error EL2t */

        ventry  hyp_sync                    /* Synchronous EL2h */
        ventry  hyp_irq                     /* IRQ EL2h */
        ventry  hyp_fiq_invalid             /* FIQ EL2h */
        ventry  hyp_error                   /* Error EL2h */

        ventry  guest_sync                  /* Synchronous 64-bit EL0/EL1 */
        ventry  guest_irq                   /* IRQ 64-bit EL0/EL1 */
        ventry  guest_fiq_invalid           /* FIQ 64-bit EL0/EL1 */
        ventry  guest_error                 /* Error 64-bit EL0/EL1 */

        ventry  guest_sync_compat           /* Synchronous 32-bit EL0/EL1 */
        ventry  guest_irq_compat            /* IRQ 32-bit EL0/EL1 */
        ventry  guest_fiq_invalid_compat    /* FIQ 32-bit EL0/EL1 */
        ventry  guest_error_compat          /* Error 32-bit EL0/EL1 */
END(hyp_traps_vector)

/*
 * struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next)
 *
 * x0 - prev
 * x1 - next
 *
 * Returns prev in x0
 */
FUNC(__context_switch)
        add     x8, x0, #VCPU_arch_saved_context
        mov     x9, sp
        stp     x19, x20, [x8], #16         /* store callee-saved registers */
        stp     x21, x22, [x8], #16
        stp     x23, x24, [x8], #16
        stp     x25, x26, [x8], #16
        stp     x27, x28, [x8], #16
        stp     x29, x9, [x8], #16
        str     lr, [x8]

        add     x8, x1, #VCPU_arch_saved_context
        ldp     x19, x20, [x8], #16         /* restore callee-saved registers */
        ldp     x21, x22, [x8], #16
        ldp     x23, x24, [x8], #16
        ldp     x25, x26, [x8], #16
        ldp     x27, x28, [x8], #16
        ldp     x29, x9, [x8], #16
        ldr     lr, [x8]
        mov     sp, x9
        ret
END(__context_switch)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
