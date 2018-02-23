#include <asm/asm_defns.h>
#include <asm/regs.h>
#include <asm/alternative.h>
#include <asm/smccc.h>
#include <public/xen.h>

/*
 * Register aliases.
 */
lr      .req    x30             /* link register */

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
 * Save state on entry to hypervisor, restore on exit
 *
 * save_x0_x1: Does the macro needs to save x0/x1? Defaults to 1
 * If 0, we rely on the on x0/x1 to have been saved at the correct
 * position on the stack before.
 */
        .macro  entry, hyp, compat, save_x0_x1=1
        sub     sp, sp, #(UREGS_SPSR_el1 - UREGS_LR) /* CPSR, PC, SP, LR */
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
        stp     w22, w23, [x21]

        .endm

        .macro  exit, hyp, compat

        .if \hyp == 0         /* Guest mode */

        bl      leave_hypervisor_tail /* Disables interrupts on return */

        exit_guest \compat

        .endif

        b       return_from_trap

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

hyp_sync_invalid:
        entry   hyp=1
        invalid BAD_SYNC

hyp_irq_invalid:
        entry   hyp=1
        invalid BAD_IRQ

hyp_fiq_invalid:
        entry   hyp=1
        invalid BAD_FIQ

hyp_error_invalid:
        entry   hyp=1
        invalid BAD_ERROR

hyp_error:
        entry   hyp=1
        msr     daifclr, #2
        mov     x0, sp
        bl      do_trap_hyp_serror
        exit    hyp=1

/* Traps taken in Current EL with SP_ELx */
hyp_sync:
        entry   hyp=1
        msr     daifclr, #6
        mov     x0, sp
        bl      do_trap_hyp_sync
        exit    hyp=1

hyp_irq:
        entry   hyp=1
        msr     daifclr, #4
        mov     x0, sp
        bl      do_trap_irq
        exit    hyp=1

guest_sync:
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
        b.ne    1f                              /* Not a HVC skip fastpath. */

        mrs     x1, esr_el2
        and     x1, x1, #0xffff                 /* Check the immediate [0:16] */
        cbnz    x1, 1f                          /* should be 0 for HVC #0 */

        /*
         * Fastest path possible for ARM_SMCCC_ARCH_WORKAROUND_1.
         * The workaround has already been applied on the exception
         * entry from the guest, so let's quickly get back to the guest.
         *
         * Note that eor is used because the function identifier cannot
         * be encoded as an immediate for cmp.
         */
        eor     w0, w0, #ARM_SMCCC_ARCH_WORKAROUND_1_FID
        cbnz    w0, 1f

        /*
         * Clobber both x0 and x1 to prevent leakage. Note that thanks
         * the eor, x0 = 0.
         */
        mov     x1, xzr
        eret

1:
        /*
         * x0/x1 may have been scratch by the fast path above, so avoid
         * to save them.
         */
        entry   hyp=0, compat=0, save_x0_x1=0
        /*
         * The vSError will be checked while SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
         * is not set. If a vSError took place, the initial exception will be
         * skipped. Exit ASAP
         */
        ALTERNATIVE("bl check_pending_vserror; cbnz x0, 1f",
                    "nop; nop",
                    SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT)
        msr     daifclr, #6
        mov     x0, sp
        bl      do_trap_guest_sync
1:
        exit    hyp=0, compat=0

guest_irq:
        entry   hyp=0, compat=0
        /*
         * The vSError will be checked while SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
         * is not set. If a vSError took place, the initial exception will be
         * skipped. Exit ASAP
         */
        ALTERNATIVE("bl check_pending_vserror; cbnz x0, 1f",
                    "nop; nop",
                    SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT)
        msr     daifclr, #4
        mov     x0, sp
        bl      do_trap_irq
1:
        exit    hyp=0, compat=0

guest_fiq_invalid:
        entry   hyp=0, compat=0
        invalid BAD_FIQ

guest_error:
        entry   hyp=0, compat=0
        msr     daifclr, #6
        mov     x0, sp
        bl      do_trap_guest_serror
        exit    hyp=0, compat=0

guest_sync_compat:
        entry   hyp=0, compat=1
        /*
         * The vSError will be checked while SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
         * is not set. If a vSError took place, the initial exception will be
         * skipped. Exit ASAP
         */
        ALTERNATIVE("bl check_pending_vserror; cbnz x0, 1f",
                    "nop; nop",
                    SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT)
        msr     daifclr, #6
        mov     x0, sp
        bl      do_trap_guest_sync
1:
        exit    hyp=0, compat=1

guest_irq_compat:
        entry   hyp=0, compat=1
        /*
         * The vSError will be checked while SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
         * is not set. If a vSError took place, the initial exception will be
         * skipped. Exit ASAP
         */
        ALTERNATIVE("bl check_pending_vserror; cbnz x0, 1f",
                    "nop; nop",
                    SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT)
        msr     daifclr, #4
        mov     x0, sp
        bl      do_trap_irq
1:
        exit    hyp=0, compat=1

guest_fiq_invalid_compat:
        entry   hyp=0, compat=1
        invalid BAD_FIQ

guest_error_compat:
        entry   hyp=0, compat=1
        msr     daifclr, #6
        mov     x0, sp
        bl      do_trap_guest_serror
        exit    hyp=0, compat=1

ENTRY(return_to_new_vcpu32)
        exit    hyp=0, compat=1
ENTRY(return_to_new_vcpu64)
        exit    hyp=0, compat=0

return_from_trap:
        msr     daifset, #2 /* Mask interrupts */

        ldr     x21, [sp, #UREGS_PC]            /* load ELR */
        ldr     w22, [sp, #UREGS_CPSR]          /* load SPSR */

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

        eret

/*
 * This function is used to check pending virtual SError in the gap of
 * EL1 -> EL2 world switch.
 * The x0 register will be used to indicate the results of detection.
 * x0 -- Non-zero indicates a pending virtual SError took place.
 * x0 -- Zero indicates no pending virtual SError took place.
 */
check_pending_vserror:
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
        msr     daifclr, #4

        /*
         * This is our single instruction exception window. A pending
         * SError is guaranteed to occur at the earliest when we unmask
         * it, and at the latest just after the ISB.
         *
         * If a pending SError occurs, the program will jump to EL2 error
         * exception handler, and the elr_el2 will be set to
         * abort_guest_exit_start or abort_guest_exit_end.
         */
        .global abort_guest_exit_start
abort_guest_exit_start:

        isb

        .global abort_guest_exit_end
abort_guest_exit_end:
        /* Mask PSTATE asynchronous abort bit, close the checking window. */
        msr     daifset, #4

        /*
         * Compare elr_el2 and the saved value to check whether we are
         * returning from a valid exception caused by pending SError.
         */
        mrs     x1, elr_el2
        cmp     x0, x1

        /*
         * Not equal, the pending SError exception took place, set
         * x0 to non-zero.
         */
        cset    x0, ne

        ret

/*
 * Exception vectors.
 */
        .macro  ventry  label
        .align  7
        b       \label
        .endm

        .align  11
ENTRY(hyp_traps_vector)
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

/*
 * struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next)
 *
 * x0 - prev
 * x1 - next
 *
 * Returns prev in x0
 */
ENTRY(__context_switch)
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

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
