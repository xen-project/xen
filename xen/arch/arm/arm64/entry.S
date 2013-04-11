#include <xen/config.h>
#include <asm/asm_defns.h>
#include <asm/regs.h>
#include <public/xen.h>

/*
 * Register aliases.
 */
lr      .req    x30             // link register

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
        mrs     x23, SPSR_EL1
        str     x23, [x21]

        .if \compat == 0 /* Aarch64 mode */

        add     x21, sp, #UREGS_SP_el0
        mrs     x22, SP_el0
        str     x22, [x21]

        add     x21, sp, #UREGS_ELR_el1
        mrs     x22, SP_el1
        mrs     x23, ELR_el1
        stp     x22, x23, [x21]

        .else             /* Aarch32 mode */

        add     x21, sp, #UREGS_SPSR_fiq
        mrs     x22, spsr_fiq
        mrs     x23, spsr_irq
        stp     w22, w23, [x21]

        add     x21, sp, #UREGS_SPSR_und
        mrs     x22, spsr_und
        mrs     x23, spsr_abt
        stp     w22, w23, [x21]

        .endif

        .endm

/*
 * Save state on entry to hypervisor
 */
        .macro  entry, hyp, compat
        sub     sp, sp, #(UREGS_SPSR_el1 - UREGS_SP)
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
        push    x0, x1

        .if \hyp == 1        /* Hypervisor mode */

        add     x21, sp, #(UREGS_X0 - UREGS_SP)

        .else                /* Guest mode */

        entry_guest \compat
        mov     x21, ~0 /* sp only valid for hyp frame XXX */

        .endif

        stp     lr, x21, [sp, #UREGS_LR]

        mrs     x22, elr_el2
        mrs     x23, spsr_el2
        stp     x22, x23, [sp, #UREGS_PC]

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

/* Traps taken in Current EL with SP_ELx */
hyp_sync:
        entry   hyp=1
        msr     daifclr, #2
        mov     x0, sp
        bl      do_trap_hypervisor
        b       return_to_hypervisor

hyp_irq:
        entry   hyp=1
        mov     x0, sp
        bl      do_trap_irq
        b       return_to_hypervisor

guest_sync:
        entry   hyp=0, compat=0
        invalid BAD_SYNC /* No AArch64 guest support yet */

guest_irq:
        entry   hyp=0, compat=0
        invalid BAD_IRQ /* No AArch64 guest support yet */

guest_fiq_invalid:
        entry   hyp=0, compat=0
        invalid BAD_FIQ

guest_error_invalid:
        entry   hyp=0, compat=0
        invalid BAD_ERROR

guest_sync_compat:
        entry   hyp=0, compat=1
        msr     daifclr, #2
        mov     x0, sp
        bl      do_trap_hypervisor
        b       return_to_guest

guest_irq_compat:
        entry   hyp=0, compat=1
        mov     x0, sp
        bl      do_trap_irq
        b       return_to_guest

guest_fiq_invalid_compat:
        entry   hyp=0, compat=1
        invalid BAD_FIQ

guest_error_invalid_compat:
        entry   hyp=0, compat=1
        invalid BAD_ERROR

ENTRY(return_to_new_vcpu)
        ldr     x21, [sp, #UREGS_CPSR]
        and     x21, x21, #PSR_MODE_MASK
        /* Returning to EL2? */
        cmp     x21, #PSR_MODE_EL2t
        ccmp    x21, #PSR_MODE_EL2h, #0x4, ne
        b.eq    return_to_hypervisor /* Yes */
        /* Fall thru */
ENTRY(return_to_guest)
        bl      leave_hypervisor_tail /* Disables interrupts on return */
        /* Fall thru */
ENTRY(return_to_hypervisor)
        msr     daifset, #2 /* Mask interrupts */

        ldp     x21, x22, [sp, #UREGS_PC]       // load ELR, SPSR

        pop     x0, x1
        pop     x2, x3
        pop     x4, x5
        pop     x6, x7
        pop     x8, x9

        msr     elr_el2, x21                    // set up the return data
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

        ldr     lr, [sp], #(UREGS_SPSR_el1 - UREGS_SP)
        eret

/*
 * Exception vectors.
 */
        .macro  ventry  label
        .align  7
        b       \label
        .endm

        .align  11
ENTRY(hyp_traps_vector)
        ventry  hyp_sync_invalid                // Synchronous EL2t
        ventry  hyp_irq_invalid                 // IRQ EL2t
        ventry  hyp_fiq_invalid                 // FIQ EL2t
        ventry  hyp_error_invalid               // Error EL2t

        ventry  hyp_sync                        // Synchronous EL2h
        ventry  hyp_irq                         // IRQ EL2h
        ventry  hyp_fiq_invalid                 // FIQ EL2h
        ventry  hyp_error_invalid               // Error EL2h

        ventry  guest_sync                      // Synchronous 64-bit EL0/EL1
        ventry  guest_irq                       // IRQ 64-bit EL0/EL1
        ventry  guest_fiq_invalid               // FIQ 64-bit EL0/EL1
        ventry  guest_error_invalid             // Error 64-bit EL0/EL1

        ventry  guest_sync_compat               // Synchronous 32-bit EL0/EL1
        ventry  guest_irq_compat                // IRQ 32-bit EL0/EL1
        ventry  guest_fiq_invalid_compat        // FIQ 32-bit EL0/EL1
        ventry  guest_error_invalid_compat      // Error 32-bit EL0/EL1

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
        stp     x19, x20, [x8], #16             // store callee-saved registers
        stp     x21, x22, [x8], #16
        stp     x23, x24, [x8], #16
        stp     x25, x26, [x8], #16
        stp     x27, x28, [x8], #16
        stp     x29, x9, [x8], #16
        str     lr, [x8]

        add     x8, x1, #VCPU_arch_saved_context
        ldp     x19, x20, [x8], #16             // restore callee-saved registers
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
