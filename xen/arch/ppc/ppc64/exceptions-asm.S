/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/asm-defns.h>
#include <asm/processor.h>

    .section .text.exceptions, "ax", %progbits

    /* Helper to dump CPU state to struct cpu_user_regs pointed to by r1. */
FUNC(exception_common)
    /*
     * Save GPRs 1-31. TODO: The value of %r1 has already been modified by the
     * ISR, so the value we save isn't the exact value we had on entry.
     */
    SAVE_GPRS(1, 31, %r1)

    /* Save LR, CTR, CR */
    mflr    %r0
    std     %r0, UREGS_lr(%r1)
    mfctr   %r0
    std     %r0, UREGS_ctr(%r1)
    mfcr    %r0
    stw     %r0, UREGS_cr(%r1) /* 32-bit */

    /* Save Exception Registers */
    mfsrr0  %r0
    std     %r0, UREGS_pc(%r1)
    mfsrr1  %r0
    std     %r0, UREGS_msr(%r1)
    mfdsisr %r0
    stw     %r0, UREGS_dsisr(%r1) /* 32-bit */
    mfdar   %r0
    std     %r0, UREGS_dar(%r1)
    li      %r0, -1 /* OS's SRR0/SRR1 have been clobbered */
    std     %r0, UREGS_srr0(%r1)
    std     %r0, UREGS_srr1(%r1)

    /* Setup TOC and a stack frame then call C exception handler */
    mr      %r3, %r1
    bcl     20, 31, 1f
1:  mflr    %r12
    addis   %r2, %r12, .TOC.-1b@ha
    addi    %r2, %r2, .TOC.-1b@l

    li      %r0, 0
    stdu    %r0, -STACK_FRAME_OVERHEAD(%r1)
    bl      exception_handler

    END(exception_common)

    /* Same as exception_common, but for exceptions that set HSRR{0,1} */
FUNC(h_exception_common)
    /*
     * Save GPRs 1-31. TODO: The value of %r1 has already been modified by the
     * ISR, so the value we save isn't the exact value we had on entry.
     */
    SAVE_GPRS(1, 31, %r1)

    /* Save LR, CTR, CR */
    mflr    %r0
    std     %r0, UREGS_lr(%r1)
    mfctr   %r0
    std     %r0, UREGS_ctr(%r1)
    mfcr    %r0
    stw     %r0, UREGS_cr(%r1) /* 32-bit */

    /* Save Exception Registers */
    mfhsrr0 %r0
    std     %r0, UREGS_pc(%r1)
    mfhsrr1 %r0
    std     %r0, UREGS_msr(%r1)
    mfsrr0  %r0
    std     %r0, UREGS_srr0(%r1)
    mfsrr1  %r0
    std     %r0, UREGS_srr1(%r1)
    mfdsisr %r0
    stw     %r0, UREGS_dsisr(%r1) /* 32-bit */
    mfdar   %r0
    std     %r0, UREGS_dar(%r1)

    /* Setup TOC and a stack frame then call C exception handler */
    mr      %r3, %r1
    bcl     20, 31, 1f
1:  mflr    %r12
    addis   %r2, %r12, .TOC.-1b@ha
    addi    %r2, %r2, .TOC.-1b@l

    li      %r0, 0
    stdu    %r0, -STACK_FRAME_OVERHEAD(%r1)
    bl      exception_handler

    END(h_exception_common)

/*
 * Declare an ISR for the provided exception that jumps to the specified handler
 */
.macro ISR name, exc, handler
    . = (AIL_VECTOR_BASE - EXCEPTION_VECTORS_START) + \exc
    FUNC(\name)
    /* TODO: switch stack */

    /* Reserve space for struct cpu_user_regs */
    subi    %r1, %r1, UREGS_sizeof

    /* Save r0 immediately so we can use it as scratch space */
    SAVE_GPR(0, %r1)

    /* Save exception vector number */
    li      %r0, \exc
    std     %r0, UREGS_entry_vector(%r1)

    /* Branch to common code */
    b       \handler

    END(\name)
.endm

/*
 * Define all ISRs. Note: These must be declared in order from lowest exception
 * vector to highest to satisfy the assembler.
 */
ISR exc_sysreset,   EXC_SYSTEM_RESET,   exception_common
ISR exc_mcheck,     EXC_MACHINE_CHECK,  exception_common
ISR exc_dstore,     EXC_DATA_STORAGE,   exception_common
ISR exc_dsegment,   EXC_DATA_SEGMENT,   exception_common
ISR exc_istore,     EXC_INSN_STORAGE,   exception_common
ISR exc_isegment,   EXC_INSN_SEGMENT,   exception_common
ISR exc_extern,     EXC_EXTERNAL,       exception_common
ISR exc_align,      EXC_ALIGNMENT,      exception_common
ISR exc_program,    EXC_PROGRAM,        exception_common
ISR exc_fpu,        EXC_FPU_UNAVAIL,    exception_common
ISR exc_dec,        EXC_DECREMENTER,    exception_common
ISR exc_h_dec,      EXC_H_DECREMENTER,  h_exception_common
/* EXC_PRIV_DOORBELL ... EXC_TRACE */
ISR exc_h_dstore,   EXC_H_DATA_STORAGE, h_exception_common
ISR exc_h_istore,   EXC_H_INSN_STORAGE, h_exception_common
