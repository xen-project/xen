/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * include/asm-x86/spec_ctrl.h
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */

#ifndef __X86_SPEC_CTRL_ASM_H__
#define __X86_SPEC_CTRL_ASM_H__

#ifdef __ASSEMBLY__
#include <asm/msr-index.h>
#include <asm/spec_ctrl.h>

/*
 * Saving and restoring MSR_SPEC_CTRL state is a little tricky.
 *
 * We want the guests choice of SPEC_CTRL while in guest context, and Xen's
 * choice (set or clear, depending on the hardware) while running in Xen
 * context.  Therefore, a simplistic algorithm is:
 *
 *  - Set/clear IBRS on entry to Xen
 *  - Set the guests' choice on exit to guest
 *  - Leave SPEC_CTRL unchanged on exit to xen
 *
 * There are two complicating factors:
 *  1) HVM guests can have direct access to the MSR, so it can change
 *     behind Xen's back.
 *  2) An NMI or MCE can interrupt at any point, including early in the entry
 *     path, or late in the exit path after restoring the guest value.  This
 *     will corrupt the guest value.
 *
 * Factor 1 is dealt with:
 *   - On VMX by using MSR load/save lists to have vmentry/exit atomically
 *     load/save the guest value.  Xen's value is loaded in regular code, and
 *     there is no need to use the shadow logic (below).
 *   - On SVM by altering MSR_SPEC_CTRL inside the CLGI/STGI region.  This
 *     makes the changes atomic with respect to NMIs/etc, so no need for
 *     shadowing logic.
 *
 * Factor 2 is harder.  We maintain a shadow_spec_ctrl value, and a use_shadow
 * boolean in the per cpu scf.  The synchronous use is:
 *
 *  1) Store guest value in shadow_spec_ctrl
 *  2) Set the use_shadow boolean
 *  3) Load guest value into MSR_SPEC_CTRL
 *  4) Exit to guest
 *  5) Entry from guest
 *  6) Clear the use_shadow boolean
 *  7) Load Xen's value into MSR_SPEC_CTRL
 *
 * The asynchronous use for interrupts/exceptions is:
 *  -  Set/clear IBRS on entry to Xen
 *  -  On exit to Xen, check use_shadow
 *  -  If set, load shadow_spec_ctrl
 *
 * Therefore, an interrupt/exception which hits the synchronous path between
 * steps 2 and 6 will restore the shadow value rather than leaving Xen's value
 * loaded and corrupting the value used in guest context.
 *
 * Additionally, in some cases it is safe to skip writes to MSR_SPEC_CTRL when
 * we don't require any of the side effects of an identical write.  Maintain a
 * per-cpu last_spec_ctrl value for this purpose.
 *
 * The following ASM fragments implement this algorithm.  See their local
 * comments for further details.
 *  - SPEC_CTRL_ENTRY_FROM_PV
 *  - SPEC_CTRL_ENTRY_FROM_INTR
 *  - SPEC_CTRL_ENTRY_FROM_INTR_IST
 *  - SPEC_CTRL_EXIT_TO_XEN
 *  - SPEC_CTRL_EXIT_TO_PV
 *
 * Additionally, the following grep-fodder exists to find the HVM logic.
 *  - SPEC_CTRL_ENTRY_FROM_{SVM,VMX}
 *  - SPEC_CTRL_EXIT_TO_{SVM,VMX}
 */

.macro DO_COND_IBPB
/*
 * Requires %rbx=SCF, %rdx=0
 * Clobbers %rax, %rcx
 *
 * Conditionally issue IBPB if SCF_entry_ibpb is active.
 */
    testb  $SCF_entry_ibpb, %bl
    jz     .L\@_skip

    mov     $MSR_PRED_CMD, %ecx
    mov     $PRED_CMD_IBPB, %eax
    wrmsr

.L\@_skip:
.endm

.macro DO_OVERWRITE_RSB tmp=rax, xu
/*
 * Requires nothing
 * Clobbers \tmp (%rax by default), %rcx
 *
 * xu is an optional parameter to add eXtra Uniqueness.  It is intended for
 * passing %= in from an asm() block, in order to work around
 * https://github.com/llvm/llvm-project/issues/60792 where Clang-IAS doesn't
 * expand \@ uniquely.
 *
 * Requires 256 bytes of {,shadow}stack space, but %rsp/SSP has no net
 * change. Based on Google's performance numbers, the loop is unrolled to 16
 * iterations and two calls per iteration.
 *
 * The call filling the RSB needs a nonzero displacement, and int3 halts
 * speculation.
 *
 * %rsp is preserved by using an extra GPR because a) we've got plenty spare,
 * b) the two movs are shorter to encode than `add $32*8, %rsp`, and c) can be
 * optimised with mov-elimination in modern cores.
 */
    mov $16, %ecx                   /* 16 iterations, two calls per loop */
    mov %rsp, %\tmp                 /* Store the current %rsp */

.L\@_fill_rsb_loop\xu:

    .irp n, 1, 2                    /* Unrolled twice. */
    call .L\@_insert_rsb_entry\xu\n /* Create an RSB entry. */
    int3                            /* Halt rogue speculation. */

.L\@_insert_rsb_entry\xu\n:
    .endr

    sub $1, %ecx
    jnz .L\@_fill_rsb_loop\xu
    mov %\tmp, %rsp                 /* Restore old %rsp */

#ifdef CONFIG_XEN_SHSTK
    mov $1, %ecx
    rdsspd %ecx
    cmp $1, %ecx
    je .L\@_shstk_done\xu
    mov $64, %ecx                   /* 64 * 4 bytes, given incsspd */
    incsspd %ecx                    /* Restore old SSP */
.L\@_shstk_done\xu:
#endif
.endm

/*
 * Helper to improve the readibility of stack dispacements with %rsp in
 * unusual positions.  Both @field and @top_of_stack should be constants from
 * the same object.  @top_of_stack should be where %rsp is currently pointing.
 */
#define STK_REL(field, top_of_stk) ((field) - (top_of_stk))

.macro SPEC_CTRL_COND_VERW \
    scf=STK_REL(CPUINFO_scf,      CPUINFO_error_code), \
    sel=STK_REL(CPUINFO_verw_sel, CPUINFO_error_code)
/*
 * Requires \scf and \sel as %rsp-relative expressions
 * Clobbers eflags
 *
 * VERW needs to run after guest GPRs have been restored, where only %rsp is
 * good to use.  Default to expecting %rsp pointing at CPUINFO_error_code.
 * Contexts where this is not true must provide an alternative \scf and \sel.
 *
 * Issue a VERW for its flushing side effect, if indicated.  This is a Spectre
 * v1 gadget, but the IRET/VMEntry is serialising.
 */
    testb $SCF_verw, \scf(%rsp)
    jz .L\@_verw_skip
    verw \sel(%rsp)
.L\@_verw_skip:
.endm

.macro DO_SPEC_CTRL_DIV
/*
 * Requires nothing
 * Clobbers %rax
 *
 * Issue a DIV for its flushing side effect (Zen1 uarch specific).  Any
 * non-faulting DIV will do; a byte DIV has least latency, and doesn't clobber
 * %rdx.
 */
    mov $1, %eax
    div %al
.endm

.macro DO_SPEC_CTRL_ENTRY maybexen:req
/*
 * Requires %rsp=regs (also cpuinfo if !maybexen)
 * Requires %r14=stack_end (if maybexen)
 * Clobbers %rax, %rcx, %rdx
 *
 * PV guests can't update MSR_SPEC_CTRL behind Xen's back, so no need to read
 * it back.  Entries from guest context need to clear SPEC_CTRL shadowing,
 * while entries from Xen must leave shadowing in its current state.
 */
    mov $MSR_SPEC_CTRL, %ecx
    xor %edx, %edx

    /*
     * Clear SPEC_CTRL shadowing *before* loading Xen's value.  If entering
     * from a possibly-xen context, %rsp doesn't necessarily alias the cpuinfo
     * block so calculate the position directly.
     */
    .if \maybexen
        xor %eax, %eax
        /* Branchless `if ( !xen ) clear_shadowing` */
        testb $3, UREGS_cs(%rsp)
        setnz %al
        not %eax
        and %al, STACK_CPUINFO_FIELD(scf)(%r14)
        mov STACK_CPUINFO_FIELD(xen_spec_ctrl)(%r14), %eax
    .else
        andb $~SCF_use_shadow, CPUINFO_scf(%rsp)
        mov  CPUINFO_xen_spec_ctrl(%rsp), %eax
    .endif

    wrmsr
.endm

.macro DO_SPEC_CTRL_EXIT_TO_GUEST
/*
 * Requires %eax=spec_ctrl, %rsp=regs/cpuinfo
 * Clobbers %rcx, %rdx
 *
 * When returning to guest context, set up SPEC_CTRL shadowing and load the
 * guest value.
 */
    /* Set up shadow value *before* enabling shadowing. */
    mov %eax, CPUINFO_shadow_spec_ctrl(%rsp)

    /* Set SPEC_CTRL shadowing *before* loading the guest value. */
    orb $SCF_use_shadow, CPUINFO_scf(%rsp)

    mov $MSR_SPEC_CTRL, %ecx
    xor %edx, %edx
    wrmsr
.endm

/*
 * Used after an entry from PV context: SYSCALL, SYSENTER, INT,
 * etc.  There is always a guest speculation state in context.
 */
.macro SPEC_CTRL_ENTRY_FROM_PV
/*
 * Requires %rsp=regs/cpuinfo, %r14=stack_end, %rdx=0
 * Clobbers %rax, %rbx, %rcx, %rdx
 */
    movzbl STACK_CPUINFO_FIELD(scf)(%r14), %ebx

    /*
     * For all safety notes, 32bit PV guest kernels run in Ring 1 and are
     * therefore supervisor (== Xen) in the architecture.  As a result, most
     * hardware isolation techniques do not work.
     */

    /*
     * IBPB is to mitigate BTC/SRSO on AMD/Hygon parts, in particular making
     * type-confused RETs safe to use.  This is not needed on Zen5 and later
     * parts when SRSO_U/S_NO is enumerated.
     */
    ALTERNATIVE "", DO_COND_IBPB, X86_FEATURE_IBPB_ENTRY_PV

    /*
     * RSB stuffing is to prevent RET predictions following guest entries.
     * This is not needed if SMEP is active and the RSB is full-width.
     */
    ALTERNATIVE "", DO_OVERWRITE_RSB, X86_FEATURE_SC_RSB_PV

    /*
     * Only used on Intel parts.  Restore Xen's MSR_SPEC_CTRL setting.  The
     * guest can't change it's value behind Xen's back.  For Legacy IBRS, this
     * flushes/inhibits indirect predictions and does not flush the RSB.  For
     * eIBRS, this prevents CALLs/JMPs using predictions learnt at a lower
     * predictor mode, and it flushes the RSB.
     */
    ALTERNATIVE "", __stringify(DO_SPEC_CTRL_ENTRY maybexen=0),         \
        X86_FEATURE_SC_MSR_PV

    /*
     * Clear the BHB to mitigate BHI.  Used on eIBRS parts, and uses RETs
     * itself so must be after we've perfomed all the RET-safety we can.
     */
    testb $SCF_entry_bhb, %bl
    jz .L\@_skip_bhb
    ALTERNATIVE_2 "",                                    \
        "call clear_bhb_loops", X86_SPEC_BHB_LOOPS,      \
        "call clear_bhb_tsx", X86_SPEC_BHB_TSX
.L\@_skip_bhb:

    ALTERNATIVE "lfence", "", X86_SPEC_NO_LFENCE_ENTRY_PV
.endm

/*
 * Used after an exception or maskable interrupt, hitting Xen or PV context.
 * There will either be a guest speculation context, or a well-formed Xen
 * speculation context, with the exception of one case.  IRET #GP handling may
 * have a guest choice of MSR_SPEC_CTRL.
 *
 * Therefore, we can skip the flush/barrier-like protections when hitting Xen,
 * but we must still run the mode-based protections.
 */
.macro SPEC_CTRL_ENTRY_FROM_INTR
/*
 * Requires %rsp=regs, %r14=stack_end, %rdx=0
 * Clobbers %rax, %rbx, %rcx, %rdx
 */
    movzbl STACK_CPUINFO_FIELD(scf)(%r14), %ebx

    /*
     * All safety notes the same as SPEC_CTRL_ENTRY_FROM_PV, although there is
     * a conditional jump skipping some actions when interrupting Xen.
     *
     * On Intel parts, the IRET #GP path ends up here with the guest's choice
     * of MSR_SPEC_CTRL.
     */

    testb $3, UREGS_cs(%rsp)
    jz .L\@_skip

    ALTERNATIVE "", DO_COND_IBPB, X86_FEATURE_IBPB_ENTRY_PV

    ALTERNATIVE "", DO_OVERWRITE_RSB, X86_FEATURE_SC_RSB_PV

.L\@_skip:
    ALTERNATIVE "", __stringify(DO_SPEC_CTRL_ENTRY maybexen=1),         \
        X86_FEATURE_SC_MSR_PV

    testb $SCF_entry_bhb, %bl
    jz .L\@_skip_bhb
    ALTERNATIVE_2 "",                                    \
        "call clear_bhb_loops", X86_SPEC_BHB_LOOPS,      \
        "call clear_bhb_tsx", X86_SPEC_BHB_TSX
.L\@_skip_bhb:

    ALTERNATIVE "lfence", "", X86_SPEC_NO_LFENCE_ENTRY_INTR
.endm

/*
 * Used when exiting from any entry context, back to PV context.  This
 * includes from an IST entry which moved onto the primary stack.
 */
.macro SPEC_CTRL_EXIT_TO_PV
/*
 * Requires %rax=spec_ctrl, %rsp=regs/info
 * Clobbers %rcx, %rdx
 */
    ALTERNATIVE "", DO_SPEC_CTRL_EXIT_TO_GUEST, X86_FEATURE_SC_MSR_PV

    ALTERNATIVE "", DO_SPEC_CTRL_DIV, X86_FEATURE_SC_DIV
.endm

/*
 * Used after an IST entry hitting Xen or PV context.  Special care is needed,
 * because when hitting Xen context, there may not be a well-formed
 * speculation context.  (i.e. it can hit in the middle of
 * SPEC_CTRL_{ENTRY,EXIT}_* regions.)
 *
 * An IST entry which hits PV context moves onto the primary stack and leaves
 * via SPEC_CTRL_EXIT_TO_PV, *not* SPEC_CTRL_EXIT_TO_XEN.
 */
.macro SPEC_CTRL_ENTRY_FROM_INTR_IST
/*
 * Requires %rsp=regs, %r14=stack_end, %rdx=0
 * Clobbers %rax, %rbx, %rcx, %rdx
 *
 * This is logical merge of:
 *    DO_COND_IBPB
 *    DO_OVERWRITE_RSB
 *    DO_SPEC_CTRL_ENTRY maybexen=1
 * but with conditionals rather than alternatives.
 */
    movzbl STACK_CPUINFO_FIELD(scf)(%r14), %ebx

    /*
     * For all safety notes, 32bit PV guest kernels run in Ring 1 and are
     * therefore supervisor (== Xen) in the architecture.  As a result, most
     * hardware isolation techniques do not work.
     */

    /*
     * IBPB is to mitigate BTC/SRSO on AMD/Hygon parts, in particular making
     * type-confused RETs safe to use.  This is not needed on Zen5 and later
     * parts when SRSO_U/S_NO is enumerated.  The SVM path takes care of
     * Host/Guest interactions prior to clearing GIF, and it's not used on the
     * VMX path.
     */
    test    $SCF_ist_ibpb, %bl
    jz      .L\@_skip_ibpb

    mov     $MSR_PRED_CMD, %ecx
    mov     $PRED_CMD_IBPB, %eax
    wrmsr

.L\@_skip_ibpb:

    /*
     * RSB stuffing is to prevent RET predictions following guest entries.
     * SCF_ist_rsb is active if either PV or HVM protections are needed.  The
     * VMX path cannot guarantee to make the RSB safe ahead of taking an IST
     * vector.
     */
    test $SCF_ist_rsb, %bl
    jz .L\@_skip_rsb

    DO_OVERWRITE_RSB         /* Clobbers %rax/%rcx */

.L\@_skip_rsb:

    /*
     * Only used on Intel parts.  Restore Xen's MSR_SPEC_CTRL setting.  PV
     * guests can't change their value behind Xen's back.  HVM guests have
     * their value stored in the MSR load/save list.  For Legacy IBRS, this
     * flushes/inhibits indirect predictions and does not flush the RSB.  For
     * eIBRS, this prevents CALLs/JMPs using predictions learnt at a lower
     * predictor mode, and it flushes the RSB.  On eIBRS parts that also
     * suffer from PBRSB, the prior RSB stuffing suffices to make the RSB
     * safe.
     */
    test $SCF_ist_sc_msr, %bl
    jz .L\@_skip_msr_spec_ctrl

    xor %eax, %eax
    testb $3, UREGS_cs(%rsp)
    setnz %al
    not %eax
    and %al, STACK_CPUINFO_FIELD(scf)(%r14)

    /* Load Xen's intended value. */
    mov $MSR_SPEC_CTRL, %ecx
    mov STACK_CPUINFO_FIELD(xen_spec_ctrl)(%r14), %eax
    wrmsr

.L\@_skip_msr_spec_ctrl:

    /*
     * Clear the BHB to mitigate BHI.  Used on eIBRS parts, and uses RETs
     * itself so must be after we've perfomed all the RET-safety we can.
     */
    testb $SCF_entry_bhb, %bl
    jz .L\@_skip_bhb

    ALTERNATIVE_2 "",                                    \
        "call clear_bhb_loops", X86_SPEC_BHB_LOOPS,      \
        "call clear_bhb_tsx", X86_SPEC_BHB_TSX
.L\@_skip_bhb:

    lfence
.endm

/*
 * Use when exiting from any entry context, back to Xen context.  This
 * includes returning to other SPEC_CTRL_{ENTRY,EXIT}_* regions with an
 * incomplete speculation context.
 *
 * Because we might have interrupted Xen beyond SPEC_CTRL_EXIT_TO_$GUEST, we
 * need to treat this as if it were an EXIT_TO_$GUEST case too.
 */
.macro SPEC_CTRL_EXIT_TO_XEN
/*
 * Requires %r12=ist_exit, %r14=stack_end, %rsp=regs
 * Clobbers %rax, %rbx, %rcx, %rdx
 */
    movzbl STACK_CPUINFO_FIELD(scf)(%r14), %ebx

    testb $SCF_ist_sc_msr, %bl
    jz .L\@_skip_sc_msr

    /*
     * When returning to Xen context, look to see whether SPEC_CTRL shadowing
     * is in effect, and reload the shadow value.  This covers race conditions
     * which exist with an NMI/MCE/etc hitting late in the return-to-guest
     * path.
     */
    xor %edx, %edx

    testb $SCF_use_shadow, %bl
    jz .L\@_skip_sc_msr

    mov STACK_CPUINFO_FIELD(shadow_spec_ctrl)(%r14), %eax
    mov $MSR_SPEC_CTRL, %ecx
    wrmsr

.L\@_skip_sc_msr:

    test %r12, %r12
    jz .L\@_skip_ist_exit

    /*
     * Stash SCF and verw_sel above eflags in the case of an IST_exit.  The
     * VERW logic needs to run after guest GPRs have been restored; i.e. where
     * we cannot use %r12 or %r14 for the purposes they have here.
     *
     * When the CPU pushed this exception frame, it zero-extended eflags.
     * Therefore it is safe for the VERW logic to look at the stashed SCF
     * outside of the ist_exit condition.  Also, this stashing won't influence
     * any other restore_all_guest() paths.
     */
    or $(__HYPERVISOR_DS32 << 16), %ebx
    mov %ebx, UREGS_eflags + 4(%rsp) /* EFRAME_shadow_scf/sel */

    ALTERNATIVE "", DO_SPEC_CTRL_DIV, X86_FEATURE_SC_DIV

.L\@_skip_ist_exit:
.endm

#endif /* __ASSEMBLY__ */
#endif /* !__X86_SPEC_CTRL_ASM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
