/******************************************************************************
 * include/asm-x86/spec_ctrl.h
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
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */

#ifndef __X86_SPEC_CTRL_ASM_H__
#define __X86_SPEC_CTRL_ASM_H__

#ifdef __ASSEMBLY__
#include <asm/msr-index.h>

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
 * Factor 1 is dealt with by relying on NMIs/MCEs being blocked immediately
 * after VMEXIT.  The VMEXIT-specific code reads MSR_SPEC_CTRL and updates
 * current before loading Xen's MSR_SPEC_CTRL setting.
 *
 * Factor 2 is harder.  We maintain a shadow_spec_ctrl value, and
 * use_shadow_spec_ctrl boolean per cpu.  The synchronous use is:
 *
 *  1) Store guest value in shadow_spec_ctrl
 *  2) Set use_shadow_spec_ctrl boolean
 *  3) Load guest value into MSR_SPEC_CTRL
 *  4) Exit to guest
 *  5) Entry from guest
 *  6) Clear use_shadow_spec_ctrl boolean
 *  7) Load Xen's value into MSR_SPEC_CTRL
 *
 * The asynchronous use for interrupts/exceptions is:
 *  -  Set/clear IBRS on entry to Xen
 *  -  On exit to Xen, check use_shadow_spec_ctrl
 *  -  If set, load shadow_spec_ctrl
 *
 * Therefore, an interrupt/exception which hits the synchronous path between
 * steps 2 and 6 will restore the shadow value rather than leaving Xen's value
 * loaded and corrupting the value used in guest context.
 *
 * The following ASM fragments implement this algorithm.  See their local
 * comments for further details.
 *  - SPEC_CTRL_ENTRY_FROM_VMEXIT
 *  - SPEC_CTRL_ENTRY_FROM_PV
 *  - SPEC_CTRL_ENTRY_FROM_INTR
 *  - SPEC_CTRL_EXIT_TO_XEN
 *  - SPEC_CTRL_EXIT_TO_GUEST
 */

.macro DO_SPEC_CTRL_ENTRY_FROM_VMEXIT ibrs_val:req
/*
 * Requires %rbx=current, %rsp=regs/cpuinfo
 * Clobbers %rax, %rcx, %rdx
 *
 * The common case is that a guest has direct access to MSR_SPEC_CTRL, at
 * which point we need to save the guest value before setting IBRS for Xen.
 * Unilaterally saving the guest value is shorter and faster than checking.
 */
    mov $MSR_SPEC_CTRL, %ecx
    rdmsr

    /* Stash the value from hardware. */
    mov %eax, VCPU_arch_spec_ctrl(%rbx)
    xor %edx, %edx

    /* Clear SPEC_CTRL shadowing *before* loading Xen's value. */
    movb %dl, CPUINFO_use_shadow_spec_ctrl(%rsp)

    /* Load Xen's intended value. */
    mov $\ibrs_val, %eax
    wrmsr
.endm

.macro DO_SPEC_CTRL_ENTRY maybexen:req ibrs_val:req
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
        /* Branchless `if ( !xen ) clear_shadowing` */
        testb $3, UREGS_cs(%rsp)
        setz %al
        and %al, STACK_CPUINFO_FIELD(use_shadow_spec_ctrl)(%r14)
    .else
        movb %dl, CPUINFO_use_shadow_spec_ctrl(%rsp)
    .endif

    /* Load Xen's intended value. */
    mov $\ibrs_val, %eax
    wrmsr
.endm

.macro DO_SPEC_CTRL_EXIT_TO_XEN
/*
 * Requires %rbx=stack_end
 * Clobbers %rax, %rcx, %rdx
 *
 * When returning to Xen context, look to see whether SPEC_CTRL shadowing is
 * in effect, and reload the shadow value.  This covers race conditions which
 * exist with an NMI/MCE/etc hitting late in the return-to-guest path.
 */
    xor %edx, %edx

    cmpb %dl, STACK_CPUINFO_FIELD(use_shadow_spec_ctrl)(%rbx)
    je .L\@_skip

    mov STACK_CPUINFO_FIELD(shadow_spec_ctrl)(%rbx), %eax
    mov $MSR_SPEC_CTRL, %ecx
    wrmsr

.L\@_skip:
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
    movb $1, CPUINFO_use_shadow_spec_ctrl(%rsp)

    mov $MSR_SPEC_CTRL, %ecx
    xor %edx, %edx
    wrmsr
.endm

/* Use after a VMEXIT from an HVM guest. */
#define SPEC_CTRL_ENTRY_FROM_VMEXIT                                     \
    ALTERNATIVE_2 __stringify(ASM_NOP32),                               \
        __stringify(DO_SPEC_CTRL_ENTRY_FROM_VMEXIT                      \
                    ibrs_val=SPEC_CTRL_IBRS),                           \
        X86_FEATURE_XEN_IBRS_SET,                                       \
        __stringify(DO_SPEC_CTRL_ENTRY_FROM_VMEXIT                      \
                    ibrs_val=0),                                        \
        X86_FEATURE_XEN_IBRS_CLEAR

/* Use after an entry from PV context (syscall/sysenter/int80/int82/etc). */
#define SPEC_CTRL_ENTRY_FROM_PV                                         \
    ALTERNATIVE_2 __stringify(ASM_NOP21),                               \
        __stringify(DO_SPEC_CTRL_ENTRY maybexen=0                       \
                    ibrs_val=SPEC_CTRL_IBRS),                           \
        X86_FEATURE_XEN_IBRS_SET,                                       \
        __stringify(DO_SPEC_CTRL_ENTRY maybexen=0 ibrs_val=0),          \
        X86_FEATURE_XEN_IBRS_CLEAR

/* Use in interrupt/exception context.  May interrupt Xen or PV context. */
#define SPEC_CTRL_ENTRY_FROM_INTR                                       \
    ALTERNATIVE_2 __stringify(ASM_NOP29),                               \
        __stringify(DO_SPEC_CTRL_ENTRY maybexen=1                       \
                    ibrs_val=SPEC_CTRL_IBRS),                           \
        X86_FEATURE_XEN_IBRS_SET,                                       \
        __stringify(DO_SPEC_CTRL_ENTRY maybexen=1 ibrs_val=0),          \
        X86_FEATURE_XEN_IBRS_CLEAR

/* Use when exiting to Xen context. */
#define SPEC_CTRL_EXIT_TO_XEN                                           \
    ALTERNATIVE_2 __stringify(ASM_NOP17),                               \
        DO_SPEC_CTRL_EXIT_TO_XEN, X86_FEATURE_XEN_IBRS_SET,             \
        DO_SPEC_CTRL_EXIT_TO_XEN, X86_FEATURE_XEN_IBRS_CLEAR

/* Use when exiting to guest context. */
#define SPEC_CTRL_EXIT_TO_GUEST                                         \
    ALTERNATIVE_2 __stringify(ASM_NOP24),                               \
        DO_SPEC_CTRL_EXIT_TO_GUEST, X86_FEATURE_XEN_IBRS_SET,           \
        DO_SPEC_CTRL_EXIT_TO_GUEST, X86_FEATURE_XEN_IBRS_CLEAR

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
