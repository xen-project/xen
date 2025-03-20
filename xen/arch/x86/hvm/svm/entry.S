/*
 * entry.S: SVM architecture-specific entry/exit handling.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

        .file "svm/entry.S"

#include <xen/lib.h>

#include <asm/asm_defns.h>
#include <asm/page.h>

FUNC(svm_asm_do_resume)
        GET_CURRENT(bx)
.Lsvm_do_resume:
        call svm_intr_assist
        call nsvm_vcpu_switch
        ASSERT_NOT_IN_ATOMIC

        mov  VCPU_processor(%rbx),%eax
        lea  irq_stat+IRQSTAT_softirq_pending(%rip),%rdx
        xor  %ecx,%ecx
        shl  $IRQSTAT_shift,%eax
        cli
        cmp  %ecx,(%rdx,%rax,1)
        jne  .Lsvm_process_softirqs

        cmp  %cl,VCPU_nsvm_hap_enabled(%rbx)
UNLIKELY_START(ne, nsvm_hap)
        cmp  %rcx,VCPU_nhvm_p2m(%rbx)
        sete %al
        test VCPU_nhvm_guestmode(%rbx),%al
        UNLIKELY_DONE(z, nsvm_hap)
        /*
         * Someone shot down our nested p2m table; go round again
         * and nsvm_vcpu_switch() will fix it for us.
         */
        sti
        jmp  .Lsvm_do_resume
__UNLIKELY_END(nsvm_hap)

        call svm_vmenter_helper

        clgi

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        /* SPEC_CTRL_EXIT_TO_SVM       Req: b=curr %rsp=regs/cpuinfo, Clob: acd */
        .macro svm_vmentry_spec_ctrl
            mov    VCPU_arch_msrs(%rbx), %rax
            mov    CPUINFO_last_spec_ctrl(%rsp), %edx
            mov    VCPUMSR_spec_ctrl_raw(%rax), %eax
            cmp    %edx, %eax
            je     1f /* Skip write if value is correct. */
            mov    $MSR_SPEC_CTRL, %ecx
            xor    %edx, %edx
            wrmsr
            mov    %eax, CPUINFO_last_spec_ctrl(%rsp)
1:          /* No Spectre v1 concerns.  Execution will hit VMRUN imminently. */
        .endm
        ALTERNATIVE "", svm_vmentry_spec_ctrl, X86_FEATURE_SC_MSR_HVM
        ALTERNATIVE "", DO_SPEC_CTRL_DIV, X86_FEATURE_SC_DIV

        /*
         * Set EFLAGS.IF after CLGI covers us from real interrupts, but not
         * immediately prior to VMRUN.  The VMRUN instruction leaks it's
         * INTR_SHADOW into guest state if a VMExit occurs before VMRUN
         * completes (e.g. taking #NPF during event injecting.)
         */
        sti

        pop  %r15
        pop  %r14
        pop  %r13
        pop  %r12
        pop  %rbp
        mov  VCPU_svm_vmcb_pa(%rbx),%rax
        pop  %rbx
        pop  %r11
        pop  %r10
        pop  %r9
        pop  %r8
        pop  %rcx /* Skip %rax: restored by VMRUN. */
        pop  %rcx
        pop  %rdx
        pop  %rsi
        pop  %rdi

        vmrun

        SAVE_ALL

        GET_CURRENT(bx)

        /* SPEC_CTRL_ENTRY_FROM_SVM    Req: %rsp=regs/cpuinfo, %rdx=0 Clob: acd */

        /*
         * IBPB is to mitigate BTC/SRSO on AMD/Hygon parts, in particular
         * making type-confused RETs safe to use.  This is not needed on Zen5
         * and later parts when SRSO_MSR_FIX (BP-SPEC-REDUCE) is in use.
         */
        .macro svm_vmexit_cond_ibpb
            testb  $SCF_entry_ibpb, CPUINFO_scf(%rsp)
            jz     .L_skip_ibpb

            mov    $MSR_PRED_CMD, %ecx
            mov    $PRED_CMD_IBPB, %eax
            wrmsr
.L_skip_ibpb:
	.endm
        ALTERNATIVE "", svm_vmexit_cond_ibpb, X86_FEATURE_IBPB_ENTRY_HVM

        /*
         * RSB (RAS/RAP) stuffing is to prevents RET predictions following guest
         * entries.  This is not needed on Zen4 and later, when AutoIBRS is in
         * use.
         */
        ALTERNATIVE "", DO_OVERWRITE_RSB, X86_FEATURE_SC_RSB_HVM

        /*
         * Restore Xen's MSR_SPEC_CTRL setting, making indirect CALLs/JMPs
         * safe to use.  The guest's setting resides in the VMCB.
         */
        .macro svm_vmexit_spec_ctrl
            mov    CPUINFO_xen_spec_ctrl(%rsp), %eax
            mov    CPUINFO_last_spec_ctrl(%rsp), %edx
            cmp    %edx, %eax
            je     1f /* Skip write if value is correct. */
            mov    $MSR_SPEC_CTRL, %ecx
            xor    %edx, %edx
            wrmsr
            mov    %eax, CPUINFO_last_spec_ctrl(%rsp)
1:
        .endm
        ALTERNATIVE "", svm_vmexit_spec_ctrl, X86_FEATURE_SC_MSR_HVM
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        /*
         * STGI is executed unconditionally, and is sufficiently serialising
         * to safely resolve any Spectre-v1 concerns in the above logic.
         */
        stgi
LABEL(svm_stgi_label, 0)
        call svm_vmexit_handler
        jmp  .Lsvm_do_resume

.Lsvm_process_softirqs:
        sti
        call do_softirq
        jmp  .Lsvm_do_resume
END(svm_asm_do_resume)
