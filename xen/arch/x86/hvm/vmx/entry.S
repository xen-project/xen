/*
 * entry.S: VMX architecture-specific entry/exit handling.
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

        .file "vmx/entry.S"

#include <asm/asm_defns.h>
#include <asm/page.h>

#define VMRESUME     .byte 0x0f,0x01,0xc3
#define VMLAUNCH     .byte 0x0f,0x01,0xc2

FUNC(vmx_asm_vmexit_handler)
        SAVE_ALL

        mov  %cr2,%rax
        GET_CURRENT(bx)

        movb $1,VCPU_vmx_launched(%rbx)
        mov  %rax,VCPU_hvm_guest_cr2(%rbx)

        /* SPEC_CTRL_ENTRY_FROM_VMX    Req: b=curr %rsp=regs/cpuinfo, Clob: acd */
        /*
         * RSB stuffing is to prevents RET predictions following guest
         * entries.  This is *not* sufficient to flush all RSB entries on
         * parts enumerating eIBRS, although the following restore_spec_ctrl
         * does covers us.
         */
        ALTERNATIVE "", DO_OVERWRITE_RSB, X86_FEATURE_SC_RSB_HVM

        /*
         * Restore Xen's MSR_SPEC_CTRL setting.  The guest's value resides in
         * the MSR load/save list.  For Legacy IBRS, this flushes/inhibits
         * indirect predictions and does not flush the RSB.  For eIBRS, this
         * prevents CALLs/JMPs using predictions learnt at a lower predictor
         * mode, and it flushes the RSB.  On eIBRS parts that also suffer from
         * PBRSB, the prior RSB stuffing suffices to make the RSB safe.
         */
        .macro restore_spec_ctrl
            mov    $MSR_SPEC_CTRL, %ecx
            mov    CPUINFO_xen_spec_ctrl(%rsp), %eax
            xor    %edx, %edx
            wrmsr
        .endm
        ALTERNATIVE "", restore_spec_ctrl, X86_FEATURE_SC_MSR_HVM

        /*
         * Clear the BHB to mitigate BHI.  Used on eIBRS parts, and uses RETs
         * itself so must be after we've perfomed all the RET-safety we can.
         */
        testb $SCF_entry_bhb, CPUINFO_scf(%rsp)
        jz .L_skip_bhb
        ALTERNATIVE_2 "",                                    \
            "call clear_bhb_loops", X86_SPEC_BHB_LOOPS,      \
            "call clear_bhb_tsx", X86_SPEC_BHB_TSX
.L_skip_bhb:

        ALTERNATIVE "lfence", "", X86_SPEC_NO_LFENCE_ENTRY_VMX
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        /* Hardware clears MSR_DEBUGCTL on VMExit.  Reinstate it if debugging Xen. */
        .macro restore_lbr
            mov $IA32_DEBUGCTLMSR_LBR, %eax
            mov $MSR_IA32_DEBUGCTLMSR, %ecx
            xor %edx, %edx
            wrmsr
        .endm
        ALTERNATIVE "", restore_lbr, X86_FEATURE_XEN_LBR

        mov  %rsp,%rdi
        call vmx_vmexit_handler

.Lvmx_do_vmentry:
        call vmx_intr_assist
        call nvmx_switch_guest
        ASSERT_NOT_IN_ATOMIC

        mov  VCPU_processor(%rbx),%eax
        lea  irq_stat+IRQSTAT_softirq_pending(%rip),%rdx
        xor  %ecx,%ecx
        shl  $IRQSTAT_shift,%eax
        cli
        cmp  %ecx,(%rdx,%rax,1)
        jnz  .Lvmx_process_softirqs

        cmp  %cl,VCPU_vmx_emulate(%rbx)
        jne .Lvmx_goto_emulator
        cmp  %cl,VCPU_vmx_realmode(%rbx)
UNLIKELY_START(ne, realmode)
        cmp  %cx,VCPU_vm86_seg_mask(%rbx)
        jnz .Lvmx_goto_emulator
        mov  %rsp,%rdi
        call vmx_enter_realmode
UNLIKELY_END(realmode)

        mov  %rsp,%rdi
        call vmx_vmenter_helper
        test %al, %al
        jz .Lvmx_vmentry_restart

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        /* SPEC_CTRL_EXIT_TO_VMX   Req: %rsp=regs/cpuinfo              Clob:    */
        /*
         * All speculation safety work happens to be elsewhere.  VERW is after
         * popping the GPRs, while restoring the guest MSR_SPEC_CTRL is left
         * to the MSR load list.
         */

        mov  VCPU_hvm_guest_cr2(%rbx),%rax
        mov  %rax, %cr2

        /*
         * We need to perform two conditional actions (VERW, and Resume vs
         * Launch) after popping GPRs.  With some cunning, we can encode both
         * of these in eflags together.
         *
         * Parity is only calculated over the bottom byte of the answer, while
         * Sign is simply the top bit.
         *
         * Therefore, the final OR instruction ends up producing:
         *   SF = VCPU_vmx_launched
         *   PF = !SCF_verw
         */
        BUILD_BUG_ON(SCF_verw & ~0xff)
        movzbl VCPU_vmx_launched(%rbx), %ecx
        shl  $31, %ecx
        movzbl CPUINFO_scf(%rsp), %eax
        and  $SCF_verw, %eax
        or   %eax, %ecx

        pop  %r15
        pop  %r14
        pop  %r13
        pop  %r12
        pop  %rbp
        pop  %rbx
        pop  %r11
        pop  %r10
        pop  %r9
        pop  %r8
        pop  %rax
        pop  %rcx
        pop  %rdx
        pop  %rsi
        pop  %rdi

        jpe  .L_skip_verw
        /* VERW clobbers ZF, but preserves all others, including SF. */
        verw STK_REL(CPUINFO_verw_sel, CPUINFO_error_code)(%rsp)
.L_skip_verw:

        jns  .Lvmx_launch

/*.Lvmx_resume:*/
        VMRESUME
        jmp  .Lvmx_vmentry_fail

.Lvmx_launch:
        VMLAUNCH

.Lvmx_vmentry_fail:
        sti
        SAVE_ALL

        /*
         * SPEC_CTRL_ENTRY notes
         *
         * If we end up here, no guest code has executed.  The MSR lists have
         * not been processed, so we still have Xen's choice of MSR_SPEC_CTRL
         * in context, and the RSB is unchanged.
         */

        call vmx_vmentry_failure
        jmp  .Lvmx_process_softirqs

LABEL(vmx_asm_do_vmentry)
        GET_CURRENT(bx)
        jmp  .Lvmx_do_vmentry

.Lvmx_vmentry_restart:
        sti
        jmp  .Lvmx_do_vmentry

.Lvmx_goto_emulator:
        sti
        mov  %rsp,%rdi
        call vmx_realmode
        jmp  .Lvmx_do_vmentry

.Lvmx_process_softirqs:
        sti
        call do_softirq
        jmp  .Lvmx_do_vmentry
END(vmx_asm_vmexit_handler)
