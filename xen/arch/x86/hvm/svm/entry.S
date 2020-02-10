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

#include <asm/asm_defns.h>
#include <asm/page.h>

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

ENTRY(svm_asm_do_resume)
        GET_CURRENT(bx)
.Lsvm_do_resume:
        call svm_intr_assist
        mov  %rsp,%rdi
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

        mov  %rsp, %rdi
        call svm_vmenter_helper

        mov VCPU_arch_msrs(%rbx), %rax
        mov VCPUMSR_spec_ctrl_raw(%rax), %eax

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        SPEC_CTRL_EXIT_TO_HVM   /* Req: a=spec_ctrl %rsp=regs/cpuinfo, Clob: cd */

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

        CLGI
        sti
        VMRUN

        SAVE_ALL

        GET_CURRENT(bx)

        SPEC_CTRL_ENTRY_FROM_HVM    /* Req: b=curr %rsp=regs/cpuinfo, Clob: acd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        STGI
GLOBAL(svm_stgi_label)
        mov  %rsp,%rdi
        call svm_vmexit_handler
        jmp  .Lsvm_do_resume

.Lsvm_process_softirqs:
        sti
        call do_softirq
        jmp  .Lsvm_do_resume
