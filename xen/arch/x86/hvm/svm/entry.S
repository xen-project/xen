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

#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/types.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>

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
        CLGI
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
        STGI
        jmp  .Lsvm_do_resume
__UNLIKELY_END(nsvm_hap)

        call svm_asid_handle_vmrun

        cmpb $0,tb_init_done(%rip)
UNLIKELY_START(nz, svm_trace)
        call svm_trace_vmentry
UNLIKELY_END(svm_trace)

        mov  VCPU_svm_vmcb(%rbx),%rcx
        mov  UREGS_rax(%rsp),%rax
        mov  %rax,VMCB_rax(%rcx)
        mov  UREGS_rip(%rsp),%rax
        mov  %rax,VMCB_rip(%rcx)
        mov  UREGS_rsp(%rsp),%rax
        mov  %rax,VMCB_rsp(%rcx)
        mov  UREGS_eflags(%rsp),%rax
        or   $X86_EFLAGS_MBS,%rax
        mov  %rax,VMCB_rflags(%rcx)

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
        add  $8,%rsp /* Skip %rax: restored by VMRUN. */
        pop  %rcx
        pop  %rdx
        pop  %rsi
        pop  %rdi

        VMRUN

        GET_CURRENT(ax)
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        mov  VCPU_svm_vmcb(%rax),%rcx
        push %rax
        push %r8
        push %r9
        push %r10
        push %r11
        push %rbx
        mov  %rax,%rbx
        push %rbp
        push %r12
        push %r13
        push %r14
        push %r15

        movb $0,VCPU_svm_vmcb_in_sync(%rbx)
        mov  VMCB_rax(%rcx),%rax
        mov  %rax,UREGS_rax(%rsp)
        mov  VMCB_rip(%rcx),%rax
        mov  %rax,UREGS_rip(%rsp)
        mov  VMCB_rsp(%rcx),%rax
        mov  %rax,UREGS_rsp(%rsp)
        mov  VMCB_rflags(%rcx),%rax
        mov  %rax,UREGS_eflags(%rsp)

        STGI
GLOBAL(svm_stgi_label)
        mov  %rsp,%rdi
        call svm_vmexit_handler
        jmp  .Lsvm_do_resume

.Lsvm_process_softirqs:
        STGI
        call do_softirq
        jmp  .Lsvm_do_resume
