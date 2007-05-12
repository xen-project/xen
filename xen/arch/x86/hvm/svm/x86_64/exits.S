/*
 * exits.S: AMD-V architecture-specific exit handling.
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, AMD Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>

#define GET_CURRENT(reg)         \
        movq $STACK_SIZE-8,reg;  \
        orq  %rsp,reg;           \
        andq $~7,reg;            \
        movq (reg),reg;

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

ENTRY(svm_asm_do_resume)
        GET_CURRENT(%rbx)
        CLGI
        movl VCPU_processor(%rbx),%eax
        shl  $IRQSTAT_shift,%rax
        leaq irq_stat(%rip),%rdx
        testl $~0,(%rdx,%rax,1)
        jnz  svm_process_softirqs
        call svm_intr_assist
        call svm_load_cr2

        movq VCPU_svm_vmcb(%rbx),%rcx
        movq UREGS_rax(%rsp),%rax
        movq %rax,VMCB_rax(%rcx)

        movq VCPU_svm_vmcb_pa(%rbx),%rax
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        addq $8,%rsp /* Skip %rax: restored by VMRUN. */
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi

        VMRUN

        pushq %rdi
        pushq %rsi
        pushq %rdx
        pushq %rcx
        pushq %rax
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11
        pushq %rbx
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15

        GET_CURRENT(%rbx)
        movb $0,VCPU_svm_vmcb_in_sync(%rbx)
        movq VCPU_svm_vmcb(%rbx),%rcx
        movq VMCB_rax(%rcx),%rax
        movq %rax,UREGS_rax(%rsp)

        STGI
.globl svm_stgi_label;
svm_stgi_label:
        movq %rsp,%rdi
        call svm_vmexit_handler
        jmp  svm_asm_do_resume

        ALIGN
svm_process_softirqs:
        STGI
        call do_softirq
        jmp  svm_asm_do_resume
