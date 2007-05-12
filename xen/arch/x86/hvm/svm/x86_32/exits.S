/*
 * exits.S: SVM architecture-specific exit handling.
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
        movl $STACK_SIZE-4,reg;  \
        orl  %esp,reg;           \
        andl $~3,reg;            \
        movl (reg),reg;

#define HVM_MONITOR_EFLAGS 0x202 /* IF on */
#define NR_SKIPPED_REGS    7     /* Skip SS thru EAX */
#define HVM_SAVE_ALL_NOSEGREGS                  \
        pushl $HVM_MONITOR_EFLAGS;              \
        popf;                                   \
        subl $(NR_SKIPPED_REGS*4),%esp;         \
        pushl %ebp;                             \
        pushl %edi;                             \
        pushl %esi;                             \
        pushl %edx;                             \
        pushl %ecx;                             \
        pushl %ebx;

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

ENTRY(svm_asm_do_resume)
        GET_CURRENT(%ebx)
        cli                             # tests must not race interrupts
        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        testl $~0,irq_stat(%eax,1)
        jnz  svm_process_softirqs
        call svm_intr_assist
        call svm_load_cr2

        CLGI                
        sti
        GET_CURRENT(%ebx)
        movl VCPU_svm_vmcb(%ebx),%ecx
        movl UREGS_eax(%esp),%eax
        movl %eax,VMCB_rax(%ecx)

        movl VCPU_svm_vmcb_pa(%ebx),%eax
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        addl $(NR_SKIPPED_REGS*4),%esp

        VMRUN

        HVM_SAVE_ALL_NOSEGREGS

        GET_CURRENT(%ebx)
        movb $0,VCPU_svm_vmcb_in_sync(%ebx)
        movl VCPU_svm_vmcb(%ebx),%ecx
        movl VMCB_rax(%ecx),%eax
        movl %eax,UREGS_eax(%esp)

        STGI
.globl svm_stgi_label;
svm_stgi_label:
        movl %esp,%eax
        push %eax
        call svm_vmexit_handler
        addl $4,%esp
        jmp  svm_asm_do_resume

        ALIGN
svm_process_softirqs:
        sti       
        call do_softirq
        jmp  svm_asm_do_resume
