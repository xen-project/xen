/*
 * exits.S: SVM architecture-specific exit handling.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
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

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

ENTRY(svm_asm_do_resume)
        GET_CURRENT(%ebx)
        CLGI

        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        testl $~0,irq_stat(%eax,1)
        jnz  svm_process_softirqs

        call svm_asid_handle_vmrun
        call svm_intr_assist

        /* Check if the trace buffer is initialized. 
         * Because the below condition is unlikely, we jump out of line
         * instead of having a mostly taken branch over the unlikely code.
         */
        cmpb $0,tb_init_done
        jnz  svm_trace
svm_trace_done:

        movl VCPU_svm_vmcb(%ebx),%ecx
        movl UREGS_eax(%esp),%eax
        movl %eax,VMCB_rax(%ecx)
        movl UREGS_eip(%esp),%eax
        movl %eax,VMCB_rip(%ecx)
        movl UREGS_esp(%esp),%eax
        movl %eax,VMCB_rsp(%ecx)
        movl UREGS_eflags(%esp),%eax
        movl %eax,VMCB_rflags(%ecx)

        movl VCPU_svm_vmcb_pa(%ebx),%eax
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp

        VMRUN

        pushl %ebp
        pushl %edi
        pushl %esi
        pushl %edx
        pushl %ecx
        pushl %ebx

        GET_CURRENT(%ebx)
        movb $0,VCPU_svm_vmcb_in_sync(%ebx)
        movl VCPU_svm_vmcb(%ebx),%ecx
        movl VMCB_rax(%ecx),%eax
        movl %eax,UREGS_eax(%esp)
        movl VMCB_rip(%ecx),%eax
        movl %eax,UREGS_eip(%esp)
        movl VMCB_rsp(%ecx),%eax
        movl %eax,UREGS_esp(%esp)
        movl VMCB_rflags(%ecx),%eax
        movl %eax,UREGS_eflags(%esp)

#ifndef NDEBUG
        movw $0xbeef,%ax
        movw %ax,UREGS_error_code(%esp)
        movw %ax,UREGS_entry_vector(%esp)
        movw %ax,UREGS_saved_upcall_mask(%esp)
        movw %ax,UREGS_cs(%esp)
        movw %ax,UREGS_ds(%esp)
        movw %ax,UREGS_es(%esp)
        movw %ax,UREGS_fs(%esp)
        movw %ax,UREGS_gs(%esp)
        movw %ax,UREGS_ss(%esp)
#endif

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
        STGI
        call do_softirq
        jmp  svm_asm_do_resume

svm_trace:
        /* Call out to C, as this is not speed critical path
         * Note: svm_trace_vmentry will recheck the tb_init_done,
         * but this is on the slow path, so who cares 
         */
        call svm_trace_vmentry
        jmp  svm_trace_done
