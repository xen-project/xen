/*
 * exits.S: VMX architecture-specific exit handling.
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

#define VMRESUME     .byte 0x0f,0x01,0xc3
#define VMLAUNCH     .byte 0x0f,0x01,0xc2
#define VMREAD(off)  .byte 0x0f,0x78,0x47,((off)-UREGS_rip)
#define VMWRITE(off) .byte 0x0f,0x79,0x47,((off)-UREGS_rip)

/* VMCS field encodings */
#define GUEST_RSP    0x681c
#define GUEST_RIP    0x681e
#define GUEST_RFLAGS 0x6820

#define GET_CURRENT(reg)         \
        movq $STACK_SIZE-8, reg; \
        orq  %rsp, reg;          \
        andq $~7,reg;            \
        movq (reg),reg;

#define HVM_SAVE_ALL_NOSEGREGS                  \
        pushq %rdi;                             \
        pushq %rsi;                             \
        pushq %rdx;                             \
        pushq %rcx;                             \
        pushq %rax;                             \
        pushq %r8;                              \
        pushq %r9;                              \
        pushq %r10;                             \
        pushq %r11;                             \
        pushq %rbx;                             \
        pushq %rbp;                             \
        pushq %r12;                             \
        pushq %r13;                             \
        pushq %r14;                             \
        pushq %r15;

#define HVM_RESTORE_ALL_NOSEGREGS               \
        popq %r15;                              \
        popq %r14;                              \
        popq %r13;                              \
        popq %r12;                              \
        popq %rbp;                              \
        popq %rbx;                              \
        popq %r11;                              \
        popq %r10;                              \
        popq %r9;                               \
        popq %r8;                               \
        popq %rax;                              \
        popq %rcx;                              \
        popq %rdx;                              \
        popq %rsi;                              \
        popq %rdi

        ALIGN
ENTRY(vmx_asm_vmexit_handler)
        HVM_SAVE_ALL_NOSEGREGS

        leaq UREGS_rip(%rsp),%rdi
        movl $GUEST_RIP,%eax
        /*VMREAD(UREGS_rip)*/
        .byte 0x0f,0x78,0x07  /* vmread %rax,(%rdi) */
        movl $GUEST_RSP,%eax
        VMREAD(UREGS_rsp)
        movl $GUEST_RFLAGS,%eax
        VMREAD(UREGS_eflags)

#ifndef NDEBUG
        movw $0xbeef,%ax
        movw %ax,UREGS_error_code(%rsp)
        movw %ax,UREGS_entry_vector(%rsp)
        movw %ax,UREGS_saved_upcall_mask(%rsp)
        movw %ax,UREGS_cs(%rsp)
        movw %ax,UREGS_ds(%rsp)
        movw %ax,UREGS_es(%rsp)
        movw %ax,UREGS_fs(%rsp)
        movw %ax,UREGS_gs(%rsp)
        movw %ax,UREGS_ss(%rsp)
#endif

        movq %rsp,%rdi
        call vmx_vmexit_handler
        jmp vmx_asm_do_vmentry

        ALIGN
vmx_process_softirqs:
        sti       
        call do_softirq
        jmp vmx_asm_do_vmentry

        ALIGN
ENTRY(vmx_asm_do_vmentry)
        GET_CURRENT(%rbx)
        cli                             # tests must not race interrupts

        movl  VCPU_processor(%rbx),%eax
        shl   $IRQSTAT_shift,%rax
        leaq  irq_stat(%rip),%rdx
        cmpl  $0,(%rdx,%rax,1)
        jnz   vmx_process_softirqs

        call vmx_intr_assist
        movq VCPU_hvm_guest_cr2(%rbx),%rax
        movq %rax,%cr2
        call vmx_trace_vmentry

        leaq UREGS_rip(%rsp),%rdi
        movl $GUEST_RIP,%eax
        /*VMWRITE(UREGS_rip)*/
        .byte 0x0f,0x79,0x07  /* vmwrite (%rdi),%rax */
        movl $GUEST_RSP,%eax
        VMWRITE(UREGS_rsp)
        movl $GUEST_RFLAGS,%eax
        VMWRITE(UREGS_eflags)

        testb $0xff,VCPU_vmx_emul(%rbx)
        jnz  vmx_goto_realmode

        cmpb $0,VCPU_vmx_launched(%rbx)
        je   vmx_launch

/*vmx_resume:*/
        HVM_RESTORE_ALL_NOSEGREGS
        VMRESUME
        pushfq
        call vm_resume_fail
        ud2

vmx_launch:
        movb $1,VCPU_vmx_launched(%rbx)
        HVM_RESTORE_ALL_NOSEGREGS
        VMLAUNCH
        pushfq
        call vm_launch_fail
        ud2

vmx_goto_realmode:
        sti
        movq %rsp,%rdi
        call vmx_realmode
        jmp vmx_asm_do_vmentry
