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
#define VMREAD(off)  .byte 0x0f,0x78,0x44,0x24,off
#define VMWRITE(off) .byte 0x0f,0x79,0x44,0x24,off

/* VMCS field encodings */
#define GUEST_RSP    0x681c
#define GUEST_RIP    0x681e
#define GUEST_RFLAGS 0x6820

#define GET_CURRENT(reg)         \
        movl $STACK_SIZE-4, reg; \
        orl  %esp, reg;          \
        andl $~3,reg;            \
        movl (reg),reg;

#define HVM_SAVE_ALL_NOSEGREGS                                              \
        pushl %eax;                                                         \
        pushl %ebp;                                                         \
        pushl %edi;                                                         \
        pushl %esi;                                                         \
        pushl %edx;                                                         \
        pushl %ecx;                                                         \
        pushl %ebx;

#define HVM_RESTORE_ALL_NOSEGREGS               \
        popl %ebx;                              \
        popl %ecx;                              \
        popl %edx;                              \
        popl %esi;                              \
        popl %edi;                              \
        popl %ebp;                              \
        popl %eax

        ALIGN
ENTRY(vmx_asm_vmexit_handler)
        HVM_SAVE_ALL_NOSEGREGS

        movl $GUEST_RIP,%eax
        VMREAD(UREGS_eip)
        movl $GUEST_RSP,%eax
        VMREAD(UREGS_esp)
        movl $GUEST_RFLAGS,%eax
        VMREAD(UREGS_eflags)

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

        movl %esp,%eax
        push %eax
        call vmx_vmexit_handler
        addl $4,%esp
        jmp vmx_asm_do_vmentry

        ALIGN
vmx_process_softirqs:
        sti       
        call do_softirq
        jmp vmx_asm_do_vmentry

        ALIGN
ENTRY(vmx_asm_do_vmentry)
        GET_CURRENT(%ebx)
        cli                             # tests must not race interrupts

        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        cmpl $0,irq_stat(%eax,1)
        jnz  vmx_process_softirqs

        call vmx_intr_assist
        movl VCPU_hvm_guest_cr2(%ebx),%eax
        movl %eax,%cr2
        call vmx_trace_vmentry

        movl $GUEST_RIP,%eax
        VMWRITE(UREGS_eip)
        movl $GUEST_RSP,%eax
        VMWRITE(UREGS_esp)
        movl $GUEST_RFLAGS,%eax
        VMWRITE(UREGS_eflags)

        testb $0xff,VCPU_vmx_emul(%ebx)
        jnz  vmx_goto_realmode

        cmpb $0,VCPU_vmx_launched(%ebx)
        je   vmx_launch

/*vmx_resume:*/
        HVM_RESTORE_ALL_NOSEGREGS
        VMRESUME
        pushf
        call vm_resume_fail
        ud2

vmx_launch:
        movb $1,VCPU_vmx_launched(%ebx)
        HVM_RESTORE_ALL_NOSEGREGS
        VMLAUNCH
        pushf
        call vm_launch_fail
        ud2

vmx_goto_realmode:
        sti
        movl %esp,%eax
        push %eax
        call vmx_realmode
        addl $4,%esp
        jmp vmx_asm_do_vmentry
