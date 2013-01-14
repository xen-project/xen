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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/types.h>
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

        ALIGN
.globl vmx_asm_vmexit_handler
vmx_asm_vmexit_handler:
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %rax
        push %r8
        push %r9
        push %r10
        push %r11
        push %rbx
        push %rbp
        push %r12
        push %r13
        push %r14
        push %r15

        GET_CURRENT(%rbx)

        movb $1,VCPU_vmx_launched(%rbx)

        lea  UREGS_rip(%rsp),%rdi
        mov  $GUEST_RIP,%eax
        /*VMREAD(UREGS_rip)*/
        .byte 0x0f,0x78,0x07  /* vmread %rax,(%rdi) */
        mov  $GUEST_RSP,%eax
        VMREAD(UREGS_rsp)
        mov  $GUEST_RFLAGS,%eax
        VMREAD(UREGS_eflags)

        mov  %cr2,%rax
        mov  %rax,VCPU_hvm_guest_cr2(%rbx)

#ifndef NDEBUG
        mov  $0xbeef,%ax
        mov  %ax,UREGS_error_code(%rsp)
        mov  %ax,UREGS_entry_vector(%rsp)
        mov  %ax,UREGS_saved_upcall_mask(%rsp)
        mov  %ax,UREGS_cs(%rsp)
        mov  %ax,UREGS_ds(%rsp)
        mov  %ax,UREGS_es(%rsp)
        mov  %ax,UREGS_fs(%rsp)
        mov  %ax,UREGS_gs(%rsp)
        mov  %ax,UREGS_ss(%rsp)
#endif

        mov  %rsp,%rdi
        call vmx_vmexit_handler

.globl vmx_asm_do_vmentry
vmx_asm_do_vmentry:
        call vmx_intr_assist
        call nvmx_switch_guest
        ASSERT_NOT_IN_ATOMIC

        GET_CURRENT(%rbx)
        cli

        mov  VCPU_processor(%rbx),%eax
        shl  $IRQSTAT_shift,%rax
        lea  irq_stat(%rip),%rdx
        cmpl $0,(%rdx,%rax,1)
        jnz  .Lvmx_process_softirqs

        testb $0xff,VCPU_vmx_emulate(%rbx)
        jnz .Lvmx_goto_emulator
        testb $0xff,VCPU_vmx_realmode(%rbx)
UNLIKELY_START(nz, realmode)
        cmpw $0,VCPU_vm86_seg_mask(%rbx)
        jnz .Lvmx_goto_emulator
        mov  %rsp,%rdi
        call vmx_enter_realmode
UNLIKELY_END(realmode)

        call vmx_vmenter_helper
        mov  VCPU_hvm_guest_cr2(%rbx),%rax
        mov  %rax,%cr2

        lea  UREGS_rip(%rsp),%rdi
        mov  $GUEST_RIP,%eax
        /*VMWRITE(UREGS_rip)*/
        .byte 0x0f,0x79,0x07  /* vmwrite (%rdi),%rax */
        mov  $GUEST_RSP,%eax
        VMWRITE(UREGS_rsp)
        mov  $GUEST_RFLAGS,%eax
        VMWRITE(UREGS_eflags)

        cmpb $0,VCPU_vmx_launched(%rbx)
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
        je   .Lvmx_launch

/*.Lvmx_resume:*/
        VMRESUME
        sti
        call vm_resume_fail
        ud2

.Lvmx_launch:
        VMLAUNCH
        sti
        call vm_launch_fail
        ud2

.Lvmx_goto_emulator:
        sti
        mov  %rsp,%rdi
        call vmx_realmode
        jmp  vmx_asm_do_vmentry

.Lvmx_process_softirqs:
        sti
        call do_softirq
        jmp  vmx_asm_do_vmentry
