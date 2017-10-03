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

#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/types.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>

#define VMRESUME     .byte 0x0f,0x01,0xc3
#define VMLAUNCH     .byte 0x0f,0x01,0xc2

ENTRY(vmx_asm_vmexit_handler)
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %rax
        mov  %cr2,%rax
        push %r8
        push %r9
        push %r10
        push %r11
        push %rbx
        GET_CURRENT(bx)
        push %rbp
        push %r12
        push %r13
        push %r14
        push %r15

        movb $1,VCPU_vmx_launched(%rbx)
        mov  %rax,VCPU_hvm_guest_cr2(%rbx)

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
        mov  VCPU_hvm_guest_cr2(%rbx),%rax

        pop  %r15
        pop  %r14
        pop  %r13
        pop  %r12
        pop  %rbp
        mov  %rax,%cr2
        cmpb $0,VCPU_vmx_launched(%rbx)
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
        jmp  .Lvmx_vmentry_fail

.Lvmx_launch:
        VMLAUNCH

.Lvmx_vmentry_fail:
        sti
        SAVE_ALL
        call vmx_vmentry_failure
        BUG  /* vmx_vmentry_failure() shouldn't return. */

ENTRY(vmx_asm_do_vmentry)
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
