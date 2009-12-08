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

#define get_current(reg)                        \
        mov $STACK_SIZE-BYTES_PER_LONG, r(reg); \
        or  r(sp), r(reg);                      \
        and $~(BYTES_PER_LONG-1),r(reg);        \
        mov (r(reg)),r(reg);

#if defined(__x86_64__)
#define r(reg) %r##reg
#define addr_of(lbl) lbl(%rip)
#define call_with_regs(fn)                      \
        mov  %rsp,%rdi;                         \
        call fn;
#else /* defined(__i386__) */
#define r(reg) %e##reg
#define addr_of(lbl) lbl
#define UREGS_rip UREGS_eip
#define UREGS_rsp UREGS_esp
#define call_with_regs(fn)                      \
        mov  %esp,%eax;                         \
        push %eax;                              \
        call fn;                                \
        add  $4,%esp;
#endif

        ALIGN
.globl vmx_asm_vmexit_handler
vmx_asm_vmexit_handler:
#if defined(__x86_64__)
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
#else /* defined(__i386__) */
        push %eax
        push %ebp
        push %edi
        push %esi
        push %edx
        push %ecx
        push %ebx
#endif

        get_current(bx)

        movb $1,VCPU_vmx_launched(r(bx))

        lea  UREGS_rip(r(sp)),r(di)
        mov  $GUEST_RIP,%eax
        /*VMREAD(UREGS_rip)*/
        .byte 0x0f,0x78,0x07  /* vmread r(ax),(r(di)) */
        mov  $GUEST_RSP,%eax
        VMREAD(UREGS_rsp)
        mov  $GUEST_RFLAGS,%eax
        VMREAD(UREGS_eflags)

        mov  %cr2,r(ax)
        mov  r(ax),VCPU_hvm_guest_cr2(r(bx))

#ifndef NDEBUG
        mov  $0xbeef,%ax
        mov  %ax,UREGS_error_code(r(sp))
        mov  %ax,UREGS_entry_vector(r(sp))
        mov  %ax,UREGS_saved_upcall_mask(r(sp))
        mov  %ax,UREGS_cs(r(sp))
        mov  %ax,UREGS_ds(r(sp))
        mov  %ax,UREGS_es(r(sp))
        mov  %ax,UREGS_fs(r(sp))
        mov  %ax,UREGS_gs(r(sp))
        mov  %ax,UREGS_ss(r(sp))
#endif

        call_with_regs(vmx_vmexit_handler)

.globl vmx_asm_do_vmentry
vmx_asm_do_vmentry:
        call vmx_intr_assist

        get_current(bx)
        cli

        mov  VCPU_processor(r(bx)),%eax
        shl  $IRQSTAT_shift,r(ax)
        lea  addr_of(irq_stat),r(dx)
        cmpl $0,(r(dx),r(ax),1)
        jnz  .Lvmx_process_softirqs

        testb $0xff,VCPU_vmx_emulate(r(bx))
        jnz .Lvmx_goto_emulator
        testb $0xff,VCPU_vmx_realmode(r(bx))
        jz .Lvmx_not_realmode
        cmpw $0,VCPU_vm86_seg_mask(r(bx))
        jnz .Lvmx_goto_emulator
        call_with_regs(vmx_enter_realmode) 

.Lvmx_not_realmode:
        call vmx_vmenter_helper
        mov  VCPU_hvm_guest_cr2(r(bx)),r(ax)
        mov  r(ax),%cr2

        lea  UREGS_rip(r(sp)),r(di)
        mov  $GUEST_RIP,%eax
        /*VMWRITE(UREGS_rip)*/
        .byte 0x0f,0x79,0x07  /* vmwrite (r(di)),r(ax) */
        mov  $GUEST_RSP,%eax
        VMWRITE(UREGS_rsp)
        mov  $GUEST_RFLAGS,%eax
        VMWRITE(UREGS_eflags)

        cmpb $0,VCPU_vmx_launched(r(bx))
#if defined(__x86_64__)
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
#else /* defined(__i386__) */
        pop  %ebx
        pop  %ecx
        pop  %edx
        pop  %esi
        pop  %edi
        pop  %ebp
        pop  %eax
#endif
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
        call_with_regs(vmx_realmode)
        jmp  vmx_asm_do_vmentry

.Lvmx_process_softirqs:
        sti
        call do_softirq
        jmp  vmx_asm_do_vmentry
