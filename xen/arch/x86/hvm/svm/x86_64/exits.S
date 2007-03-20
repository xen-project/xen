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
        movq $STACK_SIZE-8, reg; \
        orq  %rsp, reg;          \
        andq $~7,reg;            \
        movq (reg),reg;

/*
 * At VMExit time the processor saves the guest selectors, rsp, rip, 
 * and rflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The rflags of the host is not saved by AMD-V, 
 * and we set it to the fixed value.
 *
 * We also need the room, especially because orig_eax field is used 
 * by do_IRQ(). Compared the cpu_user_regs, we skip pushing for the following:
 *   (10) u64 gs;                 
 *   (9)  u64 fs;
 *   (8)  u64 ds;
 *   (7)  u64 es;
 *               <- get_stack_bottom() (= HOST_ESP)
 *   (6)  u64 ss;
 *   (5)  u64 rsp;
 *   (4)  u64 rflags;
 *   (3)  u64 cs;
 *   (2)  u64 rip;
 * (2/1)  u32 entry_vector;
 * (1/1)  u32 error_code;
 */
#define HVM_MONITOR_RFLAGS 0x202 /* IF on */
#define NR_SKIPPED_REGS    6     /* See the above explanation */
#define HVM_SAVE_ALL_NOSEGREGS \
        pushq $HVM_MONITOR_RFLAGS; \
        popfq; \
        subq $(NR_SKIPPED_REGS*8), %rsp; \
        pushq %rdi; \
        pushq %rsi; \
        pushq %rdx; \
        pushq %rcx; \
        pushq %rax; \
        pushq %r8;  \
        pushq %r9;  \
        pushq %r10; \
        pushq %r11; \
        pushq %rbx; \
        pushq %rbp; \
        pushq %r12; \
        pushq %r13; \
        pushq %r14; \
        pushq %r15; \

#define HVM_RESTORE_ALL_NOSEGREGS \
        popq %r15; \
        popq %r14; \
        popq %r13; \
        popq %r12; \
        popq %rbp; \
        popq %rbx; \
        popq %r11; \
        popq %r10; \
        popq %r9;  \
        popq %r8;  \
        popq %rax; \
        popq %rcx; \
        popq %rdx; \
        popq %rsi; \
        popq %rdi; \
        addq $(NR_SKIPPED_REGS*8), %rsp; \

#define VMRUN  .byte 0x0F,0x01,0xD8
#define VMLOAD .byte 0x0F,0x01,0xDA
#define VMSAVE .byte 0x0F,0x01,0xDB
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

ENTRY(svm_asm_do_resume)
        GET_CURRENT(%rbx)
        cli                             # tests must not race interrupts
        movl VCPU_processor(%rbx),%eax
        shl  $IRQSTAT_shift, %rax
        leaq irq_stat(%rip), %rdx
        testl $~0, (%rdx, %rax, 1)
        jnz  svm_process_softirqs
        call svm_intr_assist
        call svm_load_cr2

        CLGI                
        sti
        GET_CURRENT(%rbx)
        movq VCPU_svm_vmcb(%rbx), %rcx
        movq UREGS_rax(%rsp), %rax
        movq %rax, VMCB_rax(%rcx)
        leaq root_vmcb_pa(%rip), %rax
        movl VCPU_processor(%rbx), %ecx
        movq (%rax,%rcx,8), %rax
        VMSAVE

        movq VCPU_svm_vmcb_pa(%rbx), %rax
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
        /*
         * Skip %rax, we need to have vmcb address in there.
         * Don't worry, RAX is restored through the VMRUN instruction.
         */
        addq $8, %rsp
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi
        addq $(NR_SKIPPED_REGS*8), %rsp

        VMLOAD
        VMRUN
        VMSAVE
        HVM_SAVE_ALL_NOSEGREGS

        GET_CURRENT(%rbx)
        leaq root_vmcb_pa(%rip), %rax
        movl VCPU_processor(%rbx), %ecx
        movq (%rax,%rcx,8), %rax
        VMLOAD

        STGI
.globl svm_stgi_label;
svm_stgi_label:
        movq %rsp,%rdi
        call svm_vmexit_handler
        jmp  svm_asm_do_resume

        ALIGN
svm_process_softirqs:
        sti
        call do_softirq
        jmp  svm_asm_do_resume
