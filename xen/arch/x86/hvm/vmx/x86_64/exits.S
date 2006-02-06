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

#define GET_CURRENT(reg)         \
        movq $STACK_SIZE-8, reg; \
        orq  %rsp, reg;          \
        andq $~7,reg;            \
        movq (reg),reg;

/*
 * At VMExit time the processor saves the guest selectors, rsp, rip, 
 * and rflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The rflags of the host is not saved by VMX, 
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
#define HVM_MONITOR_RFLAGS	0x202 /* IF on */
#define NR_SKIPPED_REGS	6	/* See the above explanation */
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

ENTRY(vmx_asm_vmexit_handler)
        /* selectors are restored/saved by VMX */
        HVM_SAVE_ALL_NOSEGREGS
        call vmx_vmexit_handler
        jmp vmx_asm_do_resume

.macro vmx_asm_common launch initialized 
1:
        .if \initialized
/* vmx_test_all_events */
        GET_CURRENT(%rbx)
/* test_all_events: */
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl  VCPU_processor(%rbx),%eax
        shl   $IRQSTAT_shift,%rax
        leaq  irq_stat(%rip), %rdx
        testl $~0,(%rdx,%rax,1)
        jnz  2f 

/* vmx_restore_all_guest */
        call vmx_intr_assist
        call vmx_load_cr2
        .endif
        /* 
         * Check if we are going back to VMX-based VM
         * By this time, all the setups in the VMCS must be complete.
         */
        HVM_RESTORE_ALL_NOSEGREGS
        .if \launch
        /* VMLAUNCH */
        .byte 0x0f,0x01,0xc2
        pushfq
        call vm_launch_fail
        .else
        /* VMRESUME */
        .byte 0x0f,0x01,0xc3
        pushfq
        call vm_resume_fail
        .endif
        /* Should never reach here */
        hlt

        ALIGN

        .if \initialized
2:
/* vmx_process_softirqs */
        sti       
        call do_softirq
        jmp 1b
        ALIGN
        .endif
.endm

ENTRY(vmx_asm_do_launch)
      vmx_asm_common 1 0

ENTRY(vmx_asm_do_resume)
      vmx_asm_common 0 1

ENTRY(vmx_asm_do_relaunch)
      vmx_asm_common 1 1
