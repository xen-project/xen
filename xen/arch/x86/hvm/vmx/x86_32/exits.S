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
        movl $STACK_SIZE-4, reg; \
        orl  %esp, reg;          \
        andl $~3,reg;            \
        movl (reg),reg;

/*
 * At VMExit time the processor saves the guest selectors, esp, eip, 
 * and eflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The eflags of the host is not saved by VMX, 
 * and we set it to the fixed value.
 *
 * We also need the room, especially because orig_eax field is used 
 * by do_IRQ(). Compared the cpu_user_regs, we skip pushing for the following:
 *   (10) u32 gs;                 
 *   (9)  u32 fs;
 *   (8)  u32 ds;
 *   (7)  u32 es;
 *               <- get_stack_bottom() (= HOST_ESP)
 *   (6)  u32 ss;
 *   (5)  u32 esp;
 *   (4)  u32 eflags;
 *   (3)  u32 cs;
 *   (2)  u32 eip;
 * (2/1)  u16 entry_vector;
 * (1/1)  u16 error_code;
 * However, get_stack_bottom() actually returns 20 bytes before the real
 * bottom of the stack to allow space for:
 * domain pointer, DS, ES, FS, GS. Therefore, we effectively skip 6 registers.
 */

#define HVM_MONITOR_EFLAGS	0x202 /* IF on */
#define NR_SKIPPED_REGS	6	/* See the above explanation */
#define HVM_SAVE_ALL_NOSEGREGS \
        pushl $HVM_MONITOR_EFLAGS; \
        popf; \
        subl $(NR_SKIPPED_REGS*4), %esp; \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx;

#define HVM_RESTORE_ALL_NOSEGREGS   \
        popl %ebx;  \
        popl %ecx;  \
        popl %edx;  \
        popl %esi;  \
        popl %edi;  \
        popl %ebp;  \
        popl %eax;  \
        addl $(NR_SKIPPED_REGS*4), %esp

        ALIGN

ENTRY(vmx_asm_vmexit_handler)
        /* selectors are restored/saved by VMX */
        HVM_SAVE_ALL_NOSEGREGS
        call vmx_trace_vmexit
        call vmx_vmexit_handler
        jmp vmx_asm_do_resume

.macro vmx_asm_common launch initialized
1:
/* vmx_test_all_events */
        .if \initialized
        GET_CURRENT(%ebx)
/*test_all_events:*/
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        test %ecx,irq_stat(%eax,1)
        jnz 2f

/* vmx_restore_all_guest */
        call vmx_intr_assist
        call vmx_load_cr2
        call vmx_trace_vmentry
        .endif
        HVM_RESTORE_ALL_NOSEGREGS
        /* 
         * Check if we are going back to VMX-based VM
         * By this time, all the setups in the VMCS must be complete.
         */
        .if \launch
        /* VMLAUNCH */
        .byte 0x0f,0x01,0xc2
        pushf
        call vm_launch_fail
        .else
        /* VMRESUME */
        .byte 0x0f,0x01,0xc3
        pushf
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
