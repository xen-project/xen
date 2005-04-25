/*
 * vmx.h: VMX Architecture related definitions
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
 *
 */
#ifndef __ASM_X86_VMX_H__
#define __ASM_X86_VMX_H__

#include <xen/sched.h>
#include <asm/types.h>
#include <asm/regs.h>
#include <asm/processor.h>
#include <asm/vmx_vmcs.h>

extern void vmx_asm_vmexit_handler(struct xen_regs);
extern void vmx_asm_do_resume(void);
extern void vmx_asm_do_launch(void);
extern void vmx_intr_assist(struct exec_domain *d);

extern void arch_vmx_do_launch(struct exec_domain *);
extern void arch_vmx_do_resume(struct exec_domain *);

extern int vmcs_size;
extern unsigned int cpu_rev;

/*
 * Need fill bits for SENTER
 */

#define MONITOR_PIN_BASED_EXEC_CONTROLS         0x0000001f      
#define MONITOR_CPU_BASED_EXEC_CONTROLS         0x0581e7f2
#define MONITOR_VM_EXIT_CONTROLS                0x0003edff
#define MONITOR_VM_ENTRY_CONTROLS               0x000011ff

/*
 * Exit Reasons
 */
#define VMX_EXIT_REASONS_FAILED_VMENTRY         0x80000000

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1

#define EXIT_REASON_PENDING_INTERRUPT   7

#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_VMCALL              18

#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_MWAIT_INSTRUCTION   36

/*
 * Interruption-information format
 */
#define INTR_INFO_VECTOR_MASK           0xff            /* 7:0 */
#define INTR_INFO_INTR_TYPE_MASK        0x700           /* 10:8 */
#define INTR_INFO_DELIEVER_CODE_MASK    0x800           /* 11 */
#define INTR_INFO_VALID_MASK            0x80000000      /* 31 */

#define INTR_TYPE_EXT_INTR              (0 << 8) /* external interrupt */
#define INTR_TYPE_EXCEPTION             (3 << 8) /* processor exception */

/*
 * Exit Qualifications for MOV for Control Register Access
 */
#define CONTROL_REG_ACCESS_NUM          0x7     /* 2:0, number of control register */
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define TYPE_MOV_TO_CR                  (0 << 4) 
#define TYPE_MOV_FROM_CR                (1 << 4)
#define TYPE_CLTS                       (2 << 4)
#define	TYPE_LMSW			(3 << 4)
#define CONTROL_REG_ACCESS_REG          0x700   /* 10:8, general purpose register */
#define REG_EAX                         (0 << 8) 
#define REG_ECX                         (1 << 8) 
#define REG_EDX                         (2 << 8) 
#define REG_EBX                         (3 << 8) 
#define REG_ESP                         (4 << 8) 
#define REG_EBP                         (5 << 8) 
#define REG_ESI                         (6 << 8) 
#define REG_EDI                         (7 << 8) 
#define	LMSW_SOURCE_DATA		(0xFFFF << 16) /* 16:31 lmsw source */

/*
 * Exit Qualifications for MOV for Debug Register Access
 */
#define DEBUG_REG_ACCESS_NUM            0x7     /* 2:0, number of debug register */
#define DEBUG_REG_ACCESS_TYPE           0x10    /* 4, direction of access */
#define TYPE_MOV_TO_DR                  (0 << 4) 
#define TYPE_MOV_FROM_DR                (1 << 4)
#define DEBUG_REG_ACCESS_REG            0x700   /* 11:8, general purpose register */
 
#define EXCEPTION_BITMAP_DE     (1 << 0)        /* Divide Error */
#define EXCEPTION_BITMAP_DB     (1 << 1)        /* Debug */
#define EXCEPTION_BITMAP_NMI    (1 << 2)        /* NMI */
#define EXCEPTION_BITMAP_BP     (1 << 3)        /* Breakpoint */
#define EXCEPTION_BITMAP_OF     (1 << 4)        /* Overflow */
#define EXCEPTION_BITMAP_BR     (1 << 5)        /* BOUND Range Exceeded */
#define EXCEPTION_BITMAP_UD     (1 << 6)        /* Invalid Opcode */
#define EXCEPTION_BITMAP_NM     (1 << 7)        /* Device Not Available */
#define EXCEPTION_BITMAP_DF     (1 << 8)        /* Double Fault */
/* reserved */
#define EXCEPTION_BITMAP_TS     (1 << 10)       /* Invalid TSS */
#define EXCEPTION_BITMAP_NP     (1 << 11)       /* Segment Not Present */
#define EXCEPTION_BITMAP_SS     (1 << 12)       /* Stack-Segment Fault */
#define EXCEPTION_BITMAP_GP     (1 << 13)       /* General Protection */
#define EXCEPTION_BITMAP_PG     (1 << 14)       /* Page Fault */
#define EXCEPTION_BITMAP_MF     (1 << 16)       /* x87 FPU Floating-Point Error (Math Fault)  */
#define EXCEPTION_BITMAP_AC     (1 << 17)       /* Alignment Check */
#define EXCEPTION_BITMAP_MC     (1 << 18)       /* Machine Check */
#define EXCEPTION_BITMAP_XF     (1 << 19)       /* SIMD Floating-Point Exception */

#ifdef XEN_DEBUGGER
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_DB |                     \
      EXCEPTION_BITMAP_BP |                     \
      EXCEPTION_BITMAP_GP )
#else
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_GP )
#endif

#define VMCALL_OPCODE   ".byte 0x0f,0x01,0xc1\n"
#define VMCLEAR_OPCODE  ".byte 0x66,0x0f,0xc7\n"        /* reg/opcode: /6 */
#define VMLAUNCH_OPCODE ".byte 0x0f,0x01,0xc2\n"
#define VMPTRLD_OPCODE  ".byte 0x0f,0xc7\n"             /* reg/opcode: /6 */
#define VMPTRST_OPCODE  ".byte 0x0f,0xc7\n"             /* reg/opcode: /7 */
#define VMREAD_OPCODE   ".byte 0x0f,0x78\n"
#define VMRESUME_OPCODE ".byte 0x0f,0x01,0xc3\n"
#define VMWRITE_OPCODE  ".byte 0x0f,0x79\n"
#define VMXOFF_OPCODE   ".byte 0x0f,0x01,0xc4\n"
#define VMXON_OPCODE    ".byte 0xf3,0x0f,0xc7\n"

#define MODRM_EAX_06    ".byte 0x30\n" /* [EAX], with reg/opcode: /6 */
#define MODRM_EAX_07    ".byte 0x38\n" /* [EAX], with reg/opcode: /7 */
#define MODRM_EAX_ECX   ".byte 0xc1\n" /* [EAX], [ECX] */

static inline int __vmptrld (u64 addr)
{
    unsigned long eflags;
    __asm__ __volatile__ ( VMPTRLD_OPCODE
                           MODRM_EAX_06
                           :
                           : "a" (&addr) 
                           : "memory");

    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}

static inline void __vmptrst (u64 addr)
{
    __asm__ __volatile__ ( VMPTRST_OPCODE
                           MODRM_EAX_07
                           :
                           : "a" (&addr) 
                           : "memory");
}

static inline int __vmpclear (u64 addr)
{
    unsigned long eflags;

    __asm__ __volatile__ ( VMCLEAR_OPCODE
                           MODRM_EAX_06
                           :
                           : "a" (&addr) 
                           : "memory");
    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}

static inline int __vmread (unsigned long field, void *value)
{
    unsigned long eflags;
    unsigned long ecx = 0;

    __asm__ __volatile__ ( VMREAD_OPCODE
                           MODRM_EAX_ECX       
                           : "=c" (ecx)
                           : "a" (field)
                           : "memory");

    *((long *) value) = ecx;

    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}

static inline int __vmwrite (unsigned long field, unsigned long value)
{
    unsigned long eflags;

    __asm__ __volatile__ ( VMWRITE_OPCODE
                           MODRM_EAX_ECX       
                           :
                           : "a" (field) , "c" (value)
                           : "memory");
    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}

static inline void __vmxoff (void)
{
    __asm__ __volatile__ ( VMXOFF_OPCODE 
                           ::: "memory");
}

static inline int __vmxon (u64 addr)
{
    unsigned long eflags;

    __asm__ __volatile__ ( VMXON_OPCODE
                           MODRM_EAX_06
                           :
                           : "a" (&addr) 
                           : "memory");
    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}

#endif /* __ASM_X86_VMX_H__ */
