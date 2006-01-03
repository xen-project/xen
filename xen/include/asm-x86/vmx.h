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
#include <asm/i387.h>

#include <public/io/ioreq.h>

extern int hvm_enabled;

extern void vmx_asm_vmexit_handler(struct cpu_user_regs);
extern void vmx_asm_do_resume(void);
extern void vmx_asm_do_launch(void);
extern void vmx_intr_assist(void);
extern void pic_irq_request(int *interrupt_request, int level);

extern void arch_vmx_do_launch(struct vcpu *);
extern void arch_vmx_do_resume(struct vcpu *);
extern void arch_vmx_do_relaunch(struct vcpu *);

extern unsigned int cpu_rev;

/*
 * Need fill bits for SENTER
 */

#define MONITOR_PIN_BASED_EXEC_CONTROLS_RESERVED_VALUE         0x00000016

#define MONITOR_PIN_BASED_EXEC_CONTROLS       \
    ( \
    MONITOR_PIN_BASED_EXEC_CONTROLS_RESERVED_VALUE |   \
    PIN_BASED_EXT_INTR_MASK |   \
    PIN_BASED_NMI_EXITING \
    )

#define MONITOR_CPU_BASED_EXEC_CONTROLS_RESERVED_VALUE         0x0401e172

#define _MONITOR_CPU_BASED_EXEC_CONTROLS \
    ( \
    MONITOR_CPU_BASED_EXEC_CONTROLS_RESERVED_VALUE |    \
    CPU_BASED_HLT_EXITING | \
    CPU_BASED_INVDPG_EXITING | \
    CPU_BASED_MWAIT_EXITING | \
    CPU_BASED_MOV_DR_EXITING | \
    CPU_BASED_ACTIVATE_IO_BITMAP | \
    CPU_BASED_USE_TSC_OFFSETING  | \
    CPU_BASED_UNCOND_IO_EXITING \
    )

#define MONITOR_CPU_BASED_EXEC_CONTROLS_IA32E_MODE \
    ( \
    CPU_BASED_CR8_LOAD_EXITING | \
    CPU_BASED_CR8_STORE_EXITING \
    )

#define MONITOR_VM_EXIT_CONTROLS_RESERVED_VALUE   0x0003edff

#define MONITOR_VM_EXIT_CONTROLS_IA32E_MODE       0x00000200

#define _MONITOR_VM_EXIT_CONTROLS                \
    ( \
    MONITOR_VM_EXIT_CONTROLS_RESERVED_VALUE |\
    VM_EXIT_ACK_INTR_ON_EXIT \
    )

#if defined (__x86_64__)
#define MONITOR_CPU_BASED_EXEC_CONTROLS \
    ( \
    _MONITOR_CPU_BASED_EXEC_CONTROLS | \
    MONITOR_CPU_BASED_EXEC_CONTROLS_IA32E_MODE \
    )
#define MONITOR_VM_EXIT_CONTROLS \
    ( \
    _MONITOR_VM_EXIT_CONTROLS | \
    MONITOR_VM_EXIT_CONTROLS_IA32E_MODE  \
    )
#else
#define MONITOR_CPU_BASED_EXEC_CONTROLS \
    _MONITOR_CPU_BASED_EXEC_CONTROLS 

#define MONITOR_VM_EXIT_CONTROLS \
    _MONITOR_VM_EXIT_CONTROLS
#endif

#define VM_ENTRY_CONTROLS_RESERVED_VALUE        0x000011ff
#define VM_ENTRY_CONTROLS_IA32E_MODE            0x00000200
#define MONITOR_VM_ENTRY_CONTROLS       VM_ENTRY_CONTROLS_RESERVED_VALUE 
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
#define TYPE_LMSW   (3 << 4)
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose register */
#define LMSW_SOURCE_DATA  (0xFFFF << 16) /* 16:31 lmsw source */
#define REG_EAX                         (0 << 8) 
#define REG_ECX                         (1 << 8) 
#define REG_EDX                         (2 << 8) 
#define REG_EBX                         (3 << 8) 
#define REG_ESP                         (4 << 8) 
#define REG_EBP                         (5 << 8) 
#define REG_ESI                         (6 << 8) 
#define REG_EDI                         (7 << 8) 
#define REG_R8                         (8 << 8)
#define REG_R9                         (9 << 8)
#define REG_R10                        (10 << 8)
#define REG_R11                        (11 << 8)
#define REG_R12                        (12 << 8)
#define REG_R13                        (13 << 8)
#define REG_R14                        (14 << 8)
#define REG_R15                        (15 << 8)

/*
 * Exit Qualifications for MOV for Debug Register Access
 */
#define DEBUG_REG_ACCESS_NUM            0x7     /* 2:0, number of debug register */
#define DEBUG_REG_ACCESS_TYPE           0x10    /* 4, direction of access */
#define TYPE_MOV_TO_DR                  (0 << 4) 
#define TYPE_MOV_FROM_DR                (1 << 4)
#define DEBUG_REG_ACCESS_REG            0xf00   /* 11:8, general purpose register */
 
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

/* Pending Debug exceptions */

#define PENDING_DEBUG_EXC_BP    (1 << 12)       /* break point */
#define PENDING_DEBUG_EXC_BS    (1 << 14)       /* Single step */

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

/* These bits in the CR4 are owned by the host */
#ifdef __i386__
#define VMX_CR4_HOST_MASK (X86_CR4_VMXE)
#else
#define VMX_CR4_HOST_MASK (X86_CR4_VMXE | X86_CR4_PAE)
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

#define __vmread(x, ptr) ___vmread((x), (ptr), sizeof(*(ptr)))

static always_inline int ___vmread (const unsigned long field,  void *ptr, const int size)
{
    unsigned long eflags;
    unsigned long ecx = 0;

    __asm__ __volatile__ ( VMREAD_OPCODE
                           MODRM_EAX_ECX       
                           : "=c" (ecx)
                           : "a" (field)
                           : "memory");

    switch (size) {
    case 1:
        *((u8 *) (ptr)) = ecx;
        break;
    case 2:
        *((u16 *) (ptr)) = ecx;
        break;
    case 4:
        *((u32 *) (ptr)) = ecx;
        break;
    case 8:
        *((u64 *) (ptr)) = ecx;
        break;
    default:
        domain_crash_synchronous();
        break;
    }

    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;
    return 0;
}


static always_inline void __vmwrite_vcpu(struct vcpu *v, unsigned long field, unsigned long value)
{
    switch(field) {
    case CR0_READ_SHADOW:
	v->arch.arch_vmx.cpu_shadow_cr0 = value;
	break;
    case GUEST_CR0:
	v->arch.arch_vmx.cpu_cr0 = value;
	break;
    case CPU_BASED_VM_EXEC_CONTROL:
	v->arch.arch_vmx.cpu_based_exec_control = value;
	break;
    default:
	printk("__vmwrite_cpu: invalid field %lx\n", field);
	break;
    }
}

static always_inline void __vmread_vcpu(struct vcpu *v, unsigned long field, unsigned long *value)
{
    switch(field) {
    case CR0_READ_SHADOW:
	*value = v->arch.arch_vmx.cpu_shadow_cr0;
	break;
    case GUEST_CR0:
	*value = v->arch.arch_vmx.cpu_cr0;
	break;
    case CPU_BASED_VM_EXEC_CONTROL:
	*value = v->arch.arch_vmx.cpu_based_exec_control;
	break;
    default:
	printk("__vmread_cpu: invalid field %lx\n", field);
	break;
    }
}

static inline int __vmwrite (unsigned long field, unsigned long value)
{
    unsigned long eflags;
    struct vcpu *v = current;

    __asm__ __volatile__ ( VMWRITE_OPCODE
                           MODRM_EAX_ECX
                           :
                           : "a" (field) , "c" (value)
                           : "memory");
    __save_flags(eflags);
    if (eflags & X86_EFLAGS_ZF || eflags & X86_EFLAGS_CF)
        return -1;

    switch(field) {
    case CR0_READ_SHADOW:
    case GUEST_CR0:
    case CPU_BASED_VM_EXEC_CONTROL:
	__vmwrite_vcpu(v, field, value);
	break;
    }

    return 0;
}

static inline int __vm_set_bit(unsigned long field, unsigned long mask)
{
        unsigned long tmp;
        int err = 0;

        err |= __vmread(field, &tmp);
        tmp |= mask;
        err |= __vmwrite(field, tmp);

        return err;
}

static inline int __vm_clear_bit(unsigned long field, unsigned long mask)
{
        unsigned long tmp;
        int err = 0;

        err |= __vmread(field, &tmp);
        tmp &= ~mask;
        err |= __vmwrite(field, tmp);

        return err;
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

/* Make sure that xen intercepts any FP accesses from current */
static inline void vmx_stts(void)
{
    unsigned long cr0;
    struct vcpu *v = current;

    __vmread_vcpu(v, GUEST_CR0, &cr0);
    if (!(cr0 & X86_CR0_TS)) {
        __vmwrite(GUEST_CR0, cr0 | X86_CR0_TS);
    }

    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    if (!(cr0 & X86_CR0_TS))
       __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
}

/* Works only for vcpu == current */
static inline int vmx_paging_enabled(struct vcpu *v)
{
    unsigned long cr0;

    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    return (cr0 & X86_CR0_PE) && (cr0 & X86_CR0_PG);
}

#define VMX_INVALID_ERROR_CODE  -1

static inline int __vmx_inject_exception(struct vcpu *v, int trap, int type, 
                                         int error_code)
{
    unsigned long intr_fields;

    /* Reflect it back into the guest */
    intr_fields = (INTR_INFO_VALID_MASK | type | trap);
    if (error_code != VMX_INVALID_ERROR_CODE) {
        __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        intr_fields |= INTR_INFO_DELIEVER_CODE_MASK;
     }
    
    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, intr_fields);
    return 0;
}

static inline int vmx_inject_exception(struct vcpu *v, int trap, int error_code)
{
    return __vmx_inject_exception(v, trap, INTR_TYPE_EXCEPTION, error_code);
}

static inline int vmx_inject_extint(struct vcpu *v, int trap, int error_code)
{
    __vmx_inject_exception(v, trap, INTR_TYPE_EXT_INTR, error_code);
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);

    return 0;
}

static inline int vmx_reflect_exception(struct vcpu *v)
{
    int error_code, vector;

    __vmread(VM_EXIT_INTR_INFO, &vector);
    if (vector & INTR_INFO_DELIEVER_CODE_MASK)
        __vmread(VM_EXIT_INTR_ERROR_CODE, &error_code);
    else
        error_code = VMX_INVALID_ERROR_CODE;
    vector &= 0xff;

#ifndef NDEBUG
    {
        unsigned long eip;

        __vmread(GUEST_RIP, &eip);
        VMX_DBG_LOG(DBG_LEVEL_1,
                    "vmx_reflect_exception: eip = %lx, error_code = %x",
                    eip, error_code);
    }
#endif /* NDEBUG */

    vmx_inject_exception(v, vector, error_code);
    return 0;
}

static inline unsigned int vmx_get_vcpu_nr(struct domain *d)
{
    return d->arch.vmx_platform.nr_vcpus;
}

static inline shared_iopage_t *get_sp(struct domain *d)
{
    return (shared_iopage_t *) d->arch.vmx_platform.shared_page_va;
}

static inline vcpu_iodata_t *get_vio(struct domain *d, unsigned long cpu)
{
    return &get_sp(d)->vcpu_iodata[cpu];
}

static inline int iopacket_port(struct domain *d)
{
    return get_sp(d)->sp_global.eport;
}

/* Prototypes */
void load_cpu_user_regs(struct cpu_user_regs *regs);
void store_cpu_user_regs(struct cpu_user_regs *regs);

enum { VMX_COPY_IN = 0, VMX_COPY_OUT };
int vmx_copy(void *buf, unsigned long laddr, int size, int dir);
void pickup_deactive_ticks(struct vmx_virpit *vpit);

#endif /* __ASM_X86_VMX_H__ */
