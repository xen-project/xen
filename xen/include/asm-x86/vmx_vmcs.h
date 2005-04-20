/*
 * vmx_vmcs.h: VMCS related definitions
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
#ifndef __ASM_X86_VMX_VMCS_H__
#define __ASM_X86_VMX_VMCS_H__

#include <asm/config.h>
#include <asm/vmx_cpu.h>
#include <asm/vmx_platform.h>
#include <public/vmx_assist.h>

extern int start_vmx(void);
extern void stop_vmx(void);

void vmx_enter_scheduler(void);

#define VMX_CPU_STATE_PG_ENABLED        0       
#define	VMX_CPU_STATE_ASSIST_ENABLED	1
#define VMCS_SIZE                       0x1000

struct vmcs_struct {
    u32 vmcs_revision_id;
    unsigned char data [0x1000 - sizeof (u32)];
};

struct arch_vmx_struct {
    struct vmcs_struct      *vmcs;  /* VMCS pointer in virtual */
    unsigned long           flags;  /* VMCS flags */
    unsigned long           cpu_cr2; /* save CR2 */
    unsigned long           cpu_cr3;
    unsigned long           cpu_state;
    struct virutal_platform_def     vmx_platform; 
};

#define vmx_schedule_tail(next)         \
    (next)->thread.arch_vmx.arch_vmx_schedule_tail((next))

#define VMX_DOMAIN(ed)   ((ed)->arch.arch_vmx.flags)

#define ARCH_VMX_VMCS_LOADED    0       /* VMCS has been loaded and active */
#define ARCH_VMX_VMCS_LAUNCH    1       /* Needs VMCS launch */
#define ARCH_VMX_VMCS_RESUME    2       /* Needs VMCS resume */
#define ARCH_VMX_IO_WAIT        3       /* Waiting for I/O completion */

void vmx_do_launch(struct exec_domain *); 
void vmx_do_resume(struct exec_domain *); 

struct vmcs_struct *alloc_vmcs(void);
void free_vmcs(struct vmcs_struct *);
int  load_vmcs(struct arch_vmx_struct *, u64);
int  store_vmcs(struct arch_vmx_struct *, u64);
void dump_vmcs(void);
int  construct_vmcs(struct arch_vmx_struct *, execution_context_t *, 
                    full_execution_context_t *, int);

#define VMCS_USE_HOST_ENV       1
#define VMCS_USE_SEPARATE_ENV   0

#define VMCS_EFLAGS_RESERVED_0          0xffc08028 /* bitmap for 0 */
#define VMCS_EFLAGS_RESERVED_1          0x00000002 /* bitmap for 1 */

extern int vmcs_version;

/* VMCS Encordings */
enum vmcs_field {
    GUEST_ES_SELECTOR               = 0x00000800,
    GUEST_CS_SELECTOR               = 0x00000802,
    GUEST_SS_SELECTOR               = 0x00000804,
    GUEST_DS_SELECTOR               = 0x00000806,
    GUEST_FS_SELECTOR               = 0x00000808,
    GUEST_GS_SELECTOR               = 0x0000080a,
    GUEST_LDTR_SELECTOR             = 0x0000080c,
    GUEST_TR_SELECTOR               = 0x0000080e,
    HOST_ES_SELECTOR                = 0x00000c00,
    HOST_CS_SELECTOR                = 0x00000c02,
    HOST_SS_SELECTOR                = 0x00000c04,
    HOST_DS_SELECTOR                = 0x00000c06,
    HOST_FS_SELECTOR                = 0x00000c08,
    HOST_GS_SELECTOR                = 0x00000c0a,
    HOST_TR_SELECTOR                = 0x00000c0c,
    IO_BITMAP_A                     = 0x00002000, 
    IO_BITMAP_B                     = 0x00002002, 
    VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
    TSC_OFFSET                      = 0x00002010,
    GUEST_VMCS0                     = 0x00002800,
    GUEST_VMCS1                     = 0x00002801,
    GUEST_IA32_DEBUGCTL             = 0x00002802,
    PIN_BASED_VM_EXEC_CONTROL       = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL       = 0x00004002,   
    EXCEPTION_BITMAP                = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK      = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH     = 0x00004008,
    CR3_TARGET_COUNT                = 0x0000400a,
    VM_EXIT_CONTROLS                = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT         = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT          = 0x00004010,
    VM_ENTRY_CONTROLS               = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT         = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD        = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,
    VM_EXIT_REASON                  = 0x00004402,
    VM_EXIT_INTR_INFO               = 0x00004404,   
    VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
    IDT_VECTORING_INFO_FIELD        = 0x00004408,
    IDT_VECTORING_ERROR_CODE        = 0x0000440a,
    INSTRUCTION_LEN                 = 0x0000440c,
    GUEST_ES_LIMIT                  = 0x00004800,
    GUEST_CS_LIMIT                  = 0x00004802,
    GUEST_SS_LIMIT                  = 0x00004804,
    GUEST_DS_LIMIT                  = 0x00004806,
    GUEST_FS_LIMIT                  = 0x00004808,
    GUEST_GS_LIMIT                  = 0x0000480a,
    GUEST_LDTR_LIMIT                = 0x0000480c,
    GUEST_TR_LIMIT                  = 0x0000480e,
    GUEST_GDTR_LIMIT                = 0x00004810,
    GUEST_IDTR_LIMIT                = 0x00004812,
    GUEST_ES_AR_BYTES               = 0x00004814,
    GUEST_CS_AR_BYTES               = 0x00004816,
    GUEST_SS_AR_BYTES               = 0x00004818,
    GUEST_DS_AR_BYTES               = 0x0000481a,
    GUEST_FS_AR_BYTES               = 0x0000481c,
    GUEST_GS_AR_BYTES               = 0x0000481e,
    GUEST_LDTR_AR_BYTES             = 0x00004820,
    GUEST_TR_AR_BYTES               = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO     = 0x00004824,
    CR0_GUEST_HOST_MASK             = 0x00006000,
    CR4_GUEST_HOST_MASK             = 0x00006002,
    CR0_READ_SHADOW                 = 0x00006004,
    CR4_READ_SHADOW                 = 0x00006006,
    CR3_TARGET_VALUES               = 0x00006008, 
    CR3_GUEST_HOST_MASK             = 0x00006208,
    EXIT_QUALIFICATION              = 0x00006400,
    GUEST_CR0                       = 0x00006800,
    GUEST_CR3                       = 0x00006802,
    GUEST_CR4                       = 0x00006804,
    GUEST_ES_BASE                   = 0x00006806,
    GUEST_CS_BASE                   = 0x00006808,
    GUEST_SS_BASE                   = 0x0000680a,
    GUEST_DS_BASE                   = 0x0000680c,
    GUEST_FS_BASE                   = 0x0000680e,
    GUEST_GS_BASE                   = 0x00006810,
    GUEST_LDTR_BASE                 = 0x00006812,
    GUEST_TR_BASE                   = 0x00006814,
    GUEST_GDTR_BASE                 = 0x00006816,    
    GUEST_IDTR_BASE                 = 0x00006818,
    GUEST_DR7                       = 0x0000681a,
    GUEST_ESP                       = 0x0000681c,
    GUEST_EIP                       = 0x0000681e,
    GUEST_EFLAGS                    = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822,
    HOST_CR0                        = 0x00006c00,
    HOST_CR3                        = 0x00006c02,
    HOST_CR4                        = 0x00006c04,
    HOST_FS_BASE                    = 0x00006c06,
    HOST_GS_BASE                    = 0x00006c08,
    HOST_TR_BASE                    = 0x00006c0a,
    HOST_GDTR_BASE                  = 0x00006c0c,
    HOST_IDTR_BASE                  = 0x00006c0e,
    HOST_ESP                        = 0x00006c14,
    HOST_EIP                        = 0x00006c16,
};

#define VMX_DEBUG 1
#if VMX_DEBUG
#define DBG_LEVEL_0     (1 << 0)
#define DBG_LEVEL_1     (1 << 1)
#define DBG_LEVEL_2     (1 << 2)
#define DBG_LEVEL_3     (1 << 3)
#define DBG_LEVEL_IO    (1 << 4)
#define DBG_LEVEL_VMMU  (1 << 5)

extern unsigned int opt_vmx_debug_level;
#define VMX_DBG_LOG(level, _f, _a...)           \
    if ((level) & opt_vmx_debug_level)          \
        printk("[VMX]" _f "\n", ## _a )
#else
#define VMX_DBG_LOG(level, _f, _a...)
#endif

#define  __vmx_bug(regs)                                        \
    do {                                                        \
        printk("__vmx_bug at %s:%d\n", __FILE__, __LINE__);     \
        show_registers(regs);                                   \
        domain_crash_synchronous();                             \
    } while (0)

#endif /* ASM_X86_VMX_VMCS_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
