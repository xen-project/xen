/*
 * vmcs.h: VMCS related definitions
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
#ifndef __ASM_X86_HVM_VMX_VMCS_H__
#define __ASM_X86_HVM_VMX_VMCS_H__

#include <asm/hvm/io.h>
#include <asm/hvm/vpmu.h>
#include <irq_vectors.h>

extern void vmcs_dump_vcpu(struct vcpu *v);
extern void setup_vmcs_dump(void);
extern int  vmx_cpu_up_prepare(unsigned int cpu);
extern void vmx_cpu_dead(unsigned int cpu);
extern int  vmx_cpu_up(void);
extern void vmx_cpu_down(void);
extern void vmx_save_host_msrs(void);

struct vmcs_struct {
    u32 vmcs_revision_id;
    unsigned char data [0]; /* vmcs size is read from MSR */
};

struct vmx_msr_entry {
    u32 index;
    u32 mbz;
    u64 data;
};

enum {
    VMX_INDEX_MSR_LSTAR = 0,
    VMX_INDEX_MSR_STAR,
    VMX_INDEX_MSR_SYSCALL_MASK,

    VMX_MSR_COUNT
};

struct vmx_msr_state {
    unsigned long flags;
    unsigned long msrs[VMX_MSR_COUNT];
};

#define EPT_DEFAULT_MT      MTRR_TYPE_WRBACK

struct ept_data {
    union {
    struct {
            u64 ept_mt :3,
                ept_wl :3,
                rsvd   :6,
                asr    :52;
        };
        u64 eptp;
    };
    cpumask_var_t synced_mask;
};

struct vmx_domain {
    unsigned long apic_access_mfn;
};

struct pi_desc {
    DECLARE_BITMAP(pir, NR_VECTORS);
    u32 control;
    u32 rsvd[7];
} __attribute__ ((aligned (64)));

#define ept_get_wl(ept)   ((ept)->ept_wl)
#define ept_get_asr(ept)  ((ept)->asr)
#define ept_get_eptp(ept) ((ept)->eptp)
#define ept_get_synced_mask(ept) ((ept)->synced_mask)

struct arch_vmx_struct {
    /* Virtual address of VMCS. */
    struct vmcs_struct  *vmcs;
    /* VMCS shadow machine address. */
    paddr_t             vmcs_shadow_maddr;

    /* Protects remote usage of VMCS (VMPTRLD/VMCLEAR). */
    spinlock_t           vmcs_lock;

    /*
     * Activation and launch status of this VMCS.
     *  - Activated on a CPU by VMPTRLD. Deactivated by VMCLEAR.
     *  - Launched on active CPU by VMLAUNCH when current VMCS.
     */
    struct list_head     active_list;
    int                  active_cpu;
    int                  launched;

    /* Cache of cpu execution control. */
    u32                  exec_control;
    u32                  secondary_exec_control;
    u32                  exception_bitmap;

    struct vmx_msr_state msr_state;
    unsigned long        shadow_gs;
    unsigned long        cstar;

    unsigned long       *msr_bitmap;
    unsigned int         msr_count;
    struct vmx_msr_entry *msr_area;
    unsigned int         host_msr_count;
    struct vmx_msr_entry *host_msr_area;

    unsigned long        eoi_exitmap_changed;
    DECLARE_BITMAP(eoi_exit_bitmap, NR_VECTORS);
    struct pi_desc       pi_desc;

    unsigned long        host_cr0;

    /* Do we need to tolerate a spurious EPT_MISCONFIG VM exit? */
    bool_t               ept_spurious_misconfig;

    /* Is the guest in real mode? */
    uint8_t              vmx_realmode;
    /* Are we emulating rather than VMENTERing? */
    uint8_t              vmx_emulate;
    /* Bitmask of segments that we can't safely use in virtual 8086 mode */
    uint16_t             vm86_segment_mask;
    /* Shadow CS, SS, DS, ES, FS, GS, TR while in virtual 8086 mode */
    struct segment_register vm86_saved_seg[x86_seg_tr + 1];
    /* Remember EFLAGS while in virtual 8086 mode */
    uint32_t             vm86_saved_eflags;
    int                  hostenv_migrated;

    /* Bitmap to control vmexit policy for Non-root VMREAD/VMWRITE */
    struct page_info     *vmread_bitmap;
    struct page_info     *vmwrite_bitmap;
};

int vmx_create_vmcs(struct vcpu *v);
void vmx_destroy_vmcs(struct vcpu *v);
void vmx_vmcs_enter(struct vcpu *v);
bool_t __must_check vmx_vmcs_try_enter(struct vcpu *v);
void vmx_vmcs_exit(struct vcpu *v);

#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000
extern u32 vmx_cpu_based_exec_control;

#define PIN_BASED_EXT_INTR_MASK         0x00000001
#define PIN_BASED_NMI_EXITING           0x00000008
#define PIN_BASED_VIRTUAL_NMIS          0x00000020
#define PIN_BASED_PREEMPT_TIMER         0x00000040
#define PIN_BASED_POSTED_INTERRUPT      0x00000080
extern u32 vmx_pin_based_exec_control;

#define VM_EXIT_SAVE_DEBUG_CNTRLS       0x00000004
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL   0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_GUEST_PAT          0x00040000
#define VM_EXIT_LOAD_HOST_PAT           0x00080000
#define VM_EXIT_SAVE_GUEST_EFER         0x00100000
#define VM_EXIT_LOAD_HOST_EFER          0x00200000
#define VM_EXIT_SAVE_PREEMPT_TIMER      0x00400000
#define VM_EXIT_CLEAR_BNDCFGS           0x00800000
extern u32 vmx_vmexit_control;

#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL  0x00002000
#define VM_ENTRY_LOAD_GUEST_PAT         0x00004000
#define VM_ENTRY_LOAD_GUEST_EFER        0x00008000
#define VM_ENTRY_LOAD_BNDCFGS           0x00010000
extern u32 vmx_vmentry_control;

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING    0x00004000
extern u32 vmx_secondary_exec_control;

#define VMX_EPT_EXEC_ONLY_SUPPORTED             0x00000001
#define VMX_EPT_WALK_LENGTH_4_SUPPORTED         0x00000040
#define VMX_EPT_MEMORY_TYPE_UC                  0x00000100
#define VMX_EPT_MEMORY_TYPE_WB                  0x00004000
#define VMX_EPT_SUPERPAGE_2MB                   0x00010000
#define VMX_EPT_SUPERPAGE_1GB                   0x00020000
#define VMX_EPT_INVEPT_INSTRUCTION              0x00100000
#define VMX_EPT_INVEPT_SINGLE_CONTEXT           0x02000000
#define VMX_EPT_INVEPT_ALL_CONTEXT              0x04000000

#define VMX_MISC_VMWRITE_ALL                    0x20000000

#define VMX_VPID_INVVPID_INSTRUCTION                        0x100000000ULL
#define VMX_VPID_INVVPID_INDIVIDUAL_ADDR                    0x10000000000ULL
#define VMX_VPID_INVVPID_SINGLE_CONTEXT                     0x20000000000ULL
#define VMX_VPID_INVVPID_ALL_CONTEXT                        0x40000000000ULL
#define VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBAL    0x80000000000ULL

#define VMX_MISC_CR3_TARGET             0x1ff0000

#define cpu_has_wbinvd_exiting \
    (vmx_secondary_exec_control & SECONDARY_EXEC_WBINVD_EXITING)
#define cpu_has_vmx_virtualize_apic_accesses \
    (vmx_secondary_exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
#define cpu_has_vmx_tpr_shadow \
    (vmx_cpu_based_exec_control & CPU_BASED_TPR_SHADOW)
#define cpu_has_vmx_vnmi \
    (vmx_pin_based_exec_control & PIN_BASED_VIRTUAL_NMIS)
#define cpu_has_vmx_msr_bitmap \
    (vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_MSR_BITMAP)
#define cpu_has_vmx_secondary_exec_control \
    (vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
#define cpu_has_vmx_ept \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT)
#define cpu_has_vmx_vpid \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
#define cpu_has_monitor_trap_flag \
    (vmx_cpu_based_exec_control & CPU_BASED_MONITOR_TRAP_FLAG)
#define cpu_has_vmx_pat \
    (vmx_vmentry_control & VM_ENTRY_LOAD_GUEST_PAT)
#define cpu_has_vmx_unrestricted_guest \
    (vmx_secondary_exec_control & SECONDARY_EXEC_UNRESTRICTED_GUEST)
#define vmx_unrestricted_guest(v)               \
    ((v)->arch.hvm_vmx.secondary_exec_control & \
     SECONDARY_EXEC_UNRESTRICTED_GUEST)
#define cpu_has_vmx_ple \
    (vmx_secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
#define cpu_has_vmx_apic_reg_virt \
    (vmx_secondary_exec_control & SECONDARY_EXEC_APIC_REGISTER_VIRT)
#define cpu_has_vmx_virtual_intr_delivery \
    (vmx_secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
#define cpu_has_vmx_virtualize_x2apic_mode \
    (vmx_secondary_exec_control & SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE)
#define cpu_has_vmx_posted_intr_processing \
    (vmx_pin_based_exec_control & PIN_BASED_POSTED_INTERRUPT)
#define cpu_has_vmx_vmcs_shadowing \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VMCS_SHADOWING)

#define VMCS_RID_TYPE_MASK              0x80000000

/* GUEST_INTERRUPTIBILITY_INFO flags. */
#define VMX_INTR_SHADOW_STI             0x00000001
#define VMX_INTR_SHADOW_MOV_SS          0x00000002
#define VMX_INTR_SHADOW_SMI             0x00000004
#define VMX_INTR_SHADOW_NMI             0x00000008

#define VMX_BASIC_REVISION_MASK         0x7fffffff
#define VMX_BASIC_VMCS_SIZE_MASK        (0x1fffULL << 32)
#define VMX_BASIC_32BIT_ADDRESSES       (1ULL << 48)
#define VMX_BASIC_DUAL_MONITOR          (1ULL << 49)
#define VMX_BASIC_MEMORY_TYPE_MASK      (0xfULL << 50)
#define VMX_BASIC_INS_OUT_INFO          (1ULL << 54)
/* 
 * bit 55 of IA32_VMX_BASIC MSR, indicating whether any VMX controls that
 * default to 1 may be cleared to 0.
 */
#define VMX_BASIC_DEFAULT1_ZERO		(1ULL << 55)

extern u64 vmx_basic_msr;
#define cpu_has_vmx_ins_outs_instr_info \
    (!!(vmx_basic_msr & VMX_BASIC_INS_OUT_INFO))

/* Guest interrupt status */
#define VMX_GUEST_INTR_STATUS_SUBFIELD_BITMASK  0x0FF
#define VMX_GUEST_INTR_STATUS_SVI_OFFSET        8

/* VMCS field encodings. */
enum vmcs_field {
    VIRTUAL_PROCESSOR_ID            = 0x00000000,
    POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
    GUEST_ES_SELECTOR               = 0x00000800,
    GUEST_CS_SELECTOR               = 0x00000802,
    GUEST_SS_SELECTOR               = 0x00000804,
    GUEST_DS_SELECTOR               = 0x00000806,
    GUEST_FS_SELECTOR               = 0x00000808,
    GUEST_GS_SELECTOR               = 0x0000080a,
    GUEST_LDTR_SELECTOR             = 0x0000080c,
    GUEST_TR_SELECTOR               = 0x0000080e,
    GUEST_INTR_STATUS               = 0x00000810,
    HOST_ES_SELECTOR                = 0x00000c00,
    HOST_CS_SELECTOR                = 0x00000c02,
    HOST_SS_SELECTOR                = 0x00000c04,
    HOST_DS_SELECTOR                = 0x00000c06,
    HOST_FS_SELECTOR                = 0x00000c08,
    HOST_GS_SELECTOR                = 0x00000c0a,
    HOST_TR_SELECTOR                = 0x00000c0c,
    IO_BITMAP_A                     = 0x00002000,
    IO_BITMAP_A_HIGH                = 0x00002001,
    IO_BITMAP_B                     = 0x00002002,
    IO_BITMAP_B_HIGH                = 0x00002003,
    MSR_BITMAP                      = 0x00002004,
    MSR_BITMAP_HIGH                 = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH     = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH      = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH     = 0x0000200b,
    TSC_OFFSET                      = 0x00002010,
    TSC_OFFSET_HIGH                 = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH     = 0x00002013,
    APIC_ACCESS_ADDR                = 0x00002014,
    APIC_ACCESS_ADDR_HIGH           = 0x00002015,
    PI_DESC_ADDR                    = 0x00002016,
    PI_DESC_ADDR_HIGH               = 0x00002017,
    EPT_POINTER                     = 0x0000201a,
    EPT_POINTER_HIGH                = 0x0000201b,
    EOI_EXIT_BITMAP0                = 0x0000201c,
#define EOI_EXIT_BITMAP(n) (EOI_EXIT_BITMAP0 + (n) * 2) /* n = 0...3 */
    VMREAD_BITMAP                   = 0x00002026,
    VMREAD_BITMAP_HIGH              = 0x00002027,
    VMWRITE_BITMAP                  = 0x00002028,
    VMWRITE_BITMAP_HIGH             = 0x00002029,
    GUEST_PHYSICAL_ADDRESS          = 0x00002400,
    GUEST_PHYSICAL_ADDRESS_HIGH     = 0x00002401,
    VMCS_LINK_POINTER               = 0x00002800,
    VMCS_LINK_POINTER_HIGH          = 0x00002801,
    GUEST_IA32_DEBUGCTL             = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH        = 0x00002803,
    GUEST_PAT                       = 0x00002804,
    GUEST_PAT_HIGH                  = 0x00002805,
    GUEST_EFER                      = 0x00002806,
    GUEST_EFER_HIGH                 = 0x00002807,
    GUEST_PERF_GLOBAL_CTRL          = 0x00002808,
    GUEST_PERF_GLOBAL_CTRL_HIGH     = 0x00002809,
    GUEST_PDPTR0                    = 0x0000280a,
    GUEST_PDPTR0_HIGH               = 0x0000280b,
    GUEST_PDPTR1                    = 0x0000280c,
    GUEST_PDPTR1_HIGH               = 0x0000280d,
    GUEST_PDPTR2                    = 0x0000280e,
    GUEST_PDPTR2_HIGH               = 0x0000280f,
    GUEST_PDPTR3                    = 0x00002810,
    GUEST_PDPTR3_HIGH               = 0x00002811,
    GUEST_BNDCFGS                   = 0x00002812,
    GUEST_BNDCFGS_HIGH              = 0x00002813,
    HOST_PAT                        = 0x00002c00,
    HOST_PAT_HIGH                   = 0x00002c01,
    HOST_EFER                       = 0x00002c02,
    HOST_EFER_HIGH                  = 0x00002c03,
    HOST_PERF_GLOBAL_CTRL           = 0x00002c04,
    HOST_PERF_GLOBAL_CTRL_HIGH      = 0x00002c05,
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
    VM_ENTRY_INTR_INFO              = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,
    TPR_THRESHOLD                   = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL       = 0x0000401e,
    PLE_GAP                         = 0x00004020,
    PLE_WINDOW                      = 0x00004022,
    VM_INSTRUCTION_ERROR            = 0x00004400,
    VM_EXIT_REASON                  = 0x00004402,
    VM_EXIT_INTR_INFO               = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
    IDT_VECTORING_INFO              = 0x00004408,
    IDT_VECTORING_ERROR_CODE        = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN         = 0x0000440c,
    VMX_INSTRUCTION_INFO            = 0x0000440e,
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
    GUEST_ACTIVITY_STATE            = 0x00004826,
    GUEST_SYSENTER_CS               = 0x0000482A,
    GUEST_PREEMPTION_TIMER          = 0x0000482e,
    HOST_SYSENTER_CS                = 0x00004c00,
    CR0_GUEST_HOST_MASK             = 0x00006000,
    CR4_GUEST_HOST_MASK             = 0x00006002,
    CR0_READ_SHADOW                 = 0x00006004,
    CR4_READ_SHADOW                 = 0x00006006,
    CR3_TARGET_VALUE0               = 0x00006008,
    CR3_TARGET_VALUE1               = 0x0000600a,
    CR3_TARGET_VALUE2               = 0x0000600c,
    CR3_TARGET_VALUE3               = 0x0000600e,
    EXIT_QUALIFICATION              = 0x00006400,
    GUEST_LINEAR_ADDRESS            = 0x0000640a,
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
    GUEST_RSP                       = 0x0000681c,
    GUEST_RIP                       = 0x0000681e,
    GUEST_RFLAGS                    = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822,
    GUEST_SYSENTER_ESP              = 0x00006824,
    GUEST_SYSENTER_EIP              = 0x00006826,
    HOST_CR0                        = 0x00006c00,
    HOST_CR3                        = 0x00006c02,
    HOST_CR4                        = 0x00006c04,
    HOST_FS_BASE                    = 0x00006c06,
    HOST_GS_BASE                    = 0x00006c08,
    HOST_TR_BASE                    = 0x00006c0a,
    HOST_GDTR_BASE                  = 0x00006c0c,
    HOST_IDTR_BASE                  = 0x00006c0e,
    HOST_SYSENTER_ESP               = 0x00006c10,
    HOST_SYSENTER_EIP               = 0x00006c12,
    HOST_RSP                        = 0x00006c14,
    HOST_RIP                        = 0x00006c16,
};

/*
 * A set of MSR-s that need to be enabled for memory introspection
 * to work.
 */
extern const u32 vmx_introspection_force_enabled_msrs[];
extern const unsigned int vmx_introspection_force_enabled_msrs_size;

#define VMCS_VPID_WIDTH 16

#define MSR_TYPE_R 1
#define MSR_TYPE_W 2
void vmx_disable_intercept_for_msr(struct vcpu *v, u32 msr, int type);
void vmx_enable_intercept_for_msr(struct vcpu *v, u32 msr, int type);
int vmx_read_guest_msr(u32 msr, u64 *val);
int vmx_write_guest_msr(u32 msr, u64 val);
int vmx_add_guest_msr(u32 msr);
int vmx_add_host_load_msr(u32 msr);
void vmx_vmcs_switch(struct vmcs_struct *from, struct vmcs_struct *to);
void vmx_set_eoi_exit_bitmap(struct vcpu *v, u8 vector);
void vmx_clear_eoi_exit_bitmap(struct vcpu *v, u8 vector);
int vmx_check_msr_bitmap(unsigned long *msr_bitmap, u32 msr, int access_type);
void virtual_vmcs_enter(void *vvmcs);
void virtual_vmcs_exit(void *vvmcs);
u64 virtual_vmcs_vmread(void *vvmcs, u32 vmcs_encoding);
void virtual_vmcs_vmwrite(void *vvmcs, u32 vmcs_encoding, u64 val);

DECLARE_PER_CPU(bool_t, vmxon);

#endif /* ASM_X86_HVM_VMX_VMCS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
