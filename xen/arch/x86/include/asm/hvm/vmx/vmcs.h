/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmcs.h: VMCS related definitions
 * Copyright (c) 2004, Intel Corporation.
 *
 */
#ifndef __ASM_X86_HVM_VMX_VMCS_H__
#define __ASM_X86_HVM_VMX_VMCS_H__

#include <xen/mm.h>

extern void vmcs_dump_vcpu(struct vcpu *v);
extern int vmx_vmcs_init(void);
int cf_check vmx_cpu_up_prepare(unsigned int cpu);
void cf_check vmx_cpu_dead(unsigned int cpu);
int cf_check vmx_cpu_up(void);
void cf_check vmx_cpu_down(void);

struct vmcs_struct {
    u32 vmcs_revision_id;
    unsigned char data [0]; /* vmcs size is read from MSR */
};

struct vmx_msr_entry {
    u32 index;
    u32 mbz;
    u64 data;
};

#define EPT_DEFAULT_MT      X86_MT_WB

struct ept_data {
    union {
        struct {
            uint64_t mt:3,   /* Memory Type. */
                     wl:3,   /* Walk length -1. */
                     ad:1,   /* Enable EPT A/D bits. */
                     :5,     /* rsvd. */
                     mfn:52;
        };
        u64 eptp;
    };
    /* Set of PCPUs needing an INVEPT before a VMENTER. */
    cpumask_var_t invalidate;
};

#define _VMX_DOMAIN_PML_ENABLED    0
#define VMX_DOMAIN_PML_ENABLED     (1ul << _VMX_DOMAIN_PML_ENABLED)
struct vmx_domain {
    mfn_t apic_access_mfn;
    /* VMX_DOMAIN_* */
    unsigned int status;

    /*
     * Domain permitted to use Executable EPT Superpages?  Cleared to work
     * around CVE-2018-12207 as appropriate.
     */
    bool exec_sp;
};

/*
 * Layout of the MSR bitmap, as interpreted by hardware:
 *  - *_low  covers MSRs 0 to 0x1fff
 *  - *_ligh covers MSRs 0xc0000000 to 0xc0001fff
 */
struct vmx_msr_bitmap {
    unsigned long read_low  [0x2000 / BITS_PER_LONG];
    unsigned long read_high [0x2000 / BITS_PER_LONG];
    unsigned long write_low [0x2000 / BITS_PER_LONG];
    unsigned long write_high[0x2000 / BITS_PER_LONG];
};

struct pi_desc {
    DECLARE_BITMAP(pir, X86_NR_VECTORS);
    union {
        struct {
            u16     on     : 1,  /* bit 256 - Outstanding Notification */
                    sn     : 1,  /* bit 257 - Suppress Notification */
                    rsvd_1 : 14; /* bit 271:258 - Reserved */
            u8      nv;          /* bit 279:272 - Notification Vector */
            u8      rsvd_2;      /* bit 287:280 - Reserved */
            u32     ndst;        /* bit 319:288 - Notification Destination */
        };
        u64 control;
    };
    u32 rsvd[6];
} __attribute__ ((aligned (64)));

#define NR_PML_ENTRIES   512

struct pi_blocking_vcpu {
    struct list_head     list;
    spinlock_t           *lock;
};

struct vmx_vcpu {
    /* Physical address of VMCS. */
    paddr_t              vmcs_pa;
    /* VMCS shadow machine address. */
    paddr_t              vmcs_shadow_maddr;

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
    uint64_t             tertiary_exec_control;
    u32                  exception_bitmap;

    uint64_t             shadow_gs;
    uint64_t             star;
    uint64_t             lstar;
    uint64_t             cstar;
    uint64_t             sfmask;

    struct vmx_msr_bitmap *msr_bitmap;

    /*
     * Most accesses to the MSR host/guest load/save lists are in current
     * context.  However, the data can be modified by toolstack/migration
     * actions.  Remote access is only permitted for paused vcpus, and is
     * protected under the domctl lock.
     */
    struct vmx_msr_entry *msr_area;
    struct vmx_msr_entry *host_msr_area;
    unsigned int         msr_load_count;
    unsigned int         msr_save_count;
    unsigned int         host_msr_count;

    unsigned long        eoi_exitmap_changed;
    DECLARE_BITMAP(eoi_exit_bitmap, X86_NR_VECTORS);
    struct pi_desc       pi_desc;

    unsigned long        host_cr0;

    /* Do we need to tolerate a spurious EPT_MISCONFIG VM exit? */
    bool                 ept_spurious_misconfig;

    /* Processor Trace configured and enabled for the vcpu. */
    bool                 ipt_active;

    /* Is the guest in real mode? */
    uint8_t              vmx_realmode;
    /* Are we emulating rather than VMENTERing? */
    uint8_t              vmx_emulate;

    uint8_t              lbr_flags;

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

    struct page_info     *pml_pg;

    /* Bitmask of trapped CR4 bits. */
    unsigned long        cr4_host_mask;

    /*
     * Before it is blocked, vCPU is added to the per-cpu list.
     * VT-d engine can send wakeup notification event to the
     * pCPU and wakeup the related vCPU.
     */
    struct pi_blocking_vcpu pi_blocking;
};

int vmx_create_vmcs(struct vcpu *v);
void vmx_destroy_vmcs(struct vcpu *v);
void vmx_vmcs_enter(struct vcpu *v);
bool __must_check vmx_vmcs_try_enter(struct vcpu *v);
void vmx_vmcs_exit(struct vcpu *v);
void vmx_vmcs_reload(struct vcpu *v);

#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004U
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008U
#define CPU_BASED_HLT_EXITING                 0x00000080U
#define CPU_BASED_INVLPG_EXITING              0x00000200U
#define CPU_BASED_MWAIT_EXITING               0x00000400U
#define CPU_BASED_RDPMC_EXITING               0x00000800U
#define CPU_BASED_RDTSC_EXITING               0x00001000U
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000U
#define CPU_BASED_CR3_STORE_EXITING           0x00010000U
#define CPU_BASED_ACTIVATE_TERTIARY_CONTROLS  0x00020000U
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000U
#define CPU_BASED_CR8_STORE_EXITING           0x00100000U
#define CPU_BASED_TPR_SHADOW                  0x00200000U
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000U
#define CPU_BASED_MOV_DR_EXITING              0x00800000U
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000U
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000U
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000U
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000U
#define CPU_BASED_MONITOR_EXITING             0x20000000U
#define CPU_BASED_PAUSE_EXITING               0x40000000U
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000U
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

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001U
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002U
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004U
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008U
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010U
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020U
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040U
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080U
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100U
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200U
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400U
#define SECONDARY_EXEC_ENABLE_INVPCID           0x00001000U
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS      0x00002000U
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING    0x00004000U
#define SECONDARY_EXEC_ENABLE_PML               0x00020000U
#define SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS   0x00040000U
#define SECONDARY_EXEC_XSAVES                   0x00100000U
#define SECONDARY_EXEC_TSC_SCALING              0x02000000U
#define SECONDARY_EXEC_BUS_LOCK_DETECTION       0x40000000U
#define SECONDARY_EXEC_NOTIFY_VM_EXITING        0x80000000U
extern u32 vmx_secondary_exec_control;

#define TERTIARY_EXEC_LOADIWKEY_EXITING         BIT(0, UL)
#define TERTIARY_EXEC_ENABLE_HLAT               BIT(1, UL)
#define TERTIARY_EXEC_EPT_PAGING_WRITE          BIT(2, UL)
#define TERTIARY_EXEC_GUEST_PAGING_VERIFY       BIT(3, UL)
#define TERTIARY_EXEC_IPI_VIRT                  BIT(4, UL)
#define TERTIARY_EXEC_VIRT_SPEC_CTRL            BIT(7, UL)
extern uint64_t vmx_tertiary_exec_control;

#define cpu_has_vmx_virt_spec_ctrl \
     (vmx_tertiary_exec_control & TERTIARY_EXEC_VIRT_SPEC_CTRL)

#define VMX_EPT_EXEC_ONLY_SUPPORTED                         0x00000001
#define VMX_EPT_WALK_LENGTH_4_SUPPORTED                     0x00000040
#define VMX_EPT_MEMORY_TYPE_UC                              0x00000100
#define VMX_EPT_MEMORY_TYPE_WB                              0x00004000
#define VMX_EPT_SUPERPAGE_2MB                               0x00010000
#define VMX_EPT_SUPERPAGE_1GB                               0x00020000
#define VMX_EPT_INVEPT_INSTRUCTION                          0x00100000
#define VMX_EPT_AD_BIT                                      0x00200000
#define VMX_EPT_INVEPT_SINGLE_CONTEXT                       0x02000000
#define VMX_EPT_INVEPT_ALL_CONTEXT                          0x04000000
#define VMX_VPID_INVVPID_INSTRUCTION                     0x00100000000ULL
#define VMX_VPID_INVVPID_INDIVIDUAL_ADDR                 0x10000000000ULL
#define VMX_VPID_INVVPID_SINGLE_CONTEXT                  0x20000000000ULL
#define VMX_VPID_INVVPID_ALL_CONTEXT                     0x40000000000ULL
#define VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBAL 0x80000000000ULL
extern u64 vmx_ept_vpid_cap;

#define VMX_MISC_ACTIVITY_MASK                  0x000001c0
#define VMX_MISC_PROC_TRACE                     0x00004000
#define VMX_MISC_CR3_TARGET                     0x01ff0000
#define VMX_MISC_VMWRITE_ALL                    0x20000000

#define VMX_TSC_MULTIPLIER_MAX                  0xffffffffffffffffULL

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
#define cpu_has_vmx_tertiary_exec_control \
    (vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)
#define cpu_has_vmx_ept \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT)
#define cpu_has_vmx_dt_exiting \
    (vmx_secondary_exec_control & SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING)
#define cpu_has_vmx_rdtscp \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_RDTSCP)
#define cpu_has_vmx_vpid \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
#define cpu_has_monitor_trap_flag \
    (vmx_cpu_based_exec_control & CPU_BASED_MONITOR_TRAP_FLAG)
#define cpu_has_vmx_pat \
    (vmx_vmentry_control & VM_ENTRY_LOAD_GUEST_PAT)
#define cpu_has_vmx_efer \
    (vmx_vmentry_control & VM_ENTRY_LOAD_GUEST_EFER)
#define cpu_has_vmx_unrestricted_guest \
    (vmx_secondary_exec_control & SECONDARY_EXEC_UNRESTRICTED_GUEST)
#define vmx_unrestricted_guest(v)               \
    ((v)->arch.hvm.vmx.secondary_exec_control & \
     SECONDARY_EXEC_UNRESTRICTED_GUEST)
#define cpu_has_vmx_ple \
    (vmx_secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
#define cpu_has_vmx_invpcid \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_INVPCID)
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
#define cpu_has_vmx_vmfunc \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VM_FUNCTIONS)
#define cpu_has_vmx_virt_exceptions \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS)
#define cpu_has_vmx_pml \
    (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_PML)
#define cpu_has_vmx_mpx \
    ((vmx_vmexit_control & VM_EXIT_CLEAR_BNDCFGS) && \
     (vmx_vmentry_control & VM_ENTRY_LOAD_BNDCFGS))
#define cpu_has_vmx_xsaves \
    (vmx_secondary_exec_control & SECONDARY_EXEC_XSAVES)
#define cpu_has_vmx_tsc_scaling \
    (vmx_secondary_exec_control & SECONDARY_EXEC_TSC_SCALING)
#define cpu_has_vmx_bus_lock_detection \
    (vmx_secondary_exec_control & SECONDARY_EXEC_BUS_LOCK_DETECTION)
#define cpu_has_vmx_notify_vm_exiting \
    (vmx_secondary_exec_control & SECONDARY_EXEC_NOTIFY_VM_EXITING)

#define VMCS_RID_TYPE_MASK              0x80000000U

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

/* VMFUNC leaf definitions */
#define VMX_VMFUNC_EPTP_SWITCHING   (1ULL << 0)

/* VMCS field encodings. */
#define VMCS_HIGH(x) ((x) | 1)
enum vmcs_field {
    VIRTUAL_PROCESSOR_ID            = 0x00000000,
    POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
    EPTP_INDEX                      = 0x00000004,
#define GUEST_SEG_SELECTOR(sel) (GUEST_ES_SELECTOR + (sel) * 2) /* ES ... GS */
    GUEST_ES_SELECTOR               = 0x00000800,
    GUEST_CS_SELECTOR               = 0x00000802,
    GUEST_SS_SELECTOR               = 0x00000804,
    GUEST_DS_SELECTOR               = 0x00000806,
    GUEST_FS_SELECTOR               = 0x00000808,
    GUEST_GS_SELECTOR               = 0x0000080a,
    GUEST_LDTR_SELECTOR             = 0x0000080c,
    GUEST_TR_SELECTOR               = 0x0000080e,
    GUEST_INTR_STATUS               = 0x00000810,
    GUEST_PML_INDEX                 = 0x00000812,
    HOST_ES_SELECTOR                = 0x00000c00,
    HOST_CS_SELECTOR                = 0x00000c02,
    HOST_SS_SELECTOR                = 0x00000c04,
    HOST_DS_SELECTOR                = 0x00000c06,
    HOST_FS_SELECTOR                = 0x00000c08,
    HOST_GS_SELECTOR                = 0x00000c0a,
    HOST_TR_SELECTOR                = 0x00000c0c,
    IO_BITMAP_A                     = 0x00002000,
    IO_BITMAP_B                     = 0x00002002,
    MSR_BITMAP                      = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
    PML_ADDRESS                     = 0x0000200e,
    TSC_OFFSET                      = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,
    APIC_ACCESS_ADDR                = 0x00002014,
    PI_DESC_ADDR                    = 0x00002016,
    VM_FUNCTION_CONTROL             = 0x00002018,
    EPT_POINTER                     = 0x0000201a,
    EOI_EXIT_BITMAP0                = 0x0000201c,
#define EOI_EXIT_BITMAP(n) (EOI_EXIT_BITMAP0 + (n) * 2) /* n = 0...3 */
    EPTP_LIST_ADDR                  = 0x00002024,
    VMREAD_BITMAP                   = 0x00002026,
    VMWRITE_BITMAP                  = 0x00002028,
    VIRT_EXCEPTION_INFO             = 0x0000202a,
    XSS_EXIT_BITMAP                 = 0x0000202c,
    TSC_MULTIPLIER                  = 0x00002032,
    TERTIARY_VM_EXEC_CONTROL        = 0x00002034,
    SPEC_CTRL_MASK                  = 0x0000204a,
    SPEC_CTRL_SHADOW                = 0x0000204c,
    GUEST_PHYSICAL_ADDRESS          = 0x00002400,
    VMCS_LINK_POINTER               = 0x00002800,
    GUEST_IA32_DEBUGCTL             = 0x00002802,
    GUEST_PAT                       = 0x00002804,
    GUEST_EFER                      = 0x00002806,
    GUEST_PERF_GLOBAL_CTRL          = 0x00002808,
    GUEST_PDPTE0                    = 0x0000280a,
#define GUEST_PDPTE(n) (GUEST_PDPTE0 + (n) * 2) /* n = 0...3 */
    GUEST_BNDCFGS                   = 0x00002812,
    HOST_PAT                        = 0x00002c00,
    HOST_EFER                       = 0x00002c02,
    HOST_PERF_GLOBAL_CTRL           = 0x00002c04,
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
    NOTIFY_WINDOW                   = 0x00004024,
    VM_INSTRUCTION_ERROR            = 0x00004400,
    VM_EXIT_REASON                  = 0x00004402,
    VM_EXIT_INTR_INFO               = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
    IDT_VECTORING_INFO              = 0x00004408,
    IDT_VECTORING_ERROR_CODE        = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN         = 0x0000440c,
    VMX_INSTRUCTION_INFO            = 0x0000440e,
#define GUEST_SEG_LIMIT(sel) (GUEST_ES_LIMIT + (sel) * 2) /* ES ... GS */
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
#define GUEST_SEG_AR_BYTES(sel) (GUEST_ES_AR_BYTES + (sel) * 2) /* ES ... GS */
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
    GUEST_SMBASE                    = 0x00004828,
    GUEST_SYSENTER_CS               = 0x0000482a,
    GUEST_PREEMPTION_TIMER          = 0x0000482e,
    HOST_SYSENTER_CS                = 0x00004c00,
    CR0_GUEST_HOST_MASK             = 0x00006000,
    CR4_GUEST_HOST_MASK             = 0x00006002,
    CR0_READ_SHADOW                 = 0x00006004,
    CR4_READ_SHADOW                 = 0x00006006,
    CR3_TARGET_VALUE0               = 0x00006008,
#define CR3_TARGET_VALUE(n) (CR3_TARGET_VALUE0 + (n) * 2) /* n < CR3_TARGET_COUNT */
    EXIT_QUALIFICATION              = 0x00006400,
    GUEST_LINEAR_ADDRESS            = 0x0000640a,
    GUEST_CR0                       = 0x00006800,
    GUEST_CR3                       = 0x00006802,
    GUEST_CR4                       = 0x00006804,
#define GUEST_SEG_BASE(sel) (GUEST_ES_BASE + (sel) * 2) /* ES ... GS */
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

#define VMCS_VPID_WIDTH 16

/* VM Instruction error numbers */
enum vmx_insn_errno
{
    VMX_INSN_SUCCEED                       = 0,
    VMX_INSN_VMCLEAR_INVALID_PHYADDR       = 2,
    VMX_INSN_VMCLEAR_WITH_VMXON_PTR        = 3,
    VMX_INSN_VMLAUNCH_NONCLEAR_VMCS        = 4,
    VMX_INSN_VMRESUME_NONLAUNCHED_VMCS     = 5,
    VMX_INSN_INVALID_CONTROL_STATE         = 7,
    VMX_INSN_INVALID_HOST_STATE            = 8,
    VMX_INSN_VMPTRLD_INVALID_PHYADDR       = 9,
    VMX_INSN_VMPTRLD_WITH_VMXON_PTR        = 10,
    VMX_INSN_VMPTRLD_INCORRECT_VMCS_ID     = 11,
    VMX_INSN_UNSUPPORTED_VMCS_COMPONENT    = 12,
    VMX_INSN_VMXON_IN_VMX_ROOT             = 15,
    VMX_INSN_VMENTRY_BLOCKED_BY_MOV_SS     = 26,
    VMX_INSN_INVEPT_INVVPID_INVALID_OP     = 28,
    VMX_INSN_FAIL_INVALID                  = ~0,
};

/* MSR load/save list infrastructure. */
enum vmx_msr_list_type {
    VMX_MSR_HOST,           /* MSRs loaded on VMExit.                   */
    VMX_MSR_GUEST,          /* MSRs saved on VMExit, loaded on VMEntry. */
    VMX_MSR_GUEST_LOADONLY, /* MSRs loaded on VMEntry only.             */
};

/**
 * Add an MSR to an MSR list (inserting space for the entry if necessary), and
 * set the MSRs value.
 *
 * It is undefined behaviour to try and insert the same MSR into both the
 * GUEST and GUEST_LOADONLY list.
 *
 * May fail if unable to allocate memory for the list, or the total number of
 * entries exceeds the memory allocated.
 */
int vmx_add_msr(struct vcpu *v, uint32_t msr, uint64_t val,
                enum vmx_msr_list_type type);

/**
 * Remove an MSR entry from an MSR list.  Returns -ESRCH if the MSR was not
 * found in the list.
 */
int vmx_del_msr(struct vcpu *v, uint32_t msr, enum vmx_msr_list_type type);

static inline int vmx_add_guest_msr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    return vmx_add_msr(v, msr, val, VMX_MSR_GUEST);
}
static inline int vmx_add_host_load_msr(struct vcpu *v, uint32_t msr,
                                        uint64_t val)
{
    return vmx_add_msr(v, msr, val, VMX_MSR_HOST);
}

struct vmx_msr_entry *vmx_find_msr(const struct vcpu *v, uint32_t msr,
                                   enum vmx_msr_list_type type);

static inline int vmx_read_guest_msr(const struct vcpu *v, uint32_t msr,
                                     uint64_t *val)
{
    const struct vmx_msr_entry *ent = vmx_find_msr(v, msr, VMX_MSR_GUEST);

    if ( !ent )
    {
        *val = 0;
        return -ESRCH;
    }

    *val = ent->data;

    return 0;
}

static inline int vmx_read_guest_loadonly_msr(
    const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    const struct vmx_msr_entry *ent =
        vmx_find_msr(v, msr, VMX_MSR_GUEST_LOADONLY);

    if ( !ent )
    {
        *val = 0;
        return -ESRCH;
    }

    *val = ent->data;

    return 0;
}

static inline int vmx_write_guest_msr(struct vcpu *v, uint32_t msr,
                                      uint64_t val)
{
    struct vmx_msr_entry *ent = vmx_find_msr(v, msr, VMX_MSR_GUEST);

    if ( !ent )
        return -ESRCH;

    ent->data = val;

    return 0;
}


/* MSR intercept bitmap infrastructure. */
enum vmx_msr_intercept_type {
    VMX_MSR_R  = 1,
    VMX_MSR_W  = 2,
    VMX_MSR_RW = VMX_MSR_R | VMX_MSR_W,
};

void vmx_clear_msr_intercept(struct vcpu *v, unsigned int msr,
                             enum vmx_msr_intercept_type type);
void vmx_set_msr_intercept(struct vcpu *v, unsigned int msr,
                           enum vmx_msr_intercept_type type);
void vmx_vmcs_switch(paddr_t from, paddr_t to);
void vmx_set_eoi_exit_bitmap(struct vcpu *v, u8 vector);
void vmx_clear_eoi_exit_bitmap(struct vcpu *v, u8 vector);
bool vmx_msr_is_intercepted(struct vmx_msr_bitmap *msr_bitmap,
                            unsigned int msr, bool is_write) __nonnull(1);
void virtual_vmcs_enter(const struct vcpu *);
void virtual_vmcs_exit(const struct vcpu *);
u64 virtual_vmcs_vmread(const struct vcpu *, u32 encoding);
enum vmx_insn_errno virtual_vmcs_vmread_safe(const struct vcpu *v,
                                             u32 vmcs_encoding, u64 *val);
void virtual_vmcs_vmwrite(const struct vcpu *, u32 encoding, u64 val);
enum vmx_insn_errno virtual_vmcs_vmwrite_safe(const struct vcpu *v,
                                              u32 vmcs_encoding, u64 val);

DECLARE_PER_CPU(bool, vmxon);

bool vmx_vcpu_pml_enabled(const struct vcpu *v);
int vmx_vcpu_enable_pml(struct vcpu *v);
void vmx_vcpu_disable_pml(struct vcpu *v);
void vmx_vcpu_flush_pml_buffer(struct vcpu *v);
bool vmx_domain_pml_enabled(const struct domain *d);
int vmx_domain_enable_pml(struct domain *d);
void vmx_domain_disable_pml(struct domain *d);
void vmx_domain_flush_pml_buffers(struct domain *d);

void vmx_domain_update_eptp(struct domain *d);

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
