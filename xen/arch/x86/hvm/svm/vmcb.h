/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SVM_PRIVATE_VMCB_H
#define SVM_PRIVATE_VMCB_H

#include <xen/types.h>

#include <asm/x86-types.h>

struct vcpu;

enum GenericIntercept1bits
{
    GENERAL1_INTERCEPT_INTR          = 1 << 0,
    GENERAL1_INTERCEPT_NMI           = 1 << 1,
    GENERAL1_INTERCEPT_SMI           = 1 << 2,
    GENERAL1_INTERCEPT_INIT          = 1 << 3,
    GENERAL1_INTERCEPT_VINTR         = 1 << 4,
    GENERAL1_INTERCEPT_CR0_SEL_WRITE = 1 << 5,
    GENERAL1_INTERCEPT_IDTR_READ     = 1 << 6,
    GENERAL1_INTERCEPT_GDTR_READ     = 1 << 7,
    GENERAL1_INTERCEPT_LDTR_READ     = 1 << 8,
    GENERAL1_INTERCEPT_TR_READ       = 1 << 9,
    GENERAL1_INTERCEPT_IDTR_WRITE    = 1 << 10,
    GENERAL1_INTERCEPT_GDTR_WRITE    = 1 << 11,
    GENERAL1_INTERCEPT_LDTR_WRITE    = 1 << 12,
    GENERAL1_INTERCEPT_TR_WRITE      = 1 << 13,
    GENERAL1_INTERCEPT_RDTSC         = 1 << 14,
    GENERAL1_INTERCEPT_RDPMC         = 1 << 15,
    GENERAL1_INTERCEPT_PUSHF         = 1 << 16,
    GENERAL1_INTERCEPT_POPF          = 1 << 17,
    GENERAL1_INTERCEPT_CPUID         = 1 << 18,
    GENERAL1_INTERCEPT_RSM           = 1 << 19,
    GENERAL1_INTERCEPT_IRET          = 1 << 20,
    GENERAL1_INTERCEPT_SWINT         = 1 << 21,
    GENERAL1_INTERCEPT_INVD          = 1 << 22,
    GENERAL1_INTERCEPT_PAUSE         = 1 << 23,
    GENERAL1_INTERCEPT_HLT           = 1 << 24,
    GENERAL1_INTERCEPT_INVLPG        = 1 << 25,
    GENERAL1_INTERCEPT_INVLPGA       = 1 << 26,
    GENERAL1_INTERCEPT_IOIO_PROT     = 1 << 27,
    GENERAL1_INTERCEPT_MSR_PROT      = 1 << 28,
    GENERAL1_INTERCEPT_TASK_SWITCH   = 1 << 29,
    GENERAL1_INTERCEPT_FERR_FREEZE   = 1 << 30,
    GENERAL1_INTERCEPT_SHUTDOWN_EVT  = 1u << 31
};

enum GenericIntercept2bits
{
    GENERAL2_INTERCEPT_VMRUN   = 1 << 0,
    GENERAL2_INTERCEPT_VMMCALL = 1 << 1,
    GENERAL2_INTERCEPT_VMLOAD  = 1 << 2,
    GENERAL2_INTERCEPT_VMSAVE  = 1 << 3,
    GENERAL2_INTERCEPT_STGI    = 1 << 4,
    GENERAL2_INTERCEPT_CLGI    = 1 << 5,
    GENERAL2_INTERCEPT_SKINIT  = 1 << 6,
    GENERAL2_INTERCEPT_RDTSCP  = 1 << 7,
    GENERAL2_INTERCEPT_ICEBP   = 1 << 8,
    GENERAL2_INTERCEPT_WBINVD  = 1 << 9,
    GENERAL2_INTERCEPT_MONITOR = 1 << 10,
    GENERAL2_INTERCEPT_MWAIT   = 1 << 11,
    GENERAL2_INTERCEPT_MWAIT_CONDITIONAL = 1 << 12,
    GENERAL2_INTERCEPT_XSETBV  = 1 << 13,
    GENERAL2_INTERCEPT_RDPRU   = 1 << 14,
};

enum GenericIntercept3bits
{
    GENERAL3_INTERCEPT_BUS_LOCK = 1 << 5,
};

enum CRInterceptBits
{
    CR_INTERCEPT_CR0_READ   = 1 << 0,
    CR_INTERCEPT_CR1_READ   = 1 << 1,
    CR_INTERCEPT_CR2_READ   = 1 << 2,
    CR_INTERCEPT_CR3_READ   = 1 << 3,
    CR_INTERCEPT_CR4_READ   = 1 << 4,
    CR_INTERCEPT_CR5_READ   = 1 << 5,
    CR_INTERCEPT_CR6_READ   = 1 << 6,
    CR_INTERCEPT_CR7_READ   = 1 << 7,
    CR_INTERCEPT_CR8_READ   = 1 << 8,
    CR_INTERCEPT_CR9_READ   = 1 << 9,
    CR_INTERCEPT_CR10_READ  = 1 << 10,
    CR_INTERCEPT_CR11_READ  = 1 << 11,
    CR_INTERCEPT_CR12_READ  = 1 << 12,
    CR_INTERCEPT_CR13_READ  = 1 << 13,
    CR_INTERCEPT_CR14_READ  = 1 << 14,
    CR_INTERCEPT_CR15_READ  = 1 << 15,
    CR_INTERCEPT_CR0_WRITE  = 1 << 16,
    CR_INTERCEPT_CR1_WRITE  = 1 << 17,
    CR_INTERCEPT_CR2_WRITE  = 1 << 18,
    CR_INTERCEPT_CR3_WRITE  = 1 << 19,
    CR_INTERCEPT_CR4_WRITE  = 1 << 20,
    CR_INTERCEPT_CR5_WRITE  = 1 << 21,
    CR_INTERCEPT_CR6_WRITE  = 1 << 22,
    CR_INTERCEPT_CR7_WRITE  = 1 << 23,
    CR_INTERCEPT_CR8_WRITE  = 1 << 24,
    CR_INTERCEPT_CR9_WRITE  = 1 << 25,
    CR_INTERCEPT_CR10_WRITE = 1 << 26,
    CR_INTERCEPT_CR11_WRITE = 1 << 27,
    CR_INTERCEPT_CR12_WRITE = 1 << 28,
    CR_INTERCEPT_CR13_WRITE = 1 << 29,
    CR_INTERCEPT_CR14_WRITE = 1 << 30,
    CR_INTERCEPT_CR15_WRITE = 1u << 31,
};

enum DRInterceptBits
{
    DR_INTERCEPT_DR0_READ   = 1 << 0,
    DR_INTERCEPT_DR1_READ   = 1 << 1,
    DR_INTERCEPT_DR2_READ   = 1 << 2,
    DR_INTERCEPT_DR3_READ   = 1 << 3,
    DR_INTERCEPT_DR4_READ   = 1 << 4,
    DR_INTERCEPT_DR5_READ   = 1 << 5,
    DR_INTERCEPT_DR6_READ   = 1 << 6,
    DR_INTERCEPT_DR7_READ   = 1 << 7,
    DR_INTERCEPT_DR8_READ   = 1 << 8,
    DR_INTERCEPT_DR9_READ   = 1 << 9,
    DR_INTERCEPT_DR10_READ  = 1 << 10,
    DR_INTERCEPT_DR11_READ  = 1 << 11,
    DR_INTERCEPT_DR12_READ  = 1 << 12,
    DR_INTERCEPT_DR13_READ  = 1 << 13,
    DR_INTERCEPT_DR14_READ  = 1 << 14,
    DR_INTERCEPT_DR15_READ  = 1 << 15,
    DR_INTERCEPT_DR0_WRITE  = 1 << 16,
    DR_INTERCEPT_DR1_WRITE  = 1 << 17,
    DR_INTERCEPT_DR2_WRITE  = 1 << 18,
    DR_INTERCEPT_DR3_WRITE  = 1 << 19,
    DR_INTERCEPT_DR4_WRITE  = 1 << 20,
    DR_INTERCEPT_DR5_WRITE  = 1 << 21,
    DR_INTERCEPT_DR6_WRITE  = 1 << 22,
    DR_INTERCEPT_DR7_WRITE  = 1 << 23,
    DR_INTERCEPT_DR8_WRITE  = 1 << 24,
    DR_INTERCEPT_DR9_WRITE  = 1 << 25,
    DR_INTERCEPT_DR10_WRITE = 1 << 26,
    DR_INTERCEPT_DR11_WRITE = 1 << 27,
    DR_INTERCEPT_DR12_WRITE = 1 << 28,
    DR_INTERCEPT_DR13_WRITE = 1 << 29,
    DR_INTERCEPT_DR14_WRITE = 1 << 30,
    DR_INTERCEPT_DR15_WRITE = 1u << 31,
};

enum VMEXIT_EXITCODE
{
    /* control register read exitcodes */
    VMEXIT_CR0_READ    =   0, /* 0x0 */
    VMEXIT_CR1_READ    =   1, /* 0x1 */
    VMEXIT_CR2_READ    =   2, /* 0x2 */
    VMEXIT_CR3_READ    =   3, /* 0x3 */
    VMEXIT_CR4_READ    =   4, /* 0x4 */
    VMEXIT_CR5_READ    =   5, /* 0x5 */
    VMEXIT_CR6_READ    =   6, /* 0x6 */
    VMEXIT_CR7_READ    =   7, /* 0x7 */
    VMEXIT_CR8_READ    =   8, /* 0x8 */
    VMEXIT_CR9_READ    =   9, /* 0x9 */
    VMEXIT_CR10_READ   =  10, /* 0xa */
    VMEXIT_CR11_READ   =  11, /* 0xb */
    VMEXIT_CR12_READ   =  12, /* 0xc */
    VMEXIT_CR13_READ   =  13, /* 0xd */
    VMEXIT_CR14_READ   =  14, /* 0xe */
    VMEXIT_CR15_READ   =  15, /* 0xf */

    /* control register write exitcodes */
    VMEXIT_CR0_WRITE   =  16, /* 0x10 */
    VMEXIT_CR1_WRITE   =  17, /* 0x11 */
    VMEXIT_CR2_WRITE   =  18, /* 0x12 */
    VMEXIT_CR3_WRITE   =  19, /* 0x13 */
    VMEXIT_CR4_WRITE   =  20, /* 0x14 */
    VMEXIT_CR5_WRITE   =  21, /* 0x15 */
    VMEXIT_CR6_WRITE   =  22, /* 0x16 */
    VMEXIT_CR7_WRITE   =  23, /* 0x17 */
    VMEXIT_CR8_WRITE   =  24, /* 0x18 */
    VMEXIT_CR9_WRITE   =  25, /* 0x19 */
    VMEXIT_CR10_WRITE  =  26, /* 0x1a */
    VMEXIT_CR11_WRITE  =  27, /* 0x1b */
    VMEXIT_CR12_WRITE  =  28, /* 0x1c */
    VMEXIT_CR13_WRITE  =  29, /* 0x1d */
    VMEXIT_CR14_WRITE  =  30, /* 0x1e */
    VMEXIT_CR15_WRITE  =  31, /* 0x1f */

    /* debug register read exitcodes */
    VMEXIT_DR0_READ    =  32, /* 0x20 */
    VMEXIT_DR1_READ    =  33, /* 0x21 */
    VMEXIT_DR2_READ    =  34, /* 0x22 */
    VMEXIT_DR3_READ    =  35, /* 0x23 */
    VMEXIT_DR4_READ    =  36, /* 0x24 */
    VMEXIT_DR5_READ    =  37, /* 0x25 */
    VMEXIT_DR6_READ    =  38, /* 0x26 */
    VMEXIT_DR7_READ    =  39, /* 0x27 */
    VMEXIT_DR8_READ    =  40, /* 0x28 */
    VMEXIT_DR9_READ    =  41, /* 0x29 */
    VMEXIT_DR10_READ   =  42, /* 0x2a */
    VMEXIT_DR11_READ   =  43, /* 0x2b */
    VMEXIT_DR12_READ   =  44, /* 0x2c */
    VMEXIT_DR13_READ   =  45, /* 0x2d */
    VMEXIT_DR14_READ   =  46, /* 0x2e */
    VMEXIT_DR15_READ   =  47, /* 0x2f */

    /* debug register write exitcodes */
    VMEXIT_DR0_WRITE   =  48, /* 0x30 */
    VMEXIT_DR1_WRITE   =  49, /* 0x31 */
    VMEXIT_DR2_WRITE   =  50, /* 0x32 */
    VMEXIT_DR3_WRITE   =  51, /* 0x33 */
    VMEXIT_DR4_WRITE   =  52, /* 0x34 */
    VMEXIT_DR5_WRITE   =  53, /* 0x35 */
    VMEXIT_DR6_WRITE   =  54, /* 0x36 */
    VMEXIT_DR7_WRITE   =  55, /* 0x37 */
    VMEXIT_DR8_WRITE   =  56, /* 0x38 */
    VMEXIT_DR9_WRITE   =  57, /* 0x39 */
    VMEXIT_DR10_WRITE  =  58, /* 0x3a */
    VMEXIT_DR11_WRITE  =  59, /* 0x3b */
    VMEXIT_DR12_WRITE  =  60, /* 0x3c */
    VMEXIT_DR13_WRITE  =  61, /* 0x3d */
    VMEXIT_DR14_WRITE  =  62, /* 0x3e */
    VMEXIT_DR15_WRITE  =  63, /* 0x3f */

    /* processor exception exitcodes (VMEXIT_EXCP[0-31]) */
    VMEXIT_EXCEPTION_DE  =  64, /* 0x40, divide-by-zero-error */
    VMEXIT_EXCEPTION_DB  =  65, /* 0x41, debug */
    VMEXIT_EXCEPTION_NMI =  66, /* 0x42, non-maskable-interrupt */
    VMEXIT_EXCEPTION_BP  =  67, /* 0x43, breakpoint */
    VMEXIT_EXCEPTION_OF  =  68, /* 0x44, overflow */
    VMEXIT_EXCEPTION_BR  =  69, /* 0x45, bound-range */
    VMEXIT_EXCEPTION_UD  =  70, /* 0x46, invalid-opcode*/
    VMEXIT_EXCEPTION_NM  =  71, /* 0x47, device-not-available */
    VMEXIT_EXCEPTION_DF  =  72, /* 0x48, double-fault */
    VMEXIT_EXCEPTION_09  =  73, /* 0x49, unsupported (reserved) */
    VMEXIT_EXCEPTION_TS  =  74, /* 0x4a, invalid-tss */
    VMEXIT_EXCEPTION_NP  =  75, /* 0x4b, segment-not-present */
    VMEXIT_EXCEPTION_SS  =  76, /* 0x4c, stack */
    VMEXIT_EXCEPTION_GP  =  77, /* 0x4d, general-protection */
    VMEXIT_EXCEPTION_PF  =  78, /* 0x4e, page-fault */
    VMEXIT_EXCEPTION_15  =  79, /* 0x4f, reserved */
    VMEXIT_EXCEPTION_MF  =  80, /* 0x50, x87 floating-point exception-pending */
    VMEXIT_EXCEPTION_AC  =  81, /* 0x51, alignment-check */
    VMEXIT_EXCEPTION_MC  =  82, /* 0x52, machine-check */
    VMEXIT_EXCEPTION_XF  =  83, /* 0x53, simd floating-point */
/*  VMEXIT_EXCEPTION_20  =  84,    0x54, #VE (Intel specific) */
    VMEXIT_EXCEPTION_CP  =  85, /* 0x55, controlflow protection */

    /* exceptions 20-31 (exitcodes 84-95) are reserved */

    /* ...and the rest of the #VMEXITs */
    VMEXIT_INTR             =  96, /* 0x60 */
    VMEXIT_NMI              =  97, /* 0x61 */
    VMEXIT_SMI              =  98, /* 0x62 */
    VMEXIT_INIT             =  99, /* 0x63 */
    VMEXIT_VINTR            = 100, /* 0x64 */
    VMEXIT_CR0_SEL_WRITE    = 101, /* 0x65 */
    VMEXIT_IDTR_READ        = 102, /* 0x66 */
    VMEXIT_GDTR_READ        = 103, /* 0x67 */
    VMEXIT_LDTR_READ        = 104, /* 0x68 */
    VMEXIT_TR_READ          = 105, /* 0x69 */
    VMEXIT_IDTR_WRITE       = 106, /* 0x6a */
    VMEXIT_GDTR_WRITE       = 107, /* 0x6b */
    VMEXIT_LDTR_WRITE       = 108, /* 0x6c */
    VMEXIT_TR_WRITE         = 109, /* 0x6d */
    VMEXIT_RDTSC            = 110, /* 0x6e */
    VMEXIT_RDPMC            = 111, /* 0x6f */
    VMEXIT_PUSHF            = 112, /* 0x70 */
    VMEXIT_POPF             = 113, /* 0x71 */
    VMEXIT_CPUID            = 114, /* 0x72 */
    VMEXIT_RSM              = 115, /* 0x73 */
    VMEXIT_IRET             = 116, /* 0x74 */
    VMEXIT_SWINT            = 117, /* 0x75 */
    VMEXIT_INVD             = 118, /* 0x76 */
    VMEXIT_PAUSE            = 119, /* 0x77 */
    VMEXIT_HLT              = 120, /* 0x78 */
    VMEXIT_INVLPG           = 121, /* 0x79 */
    VMEXIT_INVLPGA          = 122, /* 0x7a */
    VMEXIT_IOIO             = 123, /* 0x7b */
    VMEXIT_MSR              = 124, /* 0x7c */
    VMEXIT_TASK_SWITCH      = 125, /* 0x7d */
    VMEXIT_FERR_FREEZE      = 126, /* 0x7e */
    VMEXIT_SHUTDOWN         = 127, /* 0x7f */
    VMEXIT_VMRUN            = 128, /* 0x80 */
    VMEXIT_VMMCALL          = 129, /* 0x81 */
    VMEXIT_VMLOAD           = 130, /* 0x82 */
    VMEXIT_VMSAVE           = 131, /* 0x83 */
    VMEXIT_STGI             = 132, /* 0x84 */
    VMEXIT_CLGI             = 133, /* 0x85 */
    VMEXIT_SKINIT           = 134, /* 0x86 */
    VMEXIT_RDTSCP           = 135, /* 0x87 */
    VMEXIT_ICEBP            = 136, /* 0x88 */
    VMEXIT_WBINVD           = 137, /* 0x89 */
    VMEXIT_MONITOR          = 138, /* 0x8a */
    VMEXIT_MWAIT            = 139, /* 0x8b */
    VMEXIT_MWAIT_CONDITIONAL= 140, /* 0x8c */
    VMEXIT_XSETBV           = 141, /* 0x8d */
    VMEXIT_RDPRU            = 142, /* 0x8e */
    VMEXIT_BUS_LOCK         = 165, /* 0xa5 */
    /* Remember to also update VMEXIT_NPF_PERFC! */
    VMEXIT_NPF              = 1024, /* 0x400, nested paging fault */
    /* Remember to also update SVM_PERF_EXIT_REASON_SIZE! */
    VMEXIT_INVALID          =  -1
};

enum
{
    /* Available on all SVM-capable hardware. */
    TLB_CTRL_NO_FLUSH             = 0,
    TLB_CTRL_FLUSH_ALL            = 1,

    /* Available with the FlushByASID feature. */
    TLB_CTRL_FLUSH_ASID           = 3,
    TLB_CTRL_FLUSH_ASID_NONGLOBAL = 7,
};

typedef union
{
    struct
    {
        uint8_t  vector;
        uint8_t  type:3;
        bool     ev:1;
        uint32_t resvd1:19;
        bool     v:1;
        uint32_t ec;
    };
    uint64_t raw;
} intinfo_t;

typedef union {
    struct {
        bool intr_shadow:    1;
        bool guest_intr_mask:1;
    };
    uint64_t raw;
} intstat_t;

typedef union {
    struct {          /* Cleanbit.tpr(3),  APM Name */
        uint8_t tpr;                /* c   V_TPR */
        bool    intr_pending:1;     /* c   V_IRQ */
        bool    gif:1;              /*     VGIF */
        bool    :1;
        bool    nmi_pending:1;      /* c   V_NMI */
        bool    nmi_blocked:1;      /* c   V_NMI_MASK */
        uint8_t :3;
        uint8_t intr_prio:4;        /* c   V_INTR_PRIO */
        bool    ign_tpr:1;          /* c   V_IGN_TPR */
        uint8_t :3;
        bool    vintr_masking:1;    /* c   V_INTR_MASKING */
        bool    vgif_en:1;          /*     VGIF_EN */
        bool    vnmi_en:1;          /*     V_NMI_ENABLE */
        uint8_t :5;
        uint8_t vector;             /* c   V_INTR_VECTOR */
    };
    uint64_t raw;
} vintr_t;

typedef union
{
    struct
    {
        bool lbr_en:1;
        bool vloadsave_en:1;
    };
    uint64_t raw;
} virt_ext_t;

typedef union
{
    struct {
        bool intercepts:1; /* 0:  cr/dr/exception/general intercepts,
                            *     pause_filter_count, tsc_offset */
        bool iopm:1;       /* 1:  iopm_base_pa, msrpm_base_pa */
        bool asid:1;       /* 2:  asid */
        bool tpr:1;        /* 3:  vintr */
        bool np:1;         /* 4:  np, h_cr3, g_pat */
        bool cr:1;         /* 5:  cr0, cr3, cr4, efer */
        bool dr:1;         /* 6:  dr6, dr7 */
        bool dt:1;         /* 7:  gdtr, idtr */
        bool seg:1;        /* 8:  cs, ds, es, ss, cpl */
        bool cr2:1;        /* 9:  cr2 */
        bool lbr:1;        /* 10: debugctlmsr, last{branch,int}{to,from}ip */
        bool :1;
        bool cet:1;        /* 12: msr_s_set, ssp, msr_isst */
    };
    uint32_t raw;
} vmcbcleanbits_t;

#define IOPM_SIZE   (12 * 1024)
#define MSRPM_SIZE  (8  * 1024)

struct vmcb {
    /* Control area */
    uint32_t _cr_intercepts;             /* 0x000 - Clean.intercepts(0) */
    uint32_t _dr_intercepts;             /* 0x004   | */
    uint32_t _exception_intercepts;      /* 0x008   | */
    uint32_t _general1_intercepts;       /* 0x00c   | */
    uint32_t _general2_intercepts;       /* 0x010   | */
    uint32_t _general3_intercepts;       /* 0x014   | */
    uint32_t res01[9];                   /* 0x018   | */
    uint16_t _pause_filter_thresh;       /* 0x03c   | */
    uint16_t _pause_filter_count;        /* 0x03e   v */
    uint64_t _iopm_base_pa;              /* 0x040 - Clean.iopm(1) */
    uint64_t _msrpm_base_pa;             /* 0x048   v */
    uint64_t _tsc_offset;                /* 0x050 - Clean.intercepts(0) */
    uint32_t _asid;                      /* 0x058 - Clean.asid(2) */
    uint8_t  tlb_control;                /* 0x05c - TLB_CTRL_* */
    uint8_t  res07[3];
    vintr_t _vintr;                      /* 0x060 - Clean.tpr(3) */
    intstat_t int_stat;                  /* 0x068 */
    uint64_t exitcode;                   /* 0x070 */
    union {
        struct {
            uint64_t exitinfo1;          /* 0x078 */
            uint64_t exitinfo2;          /* 0x080 */
        };
        union {
            struct {
                uint32_t ec; /* #NP, #SS, #GP, #PF, #AC */
                uint32_t :32;

                uint64_t cr2; /* #PF */
            } exc;
            struct {
                bool     in:1;
                bool     :1;
                bool     str:1;
                bool     rep:1;
                uint16_t bytes:3;
                uint16_t /* asz */:3;
                uint16_t seg:3;
                uint16_t :3;
                uint16_t port;
                uint32_t :32;

                uint64_t nrip;
            } io;
            struct {
                uint64_t gpr:4;
                uint64_t :59;
                bool     mov_insn:1; /* MOV, as opposed to LMSW, CLTS, etc */
            } mov_cr;
            struct {
                uint64_t ec;
                uint64_t gpa;
            } npf;
            struct {
                uint16_t sel;
                uint64_t :48;

                uint32_t ec;
                uint32_t :4;
                bool     iret:1;
                uint32_t :1;
                bool     jmp:1;
                uint32_t :5;
                bool     ev:1;
                uint32_t :3;
                bool     rf:1;
            } task_switch;
        } ei;
    };
    intinfo_t exit_int_info;             /* 0x088 */
    union {                              /* 0x090 - Clean.np(4) */
        struct {
            bool _np        :1;
            bool _sev       :1;
            bool _sev_es    :1;
            bool _gmet      :1;
            bool _np_sss    :1;
            bool _vte       :1;
        };
        uint64_t _np_ctrl;
    };
    uint64_t res08[2];
    intinfo_t event_inj;                 /* 0x0a8 */
    uint64_t _h_cr3;                     /* 0x0b0 - Clean.np(4) */
    virt_ext_t virt_ext;                 /* 0x0b8 */
    vmcbcleanbits_t cleanbits;           /* 0x0c0 */
    uint32_t :32;
    uint64_t nextrip;                    /* 0x0c8 */
    uint8_t  guest_ins_len;              /* 0x0d0 */
    uint8_t  guest_ins[15];              /* 0x0d1 */
    uint64_t res10a[8];
    uint16_t bus_lock_count;             /* 0x120 */
    uint16_t res10b[3];
    uint64_t res10c[91];

    /* State Save area, offset 0x400 */
    union {
        struct segment_register sreg[6];
        struct {
            struct segment_register es;  /* 0x400 + 0x000 - Clean.seg(8) */
            struct segment_register cs;  /* 0x400 + 0x010   | */
            struct segment_register ss;  /* 0x400 + 0x020   | */
            struct segment_register ds;  /* 0x400 + 0x030   v */
            struct segment_register fs;  /* 0x400 + 0x040 */
            struct segment_register gs;  /* 0x400 + 0x050 */
        };
    };
    struct segment_register gdtr;        /* 0x400 + 0x060 - Clean.dt(7) */
    struct segment_register ldtr;        /* 0x400 + 0x070 */
    struct segment_register idtr;        /* 0x400 + 0x080 - Clean.dt(7) */
    struct segment_register tr;          /* 0x400 + 0x090 */
    uint64_t res10[5];
    uint8_t res11[3];
    uint8_t _cpl;                        /* 0x400 + 0x0cb - Clean.seg(8) */
    uint32_t :32;
    uint64_t _efer;                      /* 0x400 + 0x0d0 - Clean.cr(5) */
    uint64_t res13[14];
    uint64_t _cr4;                       /* 0x400 + 0x148 - Clean.cr(5) */
    uint64_t _cr3;                       /* 0x400 + 0x150   | */
    uint64_t _cr0;                       /* 0x400 + 0x158   v */
    uint64_t _dr7;                       /* 0x400 + 0x160 - Clean.dr(6) */
    uint64_t _dr6;                       /* 0x400 + 0x168   v */
    uint64_t rflags;                     /* 0x400 + 0x170 */
    uint64_t rip;                        /* 0x400 + 0x178 */
    uint64_t res14[11];
    uint64_t rsp;                        /* 0x400 + 0x1d8 */
    uint64_t _msr_s_cet;                 /* 0x400 + 0x1e0 - Clean.cet(12) */
    uint64_t _ssp;                       /* 0x400 + 0x1e8   | */
    uint64_t _msr_isst;                  /* 0x400 + 0x1f0   v */
    uint64_t rax;                        /* 0x400 + 0x1f8 */
    uint64_t star;                       /* 0x400 + 0x200 */
    uint64_t lstar;                      /* 0x400 + 0x208 */
    uint64_t cstar;                      /* 0x400 + 0x210 */
    uint64_t sfmask;                     /* 0x400 + 0x218 */
    uint64_t kerngsbase;                 /* 0x400 + 0x220 */
    uint64_t sysenter_cs;                /* 0x400 + 0x228 */
    uint64_t sysenter_esp;               /* 0x400 + 0x230 */
    uint64_t sysenter_eip;               /* 0x400 + 0x238 */
    uint64_t _cr2;                       /* 0x400 + 0x240 - Clean.cr2(9) */
    uint64_t res16[4];
    uint64_t _g_pat;                     /* 0x400 + 0x268 - Clean.np(4) */
    uint64_t _debugctlmsr;               /* 0x400 + 0x270 - Clean.lbr(10) */
    uint64_t _lastbranchfromip;          /* 0x400 + 0x278   | */
    uint64_t _lastbranchtoip;            /* 0x400 + 0x280   | */
    uint64_t _lastintfromip;             /* 0x400 + 0x288   | */
    uint64_t _lastinttoip;               /* 0x400 + 0x290   v */
    uint64_t res17[9];
    uint64_t spec_ctrl;                  /* 0x400 + 0x2e0 */
    uint64_t res18[291];
};

struct vmcb *alloc_vmcb(void);
void free_vmcb(struct vmcb *vmcb);

int  svm_create_vmcb(struct vcpu *v);
void svm_destroy_vmcb(struct vcpu *v);

void setup_vmcb_dump(void);
void svm_vmcb_dump(const char *from, const struct vmcb *vmcb);
bool svm_vmcb_isvalid(const char *from, const struct vmcb *vmcb,
                      const struct vcpu *v, bool verbose);

/*
 * VMCB accessor functions.
 */

#define VMCB_ACCESSORS_(name, type, cleanbit)     \
static inline void                                \
vmcb_set_ ## name(struct vmcb *vmcb,              \
                  type value)                     \
{                                                 \
    vmcb->_ ## name = value;                      \
    vmcb->cleanbits.cleanbit = false;             \
}                                                 \
static inline type                                \
vmcb_get_ ## name(const struct vmcb *vmcb)        \
{                                                 \
    return vmcb->_ ## name;                       \
}

#define VMCB_ACCESSORS(name, cleanbit) \
    VMCB_ACCESSORS_(name, typeof(((struct vmcb){})._ ## name), cleanbit)

VMCB_ACCESSORS(cr_intercepts, intercepts)
VMCB_ACCESSORS(dr_intercepts, intercepts)
VMCB_ACCESSORS(exception_intercepts, intercepts)
VMCB_ACCESSORS(general1_intercepts, intercepts)
VMCB_ACCESSORS(general2_intercepts, intercepts)
VMCB_ACCESSORS(general3_intercepts, intercepts)
VMCB_ACCESSORS(pause_filter_count, intercepts)
VMCB_ACCESSORS(pause_filter_thresh, intercepts)
VMCB_ACCESSORS(tsc_offset, intercepts)
VMCB_ACCESSORS(iopm_base_pa, iopm)
VMCB_ACCESSORS(msrpm_base_pa, iopm)
VMCB_ACCESSORS(asid, asid)
VMCB_ACCESSORS(vintr, tpr)
VMCB_ACCESSORS(np_ctrl, np)
VMCB_ACCESSORS_(np, bool, np)
VMCB_ACCESSORS_(sev, bool, np)
VMCB_ACCESSORS_(sev_es, bool, np)
VMCB_ACCESSORS_(gmet, bool, np)
VMCB_ACCESSORS_(vte, bool, np)
VMCB_ACCESSORS(h_cr3, np)
VMCB_ACCESSORS(g_pat, np)
VMCB_ACCESSORS(cr0, cr)
VMCB_ACCESSORS(cr3, cr)
VMCB_ACCESSORS(cr4, cr)
VMCB_ACCESSORS(efer, cr)
VMCB_ACCESSORS(dr6, dr)
VMCB_ACCESSORS(dr7, dr)
VMCB_ACCESSORS(cpl, seg)
VMCB_ACCESSORS(cr2, cr2)
VMCB_ACCESSORS(debugctlmsr, lbr)
VMCB_ACCESSORS(lastbranchfromip, lbr)
VMCB_ACCESSORS(lastbranchtoip, lbr)
VMCB_ACCESSORS(lastintfromip, lbr)
VMCB_ACCESSORS(lastinttoip, lbr)
VMCB_ACCESSORS(msr_s_cet, cet)
VMCB_ACCESSORS(ssp, cet)
VMCB_ACCESSORS(msr_isst, cet)

#undef VMCB_ACCESSORS

#endif /* SVM_PRIVATE_VMCB_H */
