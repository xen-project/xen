/*
 * vmcb.h: VMCB related definitions
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef __ASM_X86_HVM_SVM_VMCB_H__
#define __ASM_X86_HVM_SVM_VMCB_H__

#include <xen/types.h>
#include <asm/hvm/emulate.h>


/* general 1 intercepts */
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
    GENERAL1_INTERCEPT_SHUTDOWN_EVT  = 1 << 31
};

/* general 2 intercepts */
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
    GENERAL2_INTERCEPT_XSETBV  = 1 << 13
};


/* control register intercepts */
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
    CR_INTERCEPT_CR15_WRITE = 1 << 31,
};


/* debug register intercepts */
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
    DR_INTERCEPT_DR15_WRITE = 1 << 31,
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
    VMEXIT_NPF              = 1024, /* 0x400, nested paging fault */
    VMEXIT_INVALID          =  -1
};

typedef union
{
    u64 bytes;
    struct
    {
        u64 vector:    8;
        u64 type:      3;
        u64 ev:        1;
        u64 resvd1:   19;
        u64 v:         1;
        u64 errorcode:32;
    } fields;
} eventinj_t;

typedef union
{
    u64 bytes;
    struct
    {
        u64 tpr:          8;
        u64 irq:          1;
        u64 vgif:         1;
        u64 rsvd0:        6;
        u64 prio:         4;
        u64 ign_tpr:      1;
        u64 rsvd1:        3;
        u64 intr_masking: 1;
        u64 vgif_enable:  1;
        u64 rsvd2:        6;
        u64 vector:       8;
        u64 rsvd3:       24;
    } fields;
} vintr_t;

typedef union
{
    u64 bytes;
    struct
    {
        u64 type: 1;
        u64 rsv0: 1;
        u64 str:  1;
        u64 rep:  1;
        u64 sz8:  1;
        u64 sz16: 1;
        u64 sz32: 1;
        u64 rsv1: 9;
        u64 port: 16;
    } fields;
} ioio_info_t;

typedef union
{
    u64 bytes;
    struct
    {
        u64 lbr_enable:1;
        u64 vloadsave_enable:1;
    } fields;
} virt_ext_t;

typedef union
{
    uint32_t bytes;
    struct
    {
        /* cr_intercepts, dr_intercepts, exception_intercepts,
         * general{1,2}_intercepts, pause_filter_count, tsc_offset */
        uint32_t intercepts: 1;
        /* iopm_base_pa, msrpm_base_pa */
        uint32_t iopm: 1;
        /* guest_asid */
        uint32_t asid: 1;
        /* vintr */
        uint32_t tpr: 1;
        /* np_enable, h_cr3, g_pat */
        uint32_t np: 1;
        /* cr0, cr3, cr4, efer */
        uint32_t cr: 1;
        /* dr6, dr7 */
        uint32_t dr: 1;
        /* gdtr, idtr */
        uint32_t dt: 1;
        /* cs, ds, es, ss, cpl */
        uint32_t seg: 1;
        /* cr2 */
        uint32_t cr2: 1;
        /* debugctlmsr, last{branch,int}{to,from}ip */
        uint32_t lbr: 1;
        uint32_t resv: 21;
    } fields;
} vmcbcleanbits_t;

#define IOPM_SIZE   (12 * 1024)
#define MSRPM_SIZE  (8  * 1024)

struct vmcb_struct {
    u32 _cr_intercepts;         /* offset 0x00 - cleanbit 0 */
    u32 _dr_intercepts;         /* offset 0x04 - cleanbit 0 */
    u32 _exception_intercepts;  /* offset 0x08 - cleanbit 0 */
    u32 _general1_intercepts;   /* offset 0x0C - cleanbit 0 */
    u32 _general2_intercepts;   /* offset 0x10 - cleanbit 0 */
    u32 res01;                  /* offset 0x14 */
    u64 res02;                  /* offset 0x18 */
    u64 res03;                  /* offset 0x20 */
    u64 res04;                  /* offset 0x28 */
    u64 res05;                  /* offset 0x30 */
    u32 res06;                  /* offset 0x38 */
    u16 _pause_filter_thresh;   /* offset 0x3C - cleanbit 0 */
    u16 _pause_filter_count;    /* offset 0x3E - cleanbit 0 */
    u64 _iopm_base_pa;          /* offset 0x40 - cleanbit 1 */
    u64 _msrpm_base_pa;         /* offset 0x48 - cleanbit 1 */
    u64 _tsc_offset;            /* offset 0x50 - cleanbit 0 */
    u32 _guest_asid;            /* offset 0x58 - cleanbit 2 */
    u8  tlb_control;            /* offset 0x5C */
    u8  res07[3];
    vintr_t _vintr;             /* offset 0x60 - cleanbit 3 */
    u64 interrupt_shadow;       /* offset 0x68 */
    u64 exitcode;               /* offset 0x70 */
    u64 exitinfo1;              /* offset 0x78 */
    u64 exitinfo2;              /* offset 0x80 */
    eventinj_t  exitintinfo;    /* offset 0x88 */
    u64 _np_enable;             /* offset 0x90 - cleanbit 4 */
    u64 res08[2];
    eventinj_t  eventinj;       /* offset 0xA8 */
    u64 _h_cr3;                 /* offset 0xB0 - cleanbit 4 */
    virt_ext_t virt_ext;        /* offset 0xB8 */
    vmcbcleanbits_t cleanbits;  /* offset 0xC0 */
    u32 res09;                  /* offset 0xC4 */
    u64 nextrip;                /* offset 0xC8 */
    u8  guest_ins_len;          /* offset 0xD0 */
    u8  guest_ins[15];          /* offset 0xD1 */
    u64 res10a[100];            /* offset 0xE0 pad to save area */

    union {
        struct segment_register sreg[6];
        struct {
            struct segment_register es;  /* offset 0x400 - cleanbit 8 */
            struct segment_register cs;  /* cleanbit 8 */
            struct segment_register ss;  /* cleanbit 8 */
            struct segment_register ds;  /* cleanbit 8 */
            struct segment_register fs;
            struct segment_register gs;
        };
    };
    struct segment_register gdtr; /* cleanbit 7 */
    struct segment_register ldtr;
    struct segment_register idtr; /* cleanbit 7 */
    struct segment_register tr;
    u64 res10[5];
    u8 res11[3];
    u8 _cpl;                    /* cleanbit 8 */
    u32 res12;
    u64 _efer;                  /* offset 0x400 + 0xD0 - cleanbit 5 */
    u64 res13[14];
    u64 _cr4;                   /* offset 0x400 + 0x148 - cleanbit 5 */
    u64 _cr3;                   /* cleanbit 5 */
    u64 _cr0;                   /* cleanbit 5 */
    u64 _dr7;                   /* cleanbit 6 */
    u64 _dr6;                   /* cleanbit 6 */
    u64 rflags;
    u64 rip;
    u64 res14[11];
    u64 rsp;
    u64 res15[3];
    u64 rax;
    u64 star;
    u64 lstar;
    u64 cstar;
    u64 sfmask;
    u64 kerngsbase;
    u64 sysenter_cs;
    u64 sysenter_esp;
    u64 sysenter_eip;
    u64 _cr2;                   /* cleanbit 9 */
    u64 pdpe0;
    u64 pdpe1;
    u64 pdpe2;
    u64 pdpe3;
    u64 _g_pat;                 /* cleanbit 4 */
    u64 _debugctlmsr;           /* cleanbit 10 */
    u64 _lastbranchfromip;      /* cleanbit 10 */
    u64 _lastbranchtoip;        /* cleanbit 10 */
    u64 _lastintfromip;         /* cleanbit 10 */
    u64 _lastinttoip;           /* cleanbit 10 */
    u64 res16[301];
};

struct svm_domain {
};

struct arch_svm_struct {
    struct vmcb_struct *vmcb;
    u64    vmcb_pa;
    unsigned long *msrpm;
    int    launch_core;
    bool_t vmcb_in_sync;    /* VMCB sync'ed with VMSAVE? */

    /* VMCB has a cached instruction from #PF/#NPF Decode Assist? */
    uint8_t cached_insn_len; /* Zero if no cached instruction. */

    /* Upper four bytes are undefined in the VMCB, therefore we can't
     * use the fields in the VMCB. Write a 64bit value and then read a 64bit
     * value is fine unless there's a VMRUN/VMEXIT in between which clears
     * the upper four bytes.
     */
    uint64_t guest_sysenter_cs;
    uint64_t guest_sysenter_esp;
    uint64_t guest_sysenter_eip;

    /* AMD lightweight profiling MSR */
    uint64_t guest_lwp_cfg;      /* guest version */
    uint64_t cpu_lwp_cfg;        /* CPU version */

    /* data breakpoint extension MSRs */
    uint32_t dr_mask[4];

    /* OSVW MSRs */
    struct {
        u64 length;
        u64 status;
    } osvw;
};

struct vmcb_struct *alloc_vmcb(void);
void free_vmcb(struct vmcb_struct *vmcb);

int  svm_create_vmcb(struct vcpu *v);
void svm_destroy_vmcb(struct vcpu *v);

void setup_vmcb_dump(void);

#define MSR_INTERCEPT_NONE    0
#define MSR_INTERCEPT_READ    1
#define MSR_INTERCEPT_WRITE   2
#define MSR_INTERCEPT_RW      (MSR_INTERCEPT_WRITE | MSR_INTERCEPT_READ)
void svm_intercept_msr(struct vcpu *v, uint32_t msr, int enable);
#define svm_disable_intercept_for_msr(v, msr) svm_intercept_msr((v), (msr), MSR_INTERCEPT_NONE)
#define svm_enable_intercept_for_msr(v, msr) svm_intercept_msr((v), (msr), MSR_INTERCEPT_RW)

/*
 * VMCB accessor functions.
 */

#define VMCB_ACCESSORS(name, cleanbit)            \
static inline void                                \
vmcb_set_ ## name(struct vmcb_struct *vmcb,       \
                  typeof(vmcb->_ ## name) value)  \
{                                                 \
    vmcb->_ ## name = value;                      \
    vmcb->cleanbits.fields.cleanbit = 0;          \
}                                                 \
static inline typeof(alloc_vmcb()->_ ## name)     \
vmcb_get_ ## name(const struct vmcb_struct *vmcb) \
{                                                 \
    return vmcb->_ ## name;                       \
}

VMCB_ACCESSORS(cr_intercepts, intercepts)
VMCB_ACCESSORS(dr_intercepts, intercepts)
VMCB_ACCESSORS(exception_intercepts, intercepts)
VMCB_ACCESSORS(general1_intercepts, intercepts)
VMCB_ACCESSORS(general2_intercepts, intercepts)
VMCB_ACCESSORS(pause_filter_count, intercepts)
VMCB_ACCESSORS(pause_filter_thresh, intercepts)
VMCB_ACCESSORS(tsc_offset, intercepts)
VMCB_ACCESSORS(iopm_base_pa, iopm)
VMCB_ACCESSORS(msrpm_base_pa, iopm)
VMCB_ACCESSORS(guest_asid, asid)
VMCB_ACCESSORS(vintr, tpr)
VMCB_ACCESSORS(np_enable, np)
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

#undef VMCB_ACCESSORS

#endif /* ASM_X86_HVM_SVM_VMCS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
