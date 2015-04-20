#ifndef __ASM_ARM_PROCESSOR_H
#define __ASM_ARM_PROCESSOR_H

#include <asm/cpregs.h>
#include <asm/sysregs.h>
#ifndef __ASSEMBLY__
#include <xen/types.h>
#endif
#include <public/arch-arm.h>

/* MIDR Main ID Register */
#define MIDR_MASK    0xff0ffff0

/* MPIDR Multiprocessor Affinity Register */
#define _MPIDR_UP           (30)
#define MPIDR_UP            (_AC(1,U) << _MPIDR_UP)
#define _MPIDR_SMP          (31)
#define MPIDR_SMP           (_AC(1,U) << _MPIDR_SMP)
#define MPIDR_AFF0_SHIFT    (0)
#define MPIDR_AFF0_MASK     (_AC(0xff,U) << MPIDR_AFF0_SHIFT)
#define MPIDR_HWID_MASK     _AC(0xffffff,U)
#define MPIDR_INVALID       (~MPIDR_HWID_MASK)
#define MPIDR_LEVEL_BITS    (8)
#define AFFINITY_MASK(level)    ~((_AC(0x1,U) << ((level) * MPIDR_LEVEL_BITS)) - 1)


/*
 * Macros to extract affinity level. picked from kernel
 */

#define MPIDR_LEVEL_BITS_SHIFT  3
#define MPIDR_LEVEL_MASK        ((1 << MPIDR_LEVEL_BITS) - 1)

#define MPIDR_LEVEL_SHIFT(level) \
         (((1 << level) >> 1) << MPIDR_LEVEL_BITS_SHIFT)

#define MPIDR_AFFINITY_LEVEL(mpidr, level) \
         ((mpidr >> MPIDR_LEVEL_SHIFT(level)) & MPIDR_LEVEL_MASK)

/* TTBCR Translation Table Base Control Register */
#define TTBCR_EAE    _AC(0x80000000,U)
#define TTBCR_N_MASK _AC(0x07,U)
#define TTBCR_N_16KB _AC(0x00,U)
#define TTBCR_N_8KB  _AC(0x01,U)
#define TTBCR_N_4KB  _AC(0x02,U)
#define TTBCR_N_2KB  _AC(0x03,U)
#define TTBCR_N_1KB  _AC(0x04,U)

/* SCTLR System Control Register. */
/* HSCTLR is a subset of this. */
#define SCTLR_TE        (_AC(1,U)<<30)
#define SCTLR_AFE       (_AC(1,U)<<29)
#define SCTLR_TRE       (_AC(1,U)<<28)
#define SCTLR_NMFI      (_AC(1,U)<<27)
#define SCTLR_EE        (_AC(1,U)<<25)
#define SCTLR_VE        (_AC(1,U)<<24)
#define SCTLR_U         (_AC(1,U)<<22)
#define SCTLR_FI        (_AC(1,U)<<21)
#define SCTLR_WXN       (_AC(1,U)<<19)
#define SCTLR_HA        (_AC(1,U)<<17)
#define SCTLR_RR        (_AC(1,U)<<14)
#define SCTLR_V         (_AC(1,U)<<13)
#define SCTLR_I         (_AC(1,U)<<12)
#define SCTLR_Z         (_AC(1,U)<<11)
#define SCTLR_SW        (_AC(1,U)<<10)
#define SCTLR_B         (_AC(1,U)<<7)
#define SCTLR_C         (_AC(1,U)<<2)
#define SCTLR_A         (_AC(1,U)<<1)
#define SCTLR_M         (_AC(1,U)<<0)

#define HSCTLR_BASE     _AC(0x30c51878,U)

/* HCR Hyp Configuration Register */
#define HCR_RW          (_AC(1,UL)<<31) /* Register Width, ARM64 only */
#define HCR_TGE         (_AC(1,UL)<<27) /* Trap General Exceptions */
#define HCR_TVM         (_AC(1,UL)<<26) /* Trap Virtual Memory Controls */
#define HCR_TTLB        (_AC(1,UL)<<25) /* Trap TLB Maintenance Operations */
#define HCR_TPU         (_AC(1,UL)<<24) /* Trap Cache Maintenance Operations to PoU */
#define HCR_TPC         (_AC(1,UL)<<23) /* Trap Cache Maintenance Operations to PoC */
#define HCR_TSW         (_AC(1,UL)<<22) /* Trap Set/Way Cache Maintenance Operations */
#define HCR_TAC         (_AC(1,UL)<<21) /* Trap ACTLR Accesses */
#define HCR_TIDCP       (_AC(1,UL)<<20) /* Trap lockdown */
#define HCR_TSC         (_AC(1,UL)<<19) /* Trap SMC instruction */
#define HCR_TID3        (_AC(1,UL)<<18) /* Trap ID Register Group 3 */
#define HCR_TID2        (_AC(1,UL)<<17) /* Trap ID Register Group 2 */
#define HCR_TID1        (_AC(1,UL)<<16) /* Trap ID Register Group 1 */
#define HCR_TID0        (_AC(1,UL)<<15) /* Trap ID Register Group 0 */
#define HCR_TWE         (_AC(1,UL)<<14) /* Trap WFE instruction */
#define HCR_TWI         (_AC(1,UL)<<13) /* Trap WFI instruction */
#define HCR_DC          (_AC(1,UL)<<12) /* Default cacheable */
#define HCR_BSU_MASK    (_AC(3,UL)<<10) /* Barrier Shareability Upgrade */
#define HCR_BSU_NONE     (_AC(0,UL)<<10)
#define HCR_BSU_INNER    (_AC(1,UL)<<10)
#define HCR_BSU_OUTER    (_AC(2,UL)<<10)
#define HCR_BSU_FULL     (_AC(3,UL)<<10)
#define HCR_FB          (_AC(1,UL)<<9) /* Force Broadcast of Cache/BP/TLB operations */
#define HCR_VA          (_AC(1,UL)<<8) /* Virtual Asynchronous Abort */
#define HCR_VI          (_AC(1,UL)<<7) /* Virtual IRQ */
#define HCR_VF          (_AC(1,UL)<<6) /* Virtual FIQ */
#define HCR_AMO         (_AC(1,UL)<<5) /* Override CPSR.A */
#define HCR_IMO         (_AC(1,UL)<<4) /* Override CPSR.I */
#define HCR_FMO         (_AC(1,UL)<<3) /* Override CPSR.F */
#define HCR_PTW         (_AC(1,UL)<<2) /* Protected Walk */
#define HCR_SWIO        (_AC(1,UL)<<1) /* Set/Way Invalidation Override */
#define HCR_VM          (_AC(1,UL)<<0) /* Virtual MMU Enable */

/* TCR: Stage 1 Translation Control */

#define TCR_T0SZ(x)     ((x)<<0)

#define TCR_IRGN0_NC    (_AC(0x0,UL)<<8)
#define TCR_IRGN0_WBWA  (_AC(0x1,UL)<<8)
#define TCR_IRGN0_WT    (_AC(0x2,UL)<<8)
#define TCR_IRGN0_WB    (_AC(0x3,UL)<<8)

#define TCR_ORGN0_NC    (_AC(0x0,UL)<<10)
#define TCR_ORGN0_WBWA  (_AC(0x1,UL)<<10)
#define TCR_ORGN0_WT    (_AC(0x2,UL)<<10)
#define TCR_ORGN0_WB    (_AC(0x3,UL)<<10)

#define TCR_SH0_NS      (_AC(0x0,UL)<<12)
#define TCR_SH0_OS      (_AC(0x2,UL)<<12)
#define TCR_SH0_IS      (_AC(0x3,UL)<<12)

#define TCR_TG0_4K      (_AC(0x0,UL)<<14)
#define TCR_TG0_64K     (_AC(0x1,UL)<<14)
#define TCR_TG0_16K     (_AC(0x2,UL)<<14)

#ifdef CONFIG_ARM_64

#define TCR_PS(x)       ((x)<<16)
#define TCR_TBI         (_AC(0x1,UL)<<20)

#define TCR_RES1        (_AC(1,UL)<<31|_AC(1,UL)<<23)

#else

#define TCR_RES1        (_AC(1,UL)<<31)

#endif

/* VTCR: Stage 2 Translation Control */

#define VTCR_T0SZ(x)    ((x)<<0)

#define VTCR_SL0(x)     ((x)<<6)

#define VTCR_IRGN0_NC   (_AC(0x0,UL)<<8)
#define VTCR_IRGN0_WBWA (_AC(0x1,UL)<<8)
#define VTCR_IRGN0_WT   (_AC(0x2,UL)<<8)
#define VTCR_IRGN0_WB   (_AC(0x3,UL)<<8)

#define VTCR_ORGN0_NC   (_AC(0x0,UL)<<10)
#define VTCR_ORGN0_WBWA (_AC(0x1,UL)<<10)
#define VTCR_ORGN0_WT   (_AC(0x2,UL)<<10)
#define VTCR_ORGN0_WB   (_AC(0x3,UL)<<10)

#define VTCR_SH0_NS     (_AC(0x0,UL)<<12)
#define VTCR_SH0_OS     (_AC(0x2,UL)<<12)
#define VTCR_SH0_IS     (_AC(0x3,UL)<<12)

#ifdef CONFIG_ARM_64

#define VTCR_TG0_4K     (_AC(0x0,UL)<<14)
#define VTCR_TG0_64K    (_AC(0x1,UL)<<14)
#define VTCR_TG0_16K    (_AC(0x2,UL)<<14)

#define VTCR_PS(x)      ((x)<<16)

#endif

#define VTCR_RES1       (_AC(1,UL)<<31)

/* HCPTR Hyp. Coprocessor Trap Register */
#define HCPTR_TTA       ((_AC(1,U)<<20))        /* Trap trace registers */
#define HCPTR_CP(x)     ((_AC(1,U)<<(x)))       /* Trap Coprocessor x */
#define HCPTR_CP_MASK   ((_AC(1,U)<<14)-1)

/* HSTR Hyp. System Trap Register */
#define HSTR_T(x)       ((_AC(1,U)<<(x)))       /* Trap Cp15 c<x> */

/* HDCR Hyp. Debug Configuration Register */
#define HDCR_TDRA       (_AC(1,U)<<11)          /* Trap Debug ROM access */
#define HDCR_TDOSA      (_AC(1,U)<<10)          /* Trap Debug-OS-related register access */
#define HDCR_TDA        (_AC(1,U)<<9)           /* Trap Debug Access */
#define HDCR_TDE        (_AC(1,U)<<8)           /* Route Soft Debug exceptions from EL1/EL1 to EL2 */
#define HDCR_TPM        (_AC(1,U)<<6)           /* Trap Performance Monitors accesses */
#define HDCR_TPMCR      (_AC(1,U)<<5)           /* Trap PMCR accesses */

#define HSR_EC_UNKNOWN              0x00
#define HSR_EC_WFI_WFE              0x01
#define HSR_EC_CP15_32              0x03
#define HSR_EC_CP15_64              0x04
#define HSR_EC_CP14_32              0x05        /* Trapped MCR or MRC access to CP14 */
#define HSR_EC_CP14_DBG             0x06        /* Trapped LDC/STC access to CP14 (only for debug registers) */
#define HSR_EC_CP                   0x07        /* HCPTR-trapped access to CP0-CP13 */
#define HSR_EC_CP10                 0x08
#define HSR_EC_JAZELLE              0x09
#define HSR_EC_BXJ                  0x0a
#define HSR_EC_CP14_64              0x0c
#define HSR_EC_SVC32                0x11
#define HSR_EC_HVC32                0x12
#define HSR_EC_SMC32                0x13
#ifdef CONFIG_ARM_64
#define HSR_EC_HVC64                0x16
#define HSR_EC_SMC64                0x17
#define HSR_EC_SYSREG               0x18
#endif
#define HSR_EC_INSTR_ABORT_LOWER_EL 0x20
#define HSR_EC_INSTR_ABORT_CURR_EL  0x21
#define HSR_EC_DATA_ABORT_LOWER_EL  0x24
#define HSR_EC_DATA_ABORT_CURR_EL   0x25
#ifdef CONFIG_ARM_64
#define HSR_EC_BRK                  0x3c
#endif

/* FSR format, common */
#define FSR_LPAE                (_AC(1,UL)<<9)
/* FSR short format */
#define FSRS_FS_DEBUG           (_AC(0,UL)<<10|_AC(0x2,UL)<<0)
/* FSR long format */
#define FSRL_STATUS_DEBUG       (_AC(0x22,UL)<<0)

#ifndef __ASSEMBLY__

struct cpuinfo_arm {
    union {
        uint32_t bits;
        struct {
            unsigned long revision:4;
            unsigned long part_number:12;
            unsigned long architecture:4;
            unsigned long variant:4;
            unsigned long implementer:8;
        };
    } midr;
    union {
        register_t bits;
        struct {
            unsigned long aff0:8;
            unsigned long aff1:8;
            unsigned long aff2:8;
            unsigned long mt:1; /* Multi-thread, iff MP == 1 */
            unsigned long __res0:5;
            unsigned long up:1; /* UP system, iff MP == 1 */
            unsigned long mp:1; /* MP extensions */

#ifdef CONFIG_ARM_64
            unsigned long aff3:8;
            unsigned long __res1:24;
#endif
        };
    } mpidr;

#ifdef CONFIG_ARM_64
    /* 64-bit CPUID registers. */
    union {
        uint64_t bits[2];
        struct {
            unsigned long el0:4;
            unsigned long el1:4;
            unsigned long el2:4;
            unsigned long el3:4;
            unsigned long fp:4;   /* Floating Point */
            unsigned long simd:4; /* Advanced SIMD */
            unsigned long gic:4;  /* GIC support */
            unsigned long __res0:4;
            unsigned long __res1;
        };
    } pfr64;

    struct {
        uint64_t bits[2];
    } dbg64;

    struct {
        uint64_t bits[2];
    } aux64;

    union {
        uint64_t bits[2];
        struct {
            unsigned long pa_range:4;
            unsigned long asid_bits:4;
            unsigned long bigend:4;
            unsigned long secure_ns:4;
            unsigned long bigend_el0:4;
            unsigned long tgranule_16K:4;
            unsigned long tgranule_64K:4;
            unsigned long tgranule_4K:4;
            unsigned long __res0:32;
       };
    } mm64;

    struct {
        uint64_t bits[2];
    } isa64;

#endif

    /*
     * 32-bit CPUID registers. On ARMv8 these describe the properties
     * when running in 32-bit mode.
     */
    union {
        uint32_t bits[2];
        struct {
            unsigned long arm:4;
            unsigned long thumb:4;
            unsigned long jazelle:4;
            unsigned long thumbee:4;
            unsigned long __res0:16;

            unsigned long progmodel:4;
            unsigned long security:4;
            unsigned long mprofile:4;
            unsigned long virt:4;
            unsigned long gentimer:4;
            unsigned long __res1:12;
        };
    } pfr32;

    struct {
        uint32_t bits[1];
    } dbg32;

    struct {
        uint32_t bits[1];
    } aux32;

    struct {
        uint32_t bits[4];
    } mm32;

    struct {
        uint32_t bits[6];
    } isa32;
};

/*
 * capabilities of CPUs
 */

extern struct cpuinfo_arm boot_cpu_data;

extern void identify_cpu(struct cpuinfo_arm *);

extern struct cpuinfo_arm cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]

extern u32 __cpu_logical_map[];
#define cpu_logical_map(cpu) __cpu_logical_map[cpu]

/* HSR data abort size definition */
enum dabt_size {
    DABT_BYTE        = 0,
    DABT_HALF_WORD   = 1,
    DABT_WORD        = 2,
    DABT_DOUBLE_WORD = 3,
};

union hsr {
    uint32_t bits;
    struct {
        unsigned long iss:25;  /* Instruction Specific Syndrome */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    };

    /* Common to all conditional exception classes (0x0N, except 0x00). */
    struct hsr_cond {
        unsigned long iss:20;  /* Instruction Specific Syndrome */
        unsigned long cc:4;    /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } cond;

    struct hsr_wfi_wfe {
        unsigned long ti:1;    /* Trapped instruction */
        unsigned long sbzp:19;
        unsigned long cc:4;    /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } wfi_wfe;

    /* reg, reg0, reg1 are 4 bits on AArch32, the fifth bit is sbzp. */
    struct hsr_cp32 {
        unsigned long read:1;  /* Direction */
        unsigned long crm:4;   /* CRm */
        unsigned long reg:5;   /* Rt */
        unsigned long crn:4;   /* CRn */
        unsigned long op1:3;   /* Op1 */
        unsigned long op2:3;   /* Op2 */
        unsigned long cc:4;    /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } cp32; /* HSR_EC_CP15_32, CP14_32, CP10 */

    struct hsr_cp64 {
        unsigned long read:1;   /* Direction */
        unsigned long crm:4;    /* CRm */
        unsigned long reg1:5;   /* Rt1 */
        unsigned long reg2:5;   /* Rt2 */
        unsigned long sbzp2:1;
        unsigned long op1:4;    /* Op1 */
        unsigned long cc:4;     /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;    /* Instruction length */
        unsigned long ec:6;     /* Exception Class */
    } cp64; /* HSR_EC_CP15_64, HSR_EC_CP14_64 */

     struct hsr_cp {
        unsigned long coproc:4; /* Number of coproc accessed */
        unsigned long sbz0p:1;
        unsigned long tas:1;    /* Trapped Advanced SIMD */
        unsigned long res0:14;
        unsigned long cc:4;     /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;    /* Instruction length */
        unsigned long ec:6;     /* Exception Class */
    } cp; /* HSR_EC_CP */

#ifdef CONFIG_ARM_64
    struct hsr_sysreg {
        unsigned long read:1;   /* Direction */
        unsigned long crm:4;    /* CRm */
        unsigned long reg:5;    /* Rt */
        unsigned long crn:4;    /* CRn */
        unsigned long op1:3;    /* Op1 */
        unsigned long op2:3;    /* Op2 */
        unsigned long op0:2;    /* Op0 */
        unsigned long res0:3;
        unsigned long len:1;    /* Instruction length */
        unsigned long ec:6;
    } sysreg; /* HSR_EC_SYSREG */
#endif

    struct hsr_iabt {
        unsigned long ifsc:6;  /* Instruction fault status code */
        unsigned long res0:1;
        unsigned long s1ptw:1; /* Stage 2 fault during stage 1 translation */
        unsigned long res1:1;
        unsigned long eat:1;   /* External abort type */
        unsigned long res2:15;
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } iabt; /* HSR_EC_INSTR_ABORT_* */

    struct hsr_dabt {
        unsigned long dfsc:6;  /* Data Fault Status Code */
        unsigned long write:1; /* Write / not Read */
        unsigned long s1ptw:1; /* Stage 2 fault during stage 1 translation */
        unsigned long cache:1; /* Cache Maintenance */
        unsigned long eat:1;   /* External Abort Type */
#ifdef CONFIG_ARM_32
        unsigned long sbzp0:6;
#else
        unsigned long sbzp0:4;
        unsigned long ar:1;    /* Acquire Release */
        unsigned long sf:1;    /* Sixty Four bit register */
#endif
        unsigned long reg:5;   /* Register */
        unsigned long sign:1;  /* Sign extend */
        unsigned long size:2;  /* Access Size */
        unsigned long valid:1; /* Syndrome Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } dabt; /* HSR_EC_DATA_ABORT_* */

#ifdef CONFIG_ARM_64
    struct hsr_brk {
        unsigned long comment:16;   /* Comment */
        unsigned long res0:9;
        unsigned long len:1;        /* Instruction length */
        unsigned long ec:6;         /* Exception Class */
    } brk;
#endif


};
#endif

/* HSR.EC == HSR_CP{15,14,10}_32 */
#define HSR_CP32_OP2_MASK (0x000e0000)
#define HSR_CP32_OP2_SHIFT (17)
#define HSR_CP32_OP1_MASK (0x0001c000)
#define HSR_CP32_OP1_SHIFT (14)
#define HSR_CP32_CRN_MASK (0x00003c00)
#define HSR_CP32_CRN_SHIFT (10)
#define HSR_CP32_CRM_MASK (0x0000001e)
#define HSR_CP32_CRM_SHIFT (1)
#define HSR_CP32_REGS_MASK (HSR_CP32_OP1_MASK|HSR_CP32_OP2_MASK|\
                            HSR_CP32_CRN_MASK|HSR_CP32_CRM_MASK)

/* HSR.EC == HSR_CP{15,14}_64 */
#define HSR_CP64_OP1_MASK (0x000f0000)
#define HSR_CP64_OP1_SHIFT (16)
#define HSR_CP64_CRM_MASK (0x0000001e)
#define HSR_CP64_CRM_SHIFT (1)
#define HSR_CP64_REGS_MASK (HSR_CP64_OP1_MASK|HSR_CP64_CRM_MASK)

/* HSR.EC == HSR_SYSREG */
#define HSR_SYSREG_OP0_MASK (0x00300000)
#define HSR_SYSREG_OP0_SHIFT (20)
#define HSR_SYSREG_OP1_MASK (0x0001c000)
#define HSR_SYSREG_OP1_SHIFT (14)
#define HSR_SYSREG_CRN_MASK (0x00003c00)
#define HSR_SYSREG_CRN_SHIFT (10)
#define HSR_SYSREG_CRM_MASK (0x0000001e)
#define HSR_SYSREG_CRM_SHIFT (1)
#define HSR_SYSREG_OP2_MASK (0x000e0000)
#define HSR_SYSREG_OP2_SHIFT (17)
#define HSR_SYSREG_REGS_MASK (HSR_SYSREG_OP0_MASK|HSR_SYSREG_OP1_MASK|\
                              HSR_SYSREG_CRN_MASK|HSR_SYSREG_CRM_MASK|\
                              HSR_SYSREG_OP2_MASK)

/* Physical Address Register */
#define PAR_F           (_AC(1,U)<<0)

/* .... If F == 1 */
#define PAR_FSC_SHIFT   (1)
#define PAR_FSC_MASK    (_AC(0x3f,U)<<PAR_FSC_SHIFT)
#define PAR_STAGE21     (_AC(1,U)<<8)     /* Stage 2 Fault During Stage 1 Walk */
#define PAR_STAGE2      (_AC(1,U)<<9)     /* Stage 2 Fault */

/* If F == 0 */
#define PAR_MAIR_SHIFT  56                       /* Memory Attributes */
#define PAR_MAIR_MASK   (0xffLL<<PAR_MAIR_SHIFT)
#define PAR_NS          (_AC(1,U)<<9)                   /* Non-Secure */
#define PAR_SH_SHIFT    7                        /* Shareability */
#define PAR_SH_MASK     (_AC(3,U)<<PAR_SH_SHIFT)

/* Fault Status Register */
/*
 * 543210 BIT
 * 00XXLL -- XX Fault Level LL
 * ..01LL -- Translation Fault LL
 * ..10LL -- Access Fault LL
 * ..11LL -- Permission Fault LL
 * 01xxxx -- Abort/Parity
 * 10xxxx -- Other
 * 11xxxx -- Implementation Defined
 */
#define FSC_TYPE_MASK (_AC(0x3,U)<<4)
#define FSC_TYPE_FAULT (_AC(0x00,U)<<4)
#define FSC_TYPE_ABT   (_AC(0x01,U)<<4)
#define FSC_TYPE_OTH   (_AC(0x02,U)<<4)
#define FSC_TYPE_IMPL  (_AC(0x03,U)<<4)

#define FSC_FLT_TRANS  (0x04)
#define FSC_FLT_ACCESS (0x08)
#define FSC_FLT_PERM   (0x0c)
#define FSC_SEA        (0x10) /* Synchronous External Abort */
#define FSC_SPE        (0x18) /* Memory Access Synchronous Parity Error */
#define FSC_APE        (0x11) /* Memory Access Asynchronous Parity Error */
#define FSC_SEATT      (0x14) /* Sync. Ext. Abort Translation Table */
#define FSC_SPETT      (0x1c) /* Sync. Parity. Error Translation Table */
#define FSC_AF         (0x21) /* Alignment Fault */
#define FSC_DE         (0x22) /* Debug Event */
#define FSC_LKD        (0x34) /* Lockdown Abort */
#define FSC_CPR        (0x3a) /* Coprocossor Abort */

#define FSC_LL_MASK    (_AC(0x03,U)<<0)

/* Time counter hypervisor control register */
#define CNTHCTL_EL2_EL1PCTEN (1u<<0) /* Kernel/user access to physical counter */
#define CNTHCTL_EL2_EL1PCEN  (1u<<1) /* Kernel/user access to CNTP timer regs */

/* Time counter kernel control register */
#define CNTKCTL_EL1_EL0PCTEN (1u<<0) /* Expose phys counters to EL0 */
#define CNTKCTL_EL1_EL0VCTEN (1u<<1) /* Expose virt counters to EL0 */
#define CNTKCTL_EL1_EL0VTEN  (1u<<8) /* Expose virt timer registers to EL0 */
#define CNTKCTL_EL1_EL0PTEN  (1u<<9) /* Expose phys timer registers to EL0 */

/* Timer control registers */
#define CNTx_CTL_ENABLE   (1u<<0)  /* Enable timer */
#define CNTx_CTL_MASK     (1u<<1)  /* Mask IRQ */
#define CNTx_CTL_PENDING  (1u<<2)  /* IRQ pending */

/* Exception Vector offsets */
/* ... ARM32 */
#define VECTOR32_RST  0
#define VECTOR32_UND  4
#define VECTOR32_SVC  8
#define VECTOR32_PABT 12
#define VECTOR32_DABT 16
/* ... ARM64 */
#define VECTOR64_CURRENT_SP0_BASE  0x000
#define VECTOR64_CURRENT_SPx_BASE  0x200
#define VECTOR64_LOWER64_BASE      0x400
#define VECTOR64_LOWER32_BASE      0x600

#define VECTOR64_SYNC_OFFSET       0x000
#define VECTOR64_IRQ_OFFSET        0x080
#define VECTOR64_FIQ_OFFSET        0x100
#define VECTOR64_ERROR_OFFSET      0x180


#if defined(CONFIG_ARM_32)
# include <asm/arm32/processor.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/processor.h>
#else
# error "unknown ARM variant"
#endif

#ifndef __ASSEMBLY__
extern uint32_t hyp_traps_vector[];

void init_traps(void);

void panic_PAR(uint64_t par);

void show_execution_state(struct cpu_user_regs *regs);
void show_registers(struct cpu_user_regs *regs);
//#define dump_execution_state() run_in_exception_handler(show_execution_state)
#define dump_execution_state() WARN()

#define cpu_relax() barrier() /* Could yield? */

/* All a bit UP for the moment */
#define cpu_to_core(_cpu)   (0)
#define cpu_to_socket(_cpu) (0)

void noreturn do_unexpected_trap(const char *msg, struct cpu_user_regs *regs);

void vcpu_regs_hyp_to_user(const struct vcpu *vcpu,
                           struct vcpu_guest_core_regs *regs);
void vcpu_regs_user_to_hyp(struct vcpu *vcpu,
                           const struct vcpu_guest_core_regs *regs);

int call_smc(register_t function_id, register_t arg0, register_t arg1,
             register_t arg2);

#endif /* __ASSEMBLY__ */
#endif /* __ASM_ARM_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
