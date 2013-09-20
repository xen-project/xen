#ifndef __ASM_ARM_PROCESSOR_H
#define __ASM_ARM_PROCESSOR_H

#include <asm/cpregs.h>
#include <asm/sysregs.h>

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

/* TTBCR Translation Table Base Control Register */
#define TTBCR_EAE    0x80000000
#define TTBCR_N_MASK 0x07
#define TTBCR_N_16KB 0x00
#define TTBCR_N_8KB  0x01
#define TTBCR_N_4KB  0x02
#define TTBCR_N_2KB  0x03
#define TTBCR_N_1KB  0x04

/* SCTLR System Control Register. */
/* HSCTLR is a subset of this. */
#define SCTLR_TE        (1<<30)
#define SCTLR_AFE       (1<<29)
#define SCTLR_TRE       (1<<28)
#define SCTLR_NMFI      (1<<27)
#define SCTLR_EE        (1<<25)
#define SCTLR_VE        (1<<24)
#define SCTLR_U         (1<<22)
#define SCTLR_FI        (1<<21)
#define SCTLR_WXN       (1<<19)
#define SCTLR_HA        (1<<17)
#define SCTLR_RR        (1<<14)
#define SCTLR_V         (1<<13)
#define SCTLR_I         (1<<12)
#define SCTLR_Z         (1<<11)
#define SCTLR_SW        (1<<10)
#define SCTLR_B         (1<<7)
#define SCTLR_C         (1<<2)
#define SCTLR_A         (1<<1)
#define SCTLR_M         (1<<0)

#define SCTLR_BASE        0x00c50078
#define HSCTLR_BASE       0x30c51878

#define PSR_GUEST32_INIT  (PSR_ABT_MASK|PSR_FIQ_MASK|PSR_IRQ_MASK|PSR_MODE_SVC)

#ifdef CONFIG_ARM_64
#define PSR_GUEST64_INIT (PSR_ABT_MASK|PSR_FIQ_MASK|PSR_IRQ_MASK|PSR_MODE_EL1h)
#endif

/* HCR Hyp Configuration Register */
#define HCR_RW          (1<<31) /* Register Width, ARM64 only */
#define HCR_TGE         (1<<27) /* Trap General Exceptions */
#define HCR_TVM         (1<<26) /* Trap Virtual Memory Controls */
#define HCR_TTLB        (1<<25) /* Trap TLB Maintenance Operations */
#define HCR_TPU         (1<<24) /* Trap Cache Maintenance Operations to PoU */
#define HCR_TPC         (1<<23) /* Trap Cache Maintenance Operations to PoC */
#define HCR_TSW         (1<<22) /* Trap Set/Way Cache Maintenance Operations */
#define HCR_TAC         (1<<21) /* Trap ACTLR Accesses */
#define HCR_TIDCP       (1<<20) /* Trap lockdown */
#define HCR_TSC         (1<<19) /* Trap SMC instruction */
#define HCR_TID3        (1<<18) /* Trap ID Register Group 3 */
#define HCR_TID2        (1<<17) /* Trap ID Register Group 2 */
#define HCR_TID1        (1<<16) /* Trap ID Register Group 1 */
#define HCR_TID0        (1<<15) /* Trap ID Register Group 0 */
#define HCR_TWE         (1<<14) /* Trap WFE instruction */
#define HCR_TWI         (1<<13) /* Trap WFI instruction */
#define HCR_DC          (1<<12) /* Default cacheable */
#define HCR_BSU_MASK    (3<<10) /* Barrier Shareability Upgrade */
#define HCR_BSU_NONE     (0<<10)
#define HCR_BSU_INNER    (1<<10)
#define HCR_BSU_OUTER    (2<<10)
#define HCR_BSU_FULL     (3<<10)
#define HCR_FB          (1<<9) /* Force Broadcast of Cache/BP/TLB operations */
#define HCR_VA          (1<<8) /* Virtual Asynchronous Abort */
#define HCR_VI          (1<<7) /* Virtual IRQ */
#define HCR_VF          (1<<6) /* Virtual FIQ */
#define HCR_AMO         (1<<5) /* Override CPSR.A */
#define HCR_IMO         (1<<4) /* Override CPSR.I */
#define HCR_FMO         (1<<3) /* Override CPSR.F */
#define HCR_PTW         (1<<2) /* Protected Walk */
#define HCR_SWIO        (1<<1) /* Set/Way Invalidation Override */
#define HCR_VM          (1<<0) /* Virtual MMU Enable */

#define HSR_EC_UNKNOWN              0x00
#define HSR_EC_WFI_WFE              0x01
#define HSR_EC_CP15_32              0x03
#define HSR_EC_CP15_64              0x04
#define HSR_EC_CP14_32              0x05
#define HSR_EC_CP14_DBG             0x06
#define HSR_EC_CP                   0x07
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
#define HSR_EC_INSTR_ABORT_GUEST    0x20
#define HSR_EC_INSTR_ABORT_HYP      0x21
#define HSR_EC_DATA_ABORT_GUEST     0x24
#define HSR_EC_DATA_ABORT_HYP       0x25

#ifndef __ASSEMBLY__

#include <xen/types.h>

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
            unsigned long __res0:8;

            unsigned long __res1;
        };
    } pfr64;

    struct {
        uint64_t bits[2];
    } dbg64;

    struct {
        uint64_t bits[2];
    } aux64;

    struct {
        uint64_t bits[2];
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

    struct hsr_dabt {
        unsigned long dfsc:6;  /* Data Fault Status Code */
        unsigned long write:1; /* Write / not Read */
        unsigned long s1ptw:1; /* */
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
#define HSR_SYSREG_CRN_MASK (0x00003800)
#define HSR_SYSREG_CRN_SHIFT (10)
#define HSR_SYSREG_CRM_MASK (0x0000001e)
#define HSR_SYSREG_CRM_SHIFT (1)
#define HSR_SYSREG_OP2_MASK (0x000e0000)
#define HSR_SYSREG_OP2_SHIFT (17)
#define HSR_SYSREG_REGS_MASK (HSR_SYSREG_OP0_MASK|HSR_SYSREG_OP1_MASK|\
                              HSR_SYSREG_CRN_MASK|HSR_SYSREG_CRM_MASK|\
                              HSR_SYSREG_OP2_MASK)

/* Physical Address Register */
#define PAR_F           (1<<0)

/* .... If F == 1 */
#define PAR_FSC_SHIFT   (1)
#define PAR_FSC_MASK    (0x3f<<PAR_FSC_SHIFT)
#define PAR_STAGE21     (1<<8)     /* Stage 2 Fault During Stage 1 Walk */
#define PAR_STAGE2      (1<<9)     /* Stage 2 Fault */

/* If F == 0 */
#define PAR_MAIR_SHIFT  56                       /* Memory Attributes */
#define PAR_MAIR_MASK   (0xffLL<<PAR_MAIR_SHIFT)
#define PAR_NS          (1<<9)                   /* Non-Secure */
#define PAR_SH_SHIFT    7                        /* Shareability */
#define PAR_SH_MASK     (3<<PAR_SH_SHIFT)

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
#define FSC_TYPE_MASK (0x3<<4)
#define FSC_TYPE_FAULT (0x00<<4)
#define FSC_TYPE_ABT   (0x01<<4)
#define FSC_TYPE_OTH   (0x02<<4)
#define FSC_TYPE_IMPL  (0x03<<4)

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

#define FSC_LL_MASK    (0x03<<0)

/* Time counter hypervisor control register */
#define CNTHCTL_PA      (1u<<0)  /* Kernel/user access to physical counter */
#define CNTHCTL_TA      (1u<<1)  /* Kernel/user access to CNTP timer */

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
#define VECTOR64_CURRENT_SP0_SYNC  0x000
#define VECTOR64_CURRENT_SP0_IRQ   0x080
#define VECTOR64_CURRENT_SP0_FIQ   0x100
#define VECTOR64_CURRENT_SP0_ERROR 0x180
#define VECTOR64_CURRENT_SPx_SYNC  0x200
#define VECTOR64_CURRENT_SPx_IRQ   0x280
#define VECTOR64_CURRENT_SPx_FIQ   0x300
#define VECTOR64_CURRENT_SPx_ERROR 0x380

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
#define dump_execution_state() asm volatile (".word 0xe7f000f0\n"); /* XXX */

#define cpu_relax() barrier() /* Could yield? */

/* All a bit UP for the moment */
#define cpu_to_core(_cpu)   (0)
#define cpu_to_socket(_cpu) (0)

void do_unexpected_trap(const char *msg, struct cpu_user_regs *regs);

void vcpu_regs_hyp_to_user(const struct vcpu *vcpu,
                           struct vcpu_guest_core_regs *regs);
void vcpu_regs_user_to_hyp(struct vcpu *vcpu,
                           const struct vcpu_guest_core_regs *regs);

struct cpuinfo_x86 {
    uint32_t pfr32[2];
};

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
