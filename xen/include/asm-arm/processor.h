#ifndef __ASM_ARM_PROCESSOR_H
#define __ASM_ARM_PROCESSOR_H

#include <asm/cpregs.h>

/* PSR bits (CPSR, SPSR)*/

/* 0-4: Mode */
#define PSR_MODE_MASK 0x1f
#define PSR_MODE_USR 0x10
#define PSR_MODE_FIQ 0x11
#define PSR_MODE_IRQ 0x12
#define PSR_MODE_SVC 0x13
#define PSR_MODE_MON 0x16
#define PSR_MODE_ABT 0x17
#define PSR_MODE_HYP 0x1a
#define PSR_MODE_UND 0x1b
#define PSR_MODE_SYS 0x1f

#define PSR_THUMB       (1<<5)        /* Thumb Mode enable */
#define PSR_FIQ_MASK    (1<<6)        /* Fast Interrupt mask */
#define PSR_IRQ_MASK    (1<<7)        /* Interrupt mask */
#define PSR_ABT_MASK    (1<<8)        /* Asynchronous Abort mask */
#define PSR_BIG_ENDIAN  (1<<9)        /* Big Endian Mode */
#define PSR_JAZELLE     (1<<24)       /* Jazelle Mode */

/* TTBCR Translation Table Base Control Register */
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

/* HCR Hyp Configuration Register */
#define HCR_TGE         (1<<27)
#define HCR_TVM         (1<<26)
#define HCR_TTLB        (1<<25)
#define HCR_TPU         (1<<24)
#define HCR_TPC         (1<<23)
#define HCR_TSW         (1<<22)
#define HCR_TAC         (1<<21)
#define HCR_TIDCP       (1<<20)
#define HCR_TSC         (1<<19)
#define HCR_TID3        (1<<18)
#define HCR_TID2        (1<<17)
#define HCR_TID1        (1<<16)
#define HCR_TID0        (1<<15)
#define HCR_TWE         (1<<14)
#define HCR_TWI         (1<<13)
#define HCR_DC          (1<<12)
#define HCR_BSU_MASK    (3<<10)
#define HCR_FB          (1<<9)
#define HCR_VA          (1<<8)
#define HCR_VI          (1<<7)
#define HCR_VF          (1<<6)
#define HCR_AMO         (1<<5)
#define HCR_IMO         (1<<4)
#define HCR_FMO         (1<<3)
#define HCR_PTW         (1<<2)
#define HCR_SWIO        (1<<1)
#define HCR_VM          (1<<0)

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
#define HSR_EC_SVC                  0x11
#define HSR_EC_HVC                  0x12
#define HSR_EC_INSTR_ABORT_GUEST    0x20
#define HSR_EC_INSTR_ABORT_HYP      0x21
#define HSR_EC_DATA_ABORT_GUEST     0x24
#define HSR_EC_DATA_ABORT_HYP       0x25

#ifndef __ASSEMBLY__
union hsr {
    uint32_t bits;
    struct {
        unsigned long iss:25;  /* Instruction Specific Syndrome */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    };

    struct hsr_cp32 {
        unsigned long read:1;  /* Direction */
        unsigned long crm:4;   /* CRm */
        unsigned long reg:4;   /* Rt */
        unsigned long sbzp:1;
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
        unsigned long reg1:4;   /* Rt1 */
        unsigned long sbzp1:1;
        unsigned long reg2:4;   /* Rt2 */
        unsigned long sbzp2:2;
        unsigned long op1:4;   /* Op1 */
        unsigned long cc:4;    /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } cp64; /* HSR_EC_CP15_64, HSR_EC_CP14_64 */

    struct hsr_dabt {
        unsigned long dfsc:6;  /* Data Fault Status Code */
        unsigned long write:1; /* Write / not Read */
        unsigned long s1ptw:1; /* */
        unsigned long cache:1; /* Cache Maintenance */
        unsigned long eat:1;   /* External Abort Type */
        unsigned long sbzp0:6;
        unsigned long reg:4;   /* Register */
        unsigned long sbzp1:1;
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

/* CPUID bits */
#define ID_PFR1_GT_MASK  0x000F0000  /* Generic Timer interface support */
#define ID_PFR1_GT_v1    0x00010000

#define MSR(reg,val)        asm volatile ("msr "#reg", %0\n" : : "r" (val))
#define MRS(val,reg)        asm volatile ("mrs %0,"#reg"\n" : "=r" (v))

#ifndef __ASSEMBLY__
extern uint32_t hyp_traps_vector[8];

void panic_PAR(uint64_t par, const char *when);

void show_execution_state(struct cpu_user_regs *regs);
void show_registers(struct cpu_user_regs *regs);
//#define dump_execution_state() run_in_exception_handler(show_execution_state)
#define dump_execution_state() asm volatile (".word 0xe7f000f0\n"); /* XXX */

#define cpu_relax() barrier() /* Could yield? */

/* All a bit UP for the moment */
#define cpu_to_core(_cpu)   (0)
#define cpu_to_socket(_cpu) (0)

#endif /* __ASSEMBLY__ */
#endif /* __ASM_ARM_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
