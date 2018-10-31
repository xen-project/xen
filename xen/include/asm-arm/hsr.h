#ifndef __ASM_ARM_HSR_H
#define __ASM_ARM_HSR_H

#include <xen/types.h>

#if defined(CONFIG_ARM_64)
# include <asm/arm64/hsr.h>
#endif

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

    /*
     * This encoding is valid only for ARMv8 (ARM DDI 0487B.a, pages D7-2271 and
     * G6-4957). On ARMv7, encoding ISS for EC=0x13 is defined as UNK/SBZP
     * (ARM DDI 0406C.c page B3-1431). UNK/SBZP means that hardware implements
     * this field as Read-As-Zero. ARMv8 is backwards compatible with ARMv7:
     * reading CCKNOWNPASS on ARMv7 will return 0, which means that condition
     * check was passed or instruction was unconditional.
     */
    struct hsr_smc32 {
        unsigned long res0:19;  /* Reserved */
        unsigned long ccknownpass:1; /* Instruction passed conditional check */
        unsigned long cc:4;    /* Condition Code */
        unsigned long ccvalid:1;/* CC Valid */
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } smc32; /* HSR_EC_SMC32 */

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
        unsigned long res0:1;  /* RES0 */
        unsigned long s1ptw:1; /* Stage 2 fault during stage 1 translation */
        unsigned long res1:1;  /* RES0 */
        unsigned long eat:1;   /* External abort type */
        unsigned long fnv:1;   /* FAR not Valid */
        unsigned long res2:14;
        unsigned long len:1;   /* Instruction length */
        unsigned long ec:6;    /* Exception Class */
    } iabt; /* HSR_EC_INSTR_ABORT_* */

    struct hsr_dabt {
        unsigned long dfsc:6;  /* Data Fault Status Code */
        unsigned long write:1; /* Write / not Read */
        unsigned long s1ptw:1; /* Stage 2 fault during stage 1 translation */
        unsigned long cache:1; /* Cache Maintenance */
        unsigned long eat:1;   /* External Abort Type */
        unsigned long fnv:1;   /* FAR not Valid */
#ifdef CONFIG_ARM_32
        unsigned long sbzp0:5;
#else
        unsigned long sbzp0:3;
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

    /* Contain the common bits between DABT and IABT */
    struct hsr_xabt {
        unsigned long fsc:6;    /* Fault status code */
        unsigned long pad1:1;   /* Not common */
        unsigned long s1ptw:1;  /* Stage 2 fault during stage 1 translation */
        unsigned long pad2:1;   /* Not common */
        unsigned long eat:1;    /* External abort type */
        unsigned long fnv:1;    /* FAR not Valid */
        unsigned long pad3:14;  /* Not common */
        unsigned long len:1;    /* Instruction length */
        unsigned long ec:6;     /* Exception Class */
    } xabt;

#ifdef CONFIG_ARM_64
    struct hsr_brk {
        unsigned long comment:16;   /* Comment */
        unsigned long res0:9;
        unsigned long len:1;        /* Instruction length */
        unsigned long ec:6;         /* Exception Class */
    } brk;
#endif
};

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

/* HSR.EC == HSR_{HVC32, HVC64, SMC64, SVC32, SVC64} */
#define HSR_XXC_IMM_MASK     (0xffff)

#endif /* __ASM_ARM_HSR_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
