#ifndef __ASM_ARM_ARM32_PROCESSOR_H
#define __ASM_ARM_ARM32_PROCESSOR_H

#define ACTLR_CAXX_SMP      (1<<6)

#ifndef __ASSEMBLY__
/* On stack VCPU state */
struct cpu_user_regs
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    union {
        uint32_t r11;
        uint32_t fp;
    };
    uint32_t r12;

    uint32_t sp; /* r13 - SP: Valid for Hyp. frames only, o/w banked (see below) */

    /* r14 - LR: is the same physical register as LR_usr */
    union {
        uint32_t lr; /* r14 - LR: Valid for Hyp. Same physical register as lr_usr. */

        uint32_t lr_usr;
    };

    union {  /* Return IP, pc32 is used to allow code to be common with 64-bit */
        uint32_t pc, pc32;
    };
    uint32_t cpsr; /* Return mode */
    uint32_t hsr;  /* Exception Syndrome */

    /* Outer guest frame only from here on... */

    uint32_t sp_usr; /* LR_usr is the same register as LR, see above */

    uint32_t sp_irq, lr_irq;
    uint32_t sp_svc, lr_svc;
    uint32_t sp_abt, lr_abt;
    uint32_t sp_und, lr_und;

    uint32_t r8_fiq, r9_fiq, r10_fiq, r11_fiq, r12_fiq;
    uint32_t sp_fiq, lr_fiq;

    uint32_t spsr_svc, spsr_abt, spsr_und, spsr_irq, spsr_fiq;

    uint32_t pad1; /* Doubleword-align the user half of the frame */
};

#endif

#endif /* __ASM_ARM_ARM32_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
