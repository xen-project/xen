#ifndef __ASM_ARM_ARM32_PROCESSOR_H
#define __ASM_ARM_ARM32_PROCESSOR_H

#include <asm/cpregs.h>

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

/* Layout as used in assembly, with src/dest registers mixed in */
#define __CP32(r, coproc, opc1, crn, crm, opc2) coproc, opc1, r, crn, crm, opc2
#define __CP64(r1, r2, coproc, opc, crm) coproc, opc, r1, r2, crm
#define CP32(r, name...) __CP32(r, name)
#define CP64(r, name...) __CP64(r, name)

/* Stringified for inline assembly */
#define LOAD_CP32(r, name...)  "mrc " __stringify(CP32(%r, name)) ";"
#define STORE_CP32(r, name...) "mcr " __stringify(CP32(%r, name)) ";"
#define LOAD_CP64(r, name...)  "mrrc " __stringify(CP64(%r, %H##r, name)) ";"
#define STORE_CP64(r, name...) "mcrr " __stringify(CP64(%r, %H##r, name)) ";"

/* Issue a CP operation which takes no argument,
 * uses r0 as a placeholder register. */
#define CMD_CP32(name...)      "mcr " __stringify(CP32(r0, name)) ";"

#ifndef __ASSEMBLY__

/* C wrappers */
#define READ_CP32(name...) ({                                   \
    register uint32_t _r;                                       \
    asm volatile(LOAD_CP32(0, name) : "=r" (_r));               \
    _r; })

#define WRITE_CP32(v, name...) do {                             \
    register uint32_t _r = (v);                                 \
    asm volatile(STORE_CP32(0, name) : : "r" (_r));             \
} while (0)

#define READ_CP64(name...) ({                                   \
    register uint64_t _r;                                       \
    asm volatile(LOAD_CP64(0, name) : "=r" (_r));               \
    _r; })

#define WRITE_CP64(v, name...) do {                             \
    register uint64_t _r = (v);                                 \
    asm volatile(STORE_CP64(0, name) : : "r" (_r));             \
} while (0)

/*
 * C wrappers for accessing system registers.
 *
 * Registers come in 3 types:
 * - those which are always 32-bit regardless of AArch32 vs AArch64
 *   (use {READ,WRITE}_SYSREG32).
 * - those which are always 64-bit regardless of AArch32 vs AArch64
 *   (use {READ,WRITE}_SYSREG64).
 * - those which vary between AArch32 and AArch64 (use {READ,WRITE}_SYSREG).
 */
#define READ_SYSREG32(R...)     READ_CP32(R)
#define WRITE_SYSREG32(V, R...) WRITE_CP32(V, R)

#define READ_SYSREG64(R...)     READ_CP64(R)
#define WRITE_SYSREG64(V, R...) WRITE_CP64(V, R)

#define READ_SYSREG(R...)       READ_SYSREG32(R)
#define WRITE_SYSREG(V, R...)   WRITE_SYSREG32(V, R)

#endif /* __ASSEMBLY__ */

#endif /* __ASM_ARM_ARM32_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
