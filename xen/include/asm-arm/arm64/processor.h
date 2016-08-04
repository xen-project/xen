#ifndef __ASM_ARM_ARM64_PROCESSOR_H
#define __ASM_ARM_ARM64_PROCESSOR_H

#include <xen/stringify.h>

#ifndef __ASSEMBLY__

/* Anonymous union includes both 32- and 64-bit names (e.g., r0/x0). */

#define __DECL_REG(n64, n32) union {            \
    uint64_t n64;                               \
    uint32_t n32;                               \
}

/* On stack VCPU state */
struct cpu_user_regs
{
    /*
     * The mapping AArch64 <-> AArch32 is based on D1.20.1 in ARM DDI
     * 0487A.d.
     *
     *         AArch64       AArch32
     */
    __DECL_REG(x0,           r0/*_usr*/);
    __DECL_REG(x1,           r1/*_usr*/);
    __DECL_REG(x2,           r2/*_usr*/);
    __DECL_REG(x3,           r3/*_usr*/);
    __DECL_REG(x4,           r4/*_usr*/);
    __DECL_REG(x5,           r5/*_usr*/);
    __DECL_REG(x6,           r6/*_usr*/);
    __DECL_REG(x7,           r7/*_usr*/);
    __DECL_REG(x8,           r8/*_usr*/);
    __DECL_REG(x9,           r9/*_usr*/);
    __DECL_REG(x10,          r10/*_usr*/);
    __DECL_REG(x11 ,         r11/*_usr*/);
    __DECL_REG(x12,          r12/*_usr*/);

    __DECL_REG(x13,          /* r13_usr */ sp_usr);
    __DECL_REG(x14,          /* r14_usr */ lr_usr);

    __DECL_REG(x15,          /* r13_hyp */ __unused_sp_hyp);

    __DECL_REG(x16,          /* r14_irq */ lr_irq);
    __DECL_REG(x17,          /* r13_irq */ sp_irq);

    __DECL_REG(x18,          /* r14_svc */ lr_svc);
    __DECL_REG(x19,          /* r13_svc */ sp_svc);

    __DECL_REG(x20,          /* r14_abt */ lr_abt);
    __DECL_REG(x21,          /* r13_abt */ sp_abt);

    __DECL_REG(x22,          /* r14_und */ lr_und);
    __DECL_REG(x23,          /* r13_und */ sp_und);

    __DECL_REG(x24,          r8_fiq);
    __DECL_REG(x25,          r9_fiq);
    __DECL_REG(x26,          r10_fiq);
    __DECL_REG(x27,          r11_fiq);
    __DECL_REG(x28,          r12_fiq);
    __DECL_REG(/* x29 */ fp, /* r13_fiq */ sp_fiq);

    __DECL_REG(/* x30 */ lr, /* r14_fiq */ lr_fiq);

    register_t sp; /* Valid for hypervisor frames */

    /* Return address and mode */
    __DECL_REG(pc,           pc32);             /* ELR_EL2 */
    uint32_t cpsr;                              /* SPSR_EL2 */

    uint32_t pad0; /* Align end of kernel frame. */

    /* Outer guest frame only from here on... */

    union {
        uint32_t spsr_el1;       /* AArch64 */
        uint32_t spsr_svc;       /* AArch32 */
    };

    uint32_t pad1; /* Doubleword-align the user half of the frame */

    /* AArch32 guests only */
    uint32_t spsr_fiq, spsr_irq, spsr_und, spsr_abt;

    /* AArch64 guests only */
    uint64_t sp_el0;
    uint64_t sp_el1, elr_el1;
};

#undef __DECL_REG

/* Access to system registers */

#define READ_SYSREG32(name) ({                          \
    uint32_t _r;                                        \
    asm volatile("mrs  %0, "__stringify(name) : "=r" (_r));         \
    _r; })
#define WRITE_SYSREG32(v, name) do {                    \
    uint32_t _r = v;                                    \
    asm volatile("msr "__stringify(name)", %0" : : "r" (_r));       \
} while (0)

#define WRITE_SYSREG64(v, name) do {                    \
    uint64_t _r = v;                                    \
    asm volatile("msr "__stringify(name)", %0" : : "r" (_r));       \
} while (0)
#define READ_SYSREG64(name) ({                          \
    uint64_t _r;                                        \
    asm volatile("mrs  %0, "__stringify(name) : "=r" (_r));         \
    _r; })

#define READ_SYSREG(name)     READ_SYSREG64(name)
#define WRITE_SYSREG(v, name) WRITE_SYSREG64(v, name)

#endif /* __ASSEMBLY__ */

#endif /* __ASM_ARM_ARM64_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
