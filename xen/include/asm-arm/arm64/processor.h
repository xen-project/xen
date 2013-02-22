#ifndef __ASM_ARM_ARM64_PROCESSOR_H
#define __ASM_ARM_ARM64_PROCESSOR_H

#ifndef __ASSEMBLY__

#define READ_SYSREG32(name) ({                          \
    uint32_t _r;                                        \
    asm volatile("mrs  %0, "#name : "=r" (_r));         \
    _r; })
#define WRITE_SYSREG32(v, name) do {                    \
    uint32_t _r = v;                                    \
    asm volatile("msr "#name", %0" : : "r" (_r));       \
} while (0)

#define WRITE_SYSREG64(v, name) do {                    \
    uint64_t _r = v;                                    \
    asm volatile("msr "#name", %0" : : "r" (_r));       \
} while (0)
#define READ_SYSREG64(name) ({                          \
    uint64_t _r;                                        \
    asm volatile("mrs  %0, "#name : "=r" (_r));         \
    _r; })

#define READ_SYSREG(name)     READ_SYSREG64(name)
#define WRITE_SYSREG(v, name) WRITE_SYSREG64(v, name)

#endif /* __ASSEMBLY__ */

#endif /* __ASM_ARM_ARM64_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
