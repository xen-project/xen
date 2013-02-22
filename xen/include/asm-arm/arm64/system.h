/* Portions taken from Linux arch arm64 */
#ifndef __ASM_ARM64_SYSTEM_H
#define __ASM_ARM64_SYSTEM_H

#define sev()           asm volatile("sev" : : : "memory")
#define wfe()           asm volatile("wfe" : : : "memory")
#define wfi()           asm volatile("wfi" : : : "memory")

#define isb()           asm volatile("isb" : : : "memory")
#define dsb()           asm volatile("dsb sy" : : : "memory")
#define dmb()           asm volatile("dmb sy" : : : "memory")

#define mb()            dsb()
#define rmb()           dsb()
#define wmb()           mb()

#define smp_mb()        mb()
#define smp_rmb()       rmb()
#define smp_wmb()       wmb()

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
