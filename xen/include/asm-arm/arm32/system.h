/* Portions taken from Linux arch arm */
#ifndef __ASM_ARM32_SYSTEM_H
#define __ASM_ARM32_SYSTEM_H

#define sev() __asm__ __volatile__ ("sev" : : : "memory")
#define wfe() __asm__ __volatile__ ("wfe" : : : "memory")
#define wfi() __asm__ __volatile__ ("wfi" : : : "memory")

#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")

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
