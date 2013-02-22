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

extern void __bad_xchg(volatile void *, int);

static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
        unsigned long ret;
        unsigned int tmp;

        smp_mb();

        switch (size) {
        case 1:
                asm volatile("@ __xchg1\n"
                "1:     ldrexb  %0, [%3]\n"
                "       strexb  %1, %2, [%3]\n"
                "       teq     %1, #0\n"
                "       bne     1b"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        case 4:
                asm volatile("@ __xchg4\n"
                "1:     ldrex   %0, [%3]\n"
                "       strex   %1, %2, [%3]\n"
                "       teq     %1, #0\n"
                "       bne     1b"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        default:
                __bad_xchg(ptr, size), ret = 0;
                break;
        }
        smp_mb();

        return ret;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

extern void __bad_cmpxchg(volatile void *ptr, int size);

static always_inline unsigned long __cmpxchg(
    volatile void *ptr, unsigned long old, unsigned long new, int size)
{
    unsigned long /*long*/ oldval, res;

    switch (size) {
    case 1:
        do {
            asm volatile("@ __cmpxchg1\n"
                         "       ldrexb  %1, [%2]\n"
                         "       mov     %0, #0\n"
                         "       teq     %1, %3\n"
                         "       strexbeq %0, %4, [%2]\n"
                         : "=&r" (res), "=&r" (oldval)
                         : "r" (ptr), "Ir" (old), "r" (new)
                         : "memory", "cc");
        } while (res);
        break;
    case 2:
        do {
            asm volatile("@ __cmpxchg2\n"
                         "       ldrexh  %1, [%2]\n"
                         "       mov     %0, #0\n"
                         "       teq     %1, %3\n"
                         "       strexheq %0, %4, [%2]\n"
                         : "=&r" (res), "=&r" (oldval)
                         : "r" (ptr), "Ir" (old), "r" (new)
                         : "memory", "cc");
        } while (res);
        break;
    case 4:
        do {
            asm volatile("@ __cmpxchg4\n"
                         "       ldrex   %1, [%2]\n"
                         "       mov     %0, #0\n"
                         "       teq     %1, %3\n"
                         "       strexeq %0, %4, [%2]\n"
                         : "=&r" (res), "=&r" (oldval)
                         : "r" (ptr), "Ir" (old), "r" (new)
                         : "memory", "cc");
        } while (res);
        break;
#if 0
    case 8:
        do {
            asm volatile("@ __cmpxchg8\n"
                         "       ldrexd   %1, [%2]\n"
                         "       mov      %0, #0\n"
                         "       teq      %1, %3\n"
                         "       strexdeq %0, %4, [%2]\n"
                         : "=&r" (res), "=&r" (oldval)
                         : "r" (ptr), "Ir" (old), "r" (new)
                         : "memory", "cc");
        } while (res);
        break;
#endif
    default:
        __bad_cmpxchg(ptr, size);
        oldval = 0;
    }

    return oldval;
}

#define cmpxchg(ptr,o,n)                                                \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)(o),            \
                                   (unsigned long)(n),sizeof(*(ptr))))

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
