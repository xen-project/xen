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


extern void __bad_xchg(volatile void *, int);

static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
        unsigned long ret, tmp;

        switch (size) {
        case 1:
                asm volatile("//        __xchg1\n"
                "1:     ldaxrb  %w0, [%3]\n"
                "       stlxrb  %w1, %w2, [%3]\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        case 2:
                asm volatile("//        __xchg2\n"
                "1:     ldaxrh  %w0, [%3]\n"
                "       stlxrh  %w1, %w2, [%3]\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        case 4:
                asm volatile("//        __xchg4\n"
                "1:     ldaxr   %w0, [%3]\n"
                "       stlxr   %w1, %w2, [%3]\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        case 8:
                asm volatile("//        __xchg8\n"
                "1:     ldaxr   %0, [%3]\n"
                "       stlxr   %w1, %2, [%3]\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp)
                        : "r" (x), "r" (ptr)
                        : "memory", "cc");
                break;
        default:
                __bad_xchg(ptr, size), ret = 0;
                break;
        }

        return ret;
}

#define xchg(ptr,x) \
        ((__typeof__(*(ptr)))__xchg((unsigned long)(x),(ptr),sizeof(*(ptr))))

extern void __bad_cmpxchg(volatile void *ptr, int size);

static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
                                      unsigned long new, int size)
{
        unsigned long oldval = 0, res;

        switch (size) {
        case 1:
                do {
                        asm volatile("// __cmpxchg1\n"
                        "       ldxrb   %w1, [%2]\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxrb   %w0, %w4, [%2]\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval)
                                : "r" (ptr), "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        case 2:
                do {
                        asm volatile("// __cmpxchg2\n"
                        "       ldxrh   %w1, [%2]\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxrh   %w0, %w4, [%2]\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval)
                                : "r" (ptr), "Ir" (old), "r" (new)
                                : "memory", "cc");
                } while (res);
                break;

        case 4:
                do {
                        asm volatile("// __cmpxchg4\n"
                        "       ldxr    %w1, [%2]\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxr    %w0, %w4, [%2]\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval)
                                : "r" (ptr), "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        case 8:
                do {
                        asm volatile("// __cmpxchg8\n"
                        "       ldxr    %1, [%2]\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %1, %3\n"
                        "       b.ne    1f\n"
                        "       stxr    %w0, %4, [%2]\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval)
                                : "r" (ptr), "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        default:
		__bad_cmpxchg(ptr, size);
		oldval = 0;
        }

        return oldval;
}

static inline unsigned long __cmpxchg_mb(volatile void *ptr, unsigned long old,
                                         unsigned long new, int size)
{
        unsigned long ret;

        smp_mb();
        ret = __cmpxchg(ptr, old, new, size);
        smp_mb();

        return ret;
}

#define cmpxchg(ptr,o,n)                                                \
        ((__typeof__(*(ptr)))__cmpxchg_mb((ptr),                        \
                                          (unsigned long)(o),           \
                                          (unsigned long)(n),           \
                                          sizeof(*(ptr))))

#define cmpxchg_local(ptr,o,n)                                          \
        ((__typeof__(*(ptr)))__cmpxchg((ptr),                           \
                                       (unsigned long)(o),              \
                                       (unsigned long)(n),              \
                                       sizeof(*(ptr))))

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
