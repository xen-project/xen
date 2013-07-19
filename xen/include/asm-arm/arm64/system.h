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
                "1:     ldaxrb  %w0, %2\n"
                "       stlxrb  %w1, %w3, %2\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp), "+Q" (*(u8 *)ptr)
                        : "r" (x)
                        : "cc", "memory");
                break;
        case 2:
                asm volatile("//        __xchg2\n"
                "1:     ldaxrh  %w0, %2\n"
                "       stlxrh  %w1, %w3, %2\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp), "+Q" (*(u16 *)ptr)
                        : "r" (x)
                        : "cc", "memory");
                break;
        case 4:
                asm volatile("//        __xchg4\n"
                "1:     ldaxr   %w0, %2\n"
                "       stlxr   %w1, %w3, %2\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp), "+Q" (*(u32 *)ptr)
                        : "r" (x)
                        : "cc", "memory");
                break;
        case 8:
                asm volatile("//        __xchg8\n"
                "1:     ldaxr   %0, %2\n"
                "       stlxr   %w1, %3, %2\n"
                "       cbnz    %w1, 1b\n"
                        : "=&r" (ret), "=&r" (tmp), "+Q" (*(u64 *)ptr)
                        : "r" (x)
                        : "cc", "memory");
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
                        "       ldxrb   %w1, %2\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxrb   %w0, %w4, %2\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval), "+Q" (*(u8 *)ptr)
                                : "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        case 2:
                do {
                        asm volatile("// __cmpxchg2\n"
                        "       ldxrh   %w1, %2\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxrh   %w0, %w4, %2\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval), "+Q" (*(u16 *)ptr)
                                : "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        case 4:
                do {
                        asm volatile("// __cmpxchg4\n"
                        "       ldxr    %w1, %2\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %w1, %w3\n"
                        "       b.ne    1f\n"
                        "       stxr    %w0, %w4, %2\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval), "+Q" (*(u32 *)ptr)
                                : "Ir" (old), "r" (new)
                                : "cc");
                } while (res);
                break;

        case 8:
                do {
                        asm volatile("// __cmpxchg8\n"
                        "       ldxr    %1, %2\n"
                        "       mov     %w0, #0\n"
                        "       cmp     %1, %3\n"
                        "       b.ne    1f\n"
                        "       stxr    %w0, %4, %2\n"
                        "1:\n"
                                : "=&r" (res), "=&r" (oldval), "+Q" (*(u64 *)ptr)
                                : "Ir" (old), "r" (new)
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

/* Uses uimm4 as a bitmask to select the clearing of one or more of
 * the DAIF exception mask bits:
 * bit 3 selects the D mask,
 * bit 2 the A mask,
 * bit 1 the I mask and
 * bit 0 the F mask.
*/

#define local_fiq_disable()   asm volatile ( "msr daifset, #1\n" ::: "memory" )
#define local_fiq_enable()    asm volatile ( "msr daifclr, #1\n" ::: "memory" )
#define local_irq_disable()   asm volatile ( "msr daifset, #2\n" ::: "memory" )
#define local_irq_enable()    asm volatile ( "msr daifclr, #2\n" ::: "memory" )
#define local_abort_disable() asm volatile ( "msr daifset, #4\n" ::: "memory" )
#define local_abort_enable()  asm volatile ( "msr daifclr, #4\n" ::: "memory" )

#define local_save_flags(x)                                      \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile(                                                \
        "mrs    %0, daif    // local_save_flags\n"               \
                : "=r" (x)                                       \
                :                                                \
                : "memory");                                     \
})

#define local_irq_save(x)                                        \
({                                                               \
    local_save_flags(x);                                         \
    local_irq_disable();                                         \
})
#define local_irq_restore(x)                                     \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile (                                               \
        "msr    daif, %0                // local_irq_restore"    \
        :                                                        \
        : "r" (flags)                                            \
        : "memory");                                             \
})

static inline int local_irq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !(flags & PSR_IRQ_MASK);
}

static inline int local_fiq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !(flags & PSR_FIQ_MASK);
}

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
