/* Portions taken from Linux arch arm */
#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/lib.h>
#include <asm/processor.h>

#define nop() \
    asm volatile ( "nop" )

#define xchg(ptr,x) \
        ((__typeof__(*(ptr)))__xchg((unsigned long)(x),(ptr),sizeof(*(ptr))))

#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")

#define mb()            dsb()
#define rmb()           dsb()
#define wmb()           mb()

#define smp_mb()        dmb()
#define smp_rmb()       dmb()
#define smp_wmb()       dmb()

/*
 * This is used to ensure the compiler did actually allocate the register we
 * asked it for some inline assembly sequences.  Apparently we can't trust
 * the compiler from one version to another so a bit of paranoia won't hurt.
 * This string is meant to be concatenated with the inline asm string and
 * will cause compilation to stop on mismatch.
 * (for details, see gcc PR 15089)
 */
#define __asmeq(x, y)  ".ifnc " x "," y " ; .err ; .endif\n\t"

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

#define local_irq_disable() asm volatile ( "cpsid i @ local_irq_disable\n" : : : "cc" )
#define local_irq_enable()  asm volatile ( "cpsie i @ local_irq_enable\n" : : : "cc" )

#define local_save_flags(x)                                      \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile ( "mrs %0, cpsr     @ local_save_flags\n"       \
                  : "=r" (x) :: "memory", "cc" );                \
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
            "msr     cpsr_c, %0      @ local_irq_restore\n"      \
            :                                                    \
            : "r" (flags)                                        \
            : "memory", "cc");                                   \
})

static inline int local_irq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !(flags & PSR_IRQ_MASK);
}

#define local_fiq_enable()  __asm__("cpsie f   @ __stf\n" : : : "memory", "cc")
#define local_fiq_disable() __asm__("cpsid f   @ __clf\n" : : : "memory", "cc")

#define local_abort_enable() __asm__("cpsie a  @ __sta\n" : : : "memory", "cc")
#define local_abort_disable() __asm__("cpsid a @ __sta\n" : : : "memory", "cc")

static inline int local_fiq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !!(flags & PSR_FIQ_MASK);
}

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
