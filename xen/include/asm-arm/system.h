/* Portions taken from Linux arch arm */
#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/lib.h>
#include <public/arch-arm.h>

#define nop() \
    asm volatile ( "nop" )

#define xchg(ptr,x) \
        ((__typeof__(*(ptr)))__xchg((unsigned long)(x),(ptr),sizeof(*(ptr))))

/*
 * This is used to ensure the compiler did actually allocate the register we
 * asked it for some inline assembly sequences.  Apparently we can't trust
 * the compiler from one version to another so a bit of paranoia won't hurt.
 * This string is meant to be concatenated with the inline asm string and
 * will cause compilation to stop on mismatch.
 * (for details, see gcc PR 15089)
 */
#define __asmeq(x, y)  ".ifnc " x "," y " ; .err ; .endif\n\t"

#if defined(CONFIG_ARM_32)
# include <asm/arm32/system.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/system.h>
#else
# error "unknown ARM variant"
#endif

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

extern struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
