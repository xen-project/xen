/* Portions taken from Linux arch arm64 */
#ifndef __ASM_ARM64_SYSTEM_H
#define __ASM_ARM64_SYSTEM_H

#include <asm/arm64/cmpxchg.h>

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
