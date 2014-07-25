/* Portions taken from Linux arch arm */
#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/lib.h>
#include <public/arch-arm.h>

#define nop() \
    asm volatile ( "nop" )

#define sev()           asm volatile("sev" : : : "memory")
#define wfe()           asm volatile("wfe" : : : "memory")
#define wfi()           asm volatile("wfi" : : : "memory")

#define isb()           asm volatile("isb" : : : "memory")
#define dsb(scope)      asm volatile("dsb " #scope : : : "memory")
#define dmb(scope)      asm volatile("dmb " #scope : : : "memory")

#define mb()            dsb(sy)
#ifdef CONFIG_ARM_64
#define rmb()           dsb(ld)
#else
#define rmb()           dsb(sy) /* 32-bit has no ld variant. */
#endif
#define wmb()           dsb(st)

#define smp_mb()        dmb(ish)
#ifdef CONFIG_ARM_64
#define smp_rmb()       dmb(ishld)
#else
#define smp_rmb()       dmb(ish) /* 32-bit has no ishld variant. */
#endif

#define smp_wmb()       dmb(ishst)

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
