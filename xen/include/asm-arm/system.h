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
