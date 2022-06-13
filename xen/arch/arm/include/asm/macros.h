#ifndef __ASM_MACROS_H
#define __ASM_MACROS_H

#ifndef __ASSEMBLY__
# error "This file should only be included in assembly file"
#endif

#include <asm/alternative.h>

    /*
     * Speculative barrier
     */
    .macro sb
alternative_if_not ARM_HAS_SB
    dsb nsh
    isb
alternative_else
    /*
     * SB encoding in hexadecimal to prevent recursive macro.
     * extra nop is required to keep same number of instructions on both sides
     * of the alternative.
     */
#if defined(CONFIG_ARM_32)
    .inst 0xf57ff070
#elif defined(CONFIG_ARM_64)
    .inst 0xd50330ff
#else
#   error "missing sb encoding for ARM variant"
#endif
    nop
alternative_endif
    .endm

#if defined (CONFIG_ARM_32)
# include <asm/arm32/macros.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/macros.h>
#else
# error "unknown ARM variant"
#endif

    /* NOP sequence  */
    .macro nops, num
    .rept   \num
    nop
    .endr
    .endm

#endif /* __ASM_ARM_MACROS_H */
