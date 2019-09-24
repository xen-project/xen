#ifndef __ASM_MACROS_H
#define __ASM_MACROS_H

#ifndef __ASSEMBLY__
# error "This file should only be included in assembly file"
#endif

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
