#ifndef __ASM_ARM_SYSREGS_H
#define __ASM_ARM_SYSREGS_H

#if defined(CONFIG_ARM_32)
# include <asm/arm32/sysregs.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/sysregs.h>
#else
# error "unknown ARM variant"
#endif

#endif /* __ASM_ARM_SYSREGS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */


