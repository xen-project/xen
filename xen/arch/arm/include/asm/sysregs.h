#ifndef __ASM_ARM_SYSREGS_H
#define __ASM_ARM_SYSREGS_H

#if defined(CONFIG_ARM_32)
# include <asm/arm32/sysregs.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/sysregs.h>
#else
# error "unknown ARM variant"
#endif

#ifndef __ASSEMBLY__

#include <asm/alternative.h>

static inline register_t read_sysreg_par(void)
{
    register_t par_el1;

    /*
     * On Cortex-A77 r0p0 and r1p0, read access to PAR_EL1 shall include a
     * DMB SY before and after accessing it, as part of the workaround for the
     * errata 1508412.
     */
    asm volatile(ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412,
                 CONFIG_ARM64_ERRATUM_1508412));
    par_el1 = READ_SYSREG64(PAR_EL1);
    asm volatile(ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412,
                 CONFIG_ARM64_ERRATUM_1508412));

    return par_el1;
}

#endif /*  !__ASSEMBLY__  */

#endif /* __ASM_ARM_SYSREGS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */


