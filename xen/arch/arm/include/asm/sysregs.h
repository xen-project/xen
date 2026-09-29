#ifndef __ASM_ARM_SYSREGS_H
#define __ASM_ARM_SYSREGS_H

#if defined(CONFIG_ARM_32)
# include <asm/arm32/sysregs.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/sysregs.h>
#else
# error "unknown ARM variant"
#endif

#define ID_PFR1_GIC_SHIFT            28
#define ID_PFR1_VIRT_FRAC_SHIFT      24
#define ID_PFR1_SEC_FRAC_SHIFT       20
#define ID_PFR1_GENTIMER_SHIFT       16
#define ID_PFR1_VIRTUALIZATION_SHIFT 12
#define ID_PFR1_MPROGMOD_SHIFT       8
#define ID_PFR1_SECURITY_SHIFT       4
#define ID_PFR1_PROGMOD_SHIFT        0

/* GIC field encodings, common to ID_PFR1{,_EL1} and ID_AA64PFR0_EL1 */
#define ID_PFR_GIC_NI                0x0U
#define ID_PFR_GIC_V3                0x1U

#ifndef __ASSEMBLER__

#include <asm/alternative.h>

static inline register_t read_sysreg_par(void)
{
    register_t par_el1;

    /*
     * On Cortex-A77 r0p0 and r1p0, read access to PAR_EL1 shall include a
     * DMB SY before and after accessing it, as part of the workaround for the
     * errata 1508412.
     */
    asm_inline volatile (
        ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412,
                    CONFIG_ARM64_ERRATUM_1508412) );
    par_el1 = READ_SYSREG64(PAR_EL1);
    asm_inline volatile (
        ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412,
                    CONFIG_ARM64_ERRATUM_1508412) );

    return par_el1;
}

#endif /*  !__ASSEMBLER__  */

#endif /* __ASM_ARM_SYSREGS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */


