/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm SVE feature code
 *
 * Copyright (C) 2022 ARM Ltd.
 */

#include <xen/types.h>
#include <asm/arm64/sve.h>
#include <asm/arm64/sysregs.h>
#include <asm/processor.h>
#include <asm/system.h>

extern unsigned int sve_get_hw_vl(void);

/* Takes a vector length in bits and returns the ZCR_ELx encoding */
static inline register_t vl_to_zcr(unsigned int vl)
{
    ASSERT(vl > 0);
    return ((vl / SVE_VL_MULTIPLE_VAL) - 1U) & ZCR_ELx_LEN_MASK;
}

register_t compute_max_zcr(void)
{
    register_t cptr_bits = get_default_cptr_flags();
    register_t zcr = vl_to_zcr(SVE_VL_MAX_BITS);
    unsigned int hw_vl;

    /* Remove trap for SVE resources */
    WRITE_SYSREG(cptr_bits & ~HCPTR_CP(8), CPTR_EL2);
    isb();

    /*
     * Set the maximum SVE vector length, doing that we will know the VL
     * supported by the platform, calling sve_get_hw_vl()
     */
    WRITE_SYSREG(zcr, ZCR_EL2);

    /*
     * Read the maximum VL, which could be lower than what we imposed before,
     * hw_vl contains VL in bytes, multiply it by 8 to use vl_to_zcr() later
     */
    hw_vl = sve_get_hw_vl() * 8U;

    /* Restore CPTR_EL2 */
    WRITE_SYSREG(cptr_bits, CPTR_EL2);
    isb();

    return vl_to_zcr(hw_vl);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
