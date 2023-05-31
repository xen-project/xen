/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm SVE feature code
 *
 * Copyright (C) 2022 ARM Ltd.
 */

#include <xen/sizes.h>
#include <xen/types.h>
#include <asm/arm64/sve.h>
#include <asm/arm64/sysregs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/system.h>

/* opt_dom0_sve: allow Dom0 to use SVE and set maximum vector length. */
int __initdata opt_dom0_sve;

extern unsigned int sve_get_hw_vl(void);

/*
 * Save the SVE context
 *
 * sve_ctx - pointer to buffer for Z0-31 + FFR
 * pregs - pointer to buffer for P0-15
 * save_ffr - Save FFR if non-zero
 */
extern void sve_save_ctx(uint64_t *sve_ctx, uint64_t *pregs, int save_ffr);

/*
 * Load the SVE context
 *
 * sve_ctx - pointer to buffer for Z0-31 + FFR
 * pregs - pointer to buffer for P0-15
 * restore_ffr - Restore FFR if non-zero
 */
extern void sve_load_ctx(uint64_t const *sve_ctx, uint64_t const *pregs,
                         int restore_ffr);

/* Takes a vector length in bits and returns the ZCR_ELx encoding */
static inline register_t vl_to_zcr(unsigned int vl)
{
    ASSERT(vl > 0);
    return ((vl / SVE_VL_MULTIPLE_VAL) - 1U) & ZCR_ELx_LEN_MASK;
}

static inline unsigned int sve_zreg_ctx_size(unsigned int vl)
{
    /*
     * Z0-31 registers size in bytes is computed from VL that is in bits, so VL
     * in bytes is VL/8.
     */
    return (vl / 8U) * 32U;
}

static inline unsigned int sve_ffrreg_ctx_size(unsigned int vl)
{
    /* FFR register size is VL/8, which is in bytes (VL/8)/8 */
    return (vl / 64U);
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

/* Get the system sanitized value for VL in bits */
unsigned int get_sys_vl_len(void)
{
    if ( !cpu_has_sve )
        return 0;

    /* ZCR_ELx len field is ((len + 1) * 128) = vector bits length */
    return ((system_cpuinfo.zcr64.bits[0] & ZCR_ELx_LEN_MASK) + 1U) *
            SVE_VL_MULTIPLE_VAL;
}

int sve_context_init(struct vcpu *v)
{
    unsigned int sve_vl_bits = sve_decode_vl(v->domain->arch.sve_vl);
    uint64_t *ctx = _xzalloc(sve_zreg_ctx_size(sve_vl_bits) +
                             sve_ffrreg_ctx_size(sve_vl_bits),
                             L1_CACHE_BYTES);

    if ( !ctx )
        return -ENOMEM;

    /*
     * Points to the end of Z0-Z31 memory, just before FFR memory, to be kept in
     * sync with sve_context_free().
     */
    v->arch.vfp.sve_zreg_ctx_end = ctx +
        (sve_zreg_ctx_size(sve_vl_bits) / sizeof(uint64_t));

    v->arch.zcr_el2 = vl_to_zcr(sve_vl_bits);

    return 0;
}

void sve_context_free(struct vcpu *v)
{
    unsigned int sve_vl_bits;

    if ( v->arch.vfp.sve_zreg_ctx_end )
        return;

    sve_vl_bits = sve_decode_vl(v->domain->arch.sve_vl);

    /*
     * Currenly points to the end of Z0-Z31 memory which is not the start of
     * the buffer. To be kept in sync with the sve_context_init().
     */
    v->arch.vfp.sve_zreg_ctx_end -=
        (sve_zreg_ctx_size(sve_vl_bits) / sizeof(uint64_t));

    XFREE(v->arch.vfp.sve_zreg_ctx_end);
}

void sve_save_state(struct vcpu *v)
{
    v->arch.zcr_el1 = READ_SYSREG(ZCR_EL1);

    sve_save_ctx(v->arch.vfp.sve_zreg_ctx_end, v->arch.vfp.fpregs, 1);
}

void sve_restore_state(struct vcpu *v)
{
    WRITE_SYSREG(v->arch.zcr_el1, ZCR_EL1);
    WRITE_SYSREG(v->arch.zcr_el2, ZCR_EL2);

    sve_load_ctx(v->arch.vfp.sve_zreg_ctx_end, v->arch.vfp.fpregs, 1);
}

bool __init sve_domctl_vl_param(int val, unsigned int *out)
{
    /*
     * Negative SVE parameter value means to use the maximum supported
     * vector length, otherwise if a positive value is provided, check if the
     * vector length is a multiple of 128
     */
    if ( val < 0 )
        *out = get_sys_vl_len();
    else if ( (val % SVE_VL_MULTIPLE_VAL) == 0 )
        *out = val;
    else
        return false;

    return true;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
