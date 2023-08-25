#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/vfp.h>
#include <asm/arm64/sve.h>

static inline void save_state(uint64_t *fpregs)
{
    asm volatile("stp q0, q1, [%1, #16 * 0]\n\t"
                 "stp q2, q3, [%1, #16 * 2]\n\t"
                 "stp q4, q5, [%1, #16 * 4]\n\t"
                 "stp q6, q7, [%1, #16 * 6]\n\t"
                 "stp q8, q9, [%1, #16 * 8]\n\t"
                 "stp q10, q11, [%1, #16 * 10]\n\t"
                 "stp q12, q13, [%1, #16 * 12]\n\t"
                 "stp q14, q15, [%1, #16 * 14]\n\t"
                 "stp q16, q17, [%1, #16 * 16]\n\t"
                 "stp q18, q19, [%1, #16 * 18]\n\t"
                 "stp q20, q21, [%1, #16 * 20]\n\t"
                 "stp q22, q23, [%1, #16 * 22]\n\t"
                 "stp q24, q25, [%1, #16 * 24]\n\t"
                 "stp q26, q27, [%1, #16 * 26]\n\t"
                 "stp q28, q29, [%1, #16 * 28]\n\t"
                 "stp q30, q31, [%1, #16 * 30]\n\t"
                 : "=Q" (*fpregs) : "r" (fpregs));
}

static inline void restore_state(const uint64_t *fpregs)
{
    asm volatile("ldp q0, q1, [%1, #16 * 0]\n\t"
                 "ldp q2, q3, [%1, #16 * 2]\n\t"
                 "ldp q4, q5, [%1, #16 * 4]\n\t"
                 "ldp q6, q7, [%1, #16 * 6]\n\t"
                 "ldp q8, q9, [%1, #16 * 8]\n\t"
                 "ldp q10, q11, [%1, #16 * 10]\n\t"
                 "ldp q12, q13, [%1, #16 * 12]\n\t"
                 "ldp q14, q15, [%1, #16 * 14]\n\t"
                 "ldp q16, q17, [%1, #16 * 16]\n\t"
                 "ldp q18, q19, [%1, #16 * 18]\n\t"
                 "ldp q20, q21, [%1, #16 * 20]\n\t"
                 "ldp q22, q23, [%1, #16 * 22]\n\t"
                 "ldp q24, q25, [%1, #16 * 24]\n\t"
                 "ldp q26, q27, [%1, #16 * 26]\n\t"
                 "ldp q28, q29, [%1, #16 * 28]\n\t"
                 "ldp q30, q31, [%1, #16 * 30]\n\t"
                 : : "Q" (*fpregs), "r" (fpregs));
}

void vfp_save_state(struct vcpu *v)
{
    if ( !cpu_has_fp )
        return;

    if ( is_sve_domain(v->domain) )
        sve_save_state(v);
    else
        save_state(v->arch.vfp.fpregs);

    v->arch.vfp.fpsr = READ_SYSREG(FPSR);
    v->arch.vfp.fpcr = READ_SYSREG(FPCR);
    if ( is_32bit_domain(v->domain) )
        v->arch.vfp.fpexc32_el2 = READ_SYSREG(FPEXC32_EL2);
}

void vfp_restore_state(struct vcpu *v)
{
    if ( !cpu_has_fp )
        return;

    if ( is_sve_domain(v->domain) )
        sve_restore_state(v);
    else
        restore_state(v->arch.vfp.fpregs);

    WRITE_SYSREG(v->arch.vfp.fpsr, FPSR);
    WRITE_SYSREG(v->arch.vfp.fpcr, FPCR);
    if ( is_32bit_domain(v->domain) )
        WRITE_SYSREG(v->arch.vfp.fpexc32_el2, FPEXC32_EL2);
}
