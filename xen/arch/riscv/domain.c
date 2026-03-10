/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sections.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/riscv_encoding.h>

struct csr_masks {
    register_t hedeleg;
    register_t henvcfg;
    register_t hideleg;
    register_t hstateen0;

    struct {
        register_t hstateen0;
    } ro_one;
};

#define HEDELEG_DEFAULT (BIT(CAUSE_MISALIGNED_FETCH, U) | \
                         BIT(CAUSE_FETCH_ACCESS, U) | \
                         BIT(CAUSE_ILLEGAL_INSTRUCTION, U) | \
                         BIT(CAUSE_BREAKPOINT, U) | \
                         BIT(CAUSE_MISALIGNED_LOAD, U) | \
                         BIT(CAUSE_LOAD_ACCESS, U) | \
                         BIT(CAUSE_MISALIGNED_STORE, U) | \
                         BIT(CAUSE_STORE_ACCESS, U) | \
                         BIT(CAUSE_USER_ECALL, U) | \
                         BIT(CAUSE_FETCH_PAGE_FAULT, U) | \
                         BIT(CAUSE_LOAD_PAGE_FAULT, U) | \
                         BIT(CAUSE_STORE_PAGE_FAULT, U))

#define HIDELEG_DEFAULT (MIP_VSSIP | MIP_VSTIP | MIP_VSEIP)

static struct csr_masks __ro_after_init csr_masks;

#define HEDELEG_AVAIL_MASK ULONG_MAX
#define HIDELEG_AVAIL_MASK ULONG_MAX
#define HENVCFG_AVAIL_MASK _UL(0xE0000003000000FF)
#define HSTATEEN0_AVAIL_MASK _UL(0xDE00000000000007)

void __init init_csr_masks(void)
{
    /*
     * The mask specifies the bits that may be safely modified without
     * causing side effects.
     *
     * For example, registers such as henvcfg or hstateen0 contain WPRI
     * fields that must be preserved. Any write to the full register must
     * therefore retain the original values of those fields.
     */
#define INIT_CSR_MASK(csr, field, mask) do { \
        register_t old = csr_read_set(CSR_ ## csr, mask); \
        csr_masks.field = csr_swap(CSR_ ## csr, old); \
    } while (0)

#define INIT_RO_ONE_MASK(csr, field, mask) do { \
        register_t old = csr_read_clear(CSR_ ## csr, mask); \
        csr_masks.ro_one.field = csr_swap(CSR_ ## csr, old) & mask; \
    } while (0)

    INIT_CSR_MASK(HEDELEG, hedeleg, HEDELEG_AVAIL_MASK);
    INIT_CSR_MASK(HIDELEG, hideleg, HIDELEG_AVAIL_MASK);

    INIT_CSR_MASK(HENVCFG, henvcfg, HENVCFG_AVAIL_MASK);

    if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_smstateen) )
    {
        INIT_CSR_MASK(HSTATEEN0, hstateen0, HSTATEEN0_AVAIL_MASK);
        INIT_RO_ONE_MASK(HSTATEEN0, hstateen0, HSTATEEN0_AVAIL_MASK);
    }

#undef INIT_CSR_MASK
#undef INIT_RO_ONE_MASK
}

static void vcpu_csr_init(struct vcpu *v)
{
    v->arch.hedeleg = HEDELEG_DEFAULT & csr_masks.hedeleg;

    vcpu_guest_cpu_user_regs(v)->hstatus = HSTATUS_SPV | HSTATUS_SPVP;

    v->arch.hideleg = HIDELEG_DEFAULT & csr_masks.hideleg;

    /*
     * VS should access only the time counter directly.
     * Everything else should trap.
     */
    v->arch.hcounteren = HCOUNTEREN_TM;

    if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_svpbmt) )
        v->arch.henvcfg = ENVCFG_PBMTE & csr_masks.henvcfg;

    if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_smstateen) )
    {
        /* Allow guest to access CSR_SENVCFG */
        register_t hstateen0 = SMSTATEEN0_HSENVCFG;

        if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_ssaia) )
            /*
             * If the hypervisor extension is implemented, the same three
             * bits are defined also in hypervisor CSR hstateen0 but concern
             * only the state potentially accessible to a virtual machine
             * executing in privilege modes VS and VU:
             *      bit 60 CSRs siselect and sireg (really vsiselect and
             *             vsireg)
             *      bit 59 CSRs siph and sieh (RV32 only) and stopi (really
             *             vsiph, vsieh, and vstopi)
             *      bit 58 all state of IMSIC guest interrupt files, including
             *             CSR stopei (really vstopei)
             * If one of these bits is zero in hstateen0, and the same bit is
             * one in mstateen0, then an attempt to access the corresponding
             * state from VS or VU-mode raises a virtual instruction exception.
             */
            hstateen0 |= SMSTATEEN0_AIA | SMSTATEEN0_IMSIC | SMSTATEEN0_SVSLCT;

        v->arch.hstateen0 = (hstateen0 & csr_masks.hstateen0) |
                            csr_masks.ro_one.hstateen0;
    }
}

static void continue_new_vcpu(struct vcpu *prev)
{
    BUG_ON("unimplemented\n");
}

int arch_vcpu_create(struct vcpu *v)
{
    int rc;
    void *stack = vzalloc(STACK_SIZE);

    if ( !stack )
        return -ENOMEM;

    v->arch.cpu_info = stack + STACK_SIZE - sizeof(*v->arch.cpu_info);

    v->arch.xen_saved_context.sp = (register_t)v->arch.cpu_info;
    v->arch.xen_saved_context.ra = (register_t)continue_new_vcpu;

    /* Idle VCPUs don't need the rest of this setup */
    if ( is_idle_vcpu(v) )
        return 0;

    vcpu_csr_init(v);

    /*
     * As the vtimer and interrupt controller (IC) are not yet implemented,
     * return an error.
     *
     * TODO: Drop this once the vtimer and IC are implemented.
     */
    rc = -EOPNOTSUPP;
    goto fail;

    return rc;

 fail:
    arch_vcpu_destroy(v);
    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    vfree((void *)&v->arch.cpu_info[1] - STACK_SIZE);
}

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Enforce the requirement documented in struct cpu_info that
     * guest_cpu_user_regs must be the first field.
     */
    BUILD_BUG_ON(offsetof(struct cpu_info, guest_cpu_user_regs));
}
