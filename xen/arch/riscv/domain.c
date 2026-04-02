/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sections.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/vmap.h>

#include <asm/bitops.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/riscv_encoding.h>
#include <asm/vtimer.h>

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

#define HEDELEG_VALID_MASK ULONG_MAX
#define HIDELEG_VALID_MASK ULONG_MAX
#define HENVCFG_VALID_MASK 0xe0000003000000ffUL
#define HSTATEEN0_VALID_MASK 0xde00000000000007UL

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
#define INIT_CSR_MASK(csr, field) do { \
        register_t old = csr_read_set(CSR_ ## csr, csr ## _VALID_MASK); \
        csr_masks.field = csr_swap(CSR_ ## csr, old); \
    } while (0)

#define INIT_RO_ONE_MASK(csr, field) do { \
        register_t old = csr_read_clear(CSR_ ## csr, csr ## _VALID_MASK); \
        csr_masks.ro_one.field = csr_swap(CSR_ ## csr, old) & \
                                 csr ## _VALID_MASK; \
    } while (0)

    INIT_CSR_MASK(HEDELEG, hedeleg);
    INIT_CSR_MASK(HIDELEG, hideleg);

    INIT_CSR_MASK(HENVCFG, henvcfg);

    if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_smstateen) )
    {
        INIT_CSR_MASK(HSTATEEN0, hstateen0);
        INIT_RO_ONE_MASK(HSTATEEN0, hstateen0);
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

    if ( (rc = vcpu_vtimer_init(v)) )
        goto fail;

    /*
     * As interrupt controller (IC) is not yet implemented,
     * return an error.
     *
     * TODO: Drop this once IC is implemented.
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
    vcpu_timer_destroy(v);

    vfree((void *)&v->arch.cpu_info[1] - STACK_SIZE);
}

int vcpu_set_interrupt(struct vcpu *v, unsigned int irq)
{
    bool kick_vcpu;

    /* We only allow VS-mode software, timer, and external interrupts */
    if ( irq != IRQ_VS_SOFT &&
         irq != IRQ_VS_TIMER &&
         irq != IRQ_VS_EXT )
        return -EINVAL;

    kick_vcpu = !test_and_set_bit(irq, v->arch.irqs_pending);

    /*
     * The counterpart of this barrier is the one encoded implicitly in xchg()
     * which is used in consumer part (vcpu_flush_interrupts()).
     */
    smp_wmb();

    kick_vcpu |= !test_and_set_bit(irq, v->arch.irqs_pending_mask);

    if ( kick_vcpu )
        vcpu_kick(v);

    return 0;
}

int vcpu_unset_interrupt(struct vcpu *v, unsigned int irq)
{
    /* We only allow VS-mode software, timer, external interrupts */
    if ( irq != IRQ_VS_SOFT &&
         irq != IRQ_VS_TIMER &&
         irq != IRQ_VS_EXT )
        return -EINVAL;

    clear_bit(irq, v->arch.irqs_pending);
    /*
     * The counterpart of this barrier is the one encoded implicitly in xchg()
     * which is used in consumer part (vcpu_flush_interrupts()).
     */
    smp_wmb();
    set_bit(irq, v->arch.irqs_pending_mask);

    return 0;
}

void vcpu_sync_interrupts(struct vcpu *curr)
{
    unsigned long hvip = csr_read(CSR_HVIP);

    ASSERT(curr == current);

    /* Sync-up HVIP.VSSIP bit changes done by Guest */
    if ( ((curr->arch.hvip ^ hvip) & BIT(IRQ_VS_SOFT, UL)) &&
         !test_and_set_bit(IRQ_VS_SOFT, &curr->arch.irqs_pending_mask) )
    {
        if ( hvip & BIT(IRQ_VS_SOFT, UL) )
            set_bit(IRQ_VS_SOFT, &curr->arch.irqs_pending);
        else
            clear_bit(IRQ_VS_SOFT, &curr->arch.irqs_pending);
    }
}

void vcpu_flush_interrupts(struct vcpu *curr)
{
    ASSERT(curr == current);

    if ( ACCESS_ONCE(curr->arch.irqs_pending_mask[0]) )
    {
        unsigned long mask = xchg(&curr->arch.irqs_pending_mask[0], 0UL);
        unsigned long val = ACCESS_ONCE(curr->arch.irqs_pending[0]) & mask;
        register_t *hvip = &curr->arch.hvip;

        *hvip &= ~mask;
        *hvip |= val;

        csr_write(CSR_HVIP, *hvip);
    }

#ifdef CONFIG_RISCV_32
    /*
     * Flush AIA high interrupts.
     *
     * It is necessary to do only for CONFIG_RISCV_32 which isn't
     * supported now.
     */
#   error "Update v->arch.hviph"
#endif
}

void vcpu_kick(struct vcpu *v)
{
    bool running = v->is_running;

    vcpu_unblock(v);
    if ( running && v != current )
    {
        perfc_incr(vcpu_kick);
        smp_send_event_check_mask(cpumask_of(v->processor));
    }
}

void sync_local_execstate(void)
{
    /* Nothing to do -- no lazy switching */
}

void sync_vcpu_execstate(struct vcpu *v)
{
    /* Nothing to do -- no lazy switching */
}

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Enforce the requirement documented in struct cpu_info that
     * guest_cpu_user_regs must be the first field.
     */
    BUILD_BUG_ON(offsetof(struct cpu_info, guest_cpu_user_regs));
}
