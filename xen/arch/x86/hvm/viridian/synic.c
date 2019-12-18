/***************************************************************************
 * synic.c
 *
 * An implementation of some interrupt related Viridian enlightenments.
 * See Microsoft's Hypervisor Top Level Functional Specification.
 * for more information.
 */

#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/version.h>

#include <asm/apic.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vlapic.h>

#include "private.h"


void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(sizeof(struct hv_message) != HV_MESSAGE_SIZE);
}

void viridian_apic_assist_set(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct hv_vp_assist_page *ptr = vv->vp_assist.ptr;

    if ( !ptr )
        return;

    /*
     * If there is already an assist pending then something has gone
     * wrong and the VM will most likely hang so force a crash now
     * to make the problem clear.
     */
    if ( vv->apic_assist_pending )
        domain_crash(v->domain);

    vv->apic_assist_pending = true;
    ptr->apic_assist = 1;
}

bool viridian_apic_assist_completed(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct hv_vp_assist_page *ptr = vv->vp_assist.ptr;

    if ( !ptr )
        return false;

    if ( vv->apic_assist_pending && !ptr->apic_assist )
    {
        /* An EOI has been avoided */
        vv->apic_assist_pending = false;
        return true;
    }

    return false;
}

void viridian_apic_assist_clear(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct hv_vp_assist_page *ptr = vv->vp_assist.ptr;

    if ( !ptr )
        return;

    ptr->apic_assist = 0;
    vv->apic_assist_pending = false;
}

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct domain *d = v->domain;

    ASSERT(v == current || !v->is_running);

    switch ( idx )
    {
    case HV_X64_MSR_EOI:
        vlapic_EOI_set(vcpu_vlapic(v));
        break;

    case HV_X64_MSR_ICR:
        vlapic_reg_write(v, APIC_ICR2, val >> 32);
        vlapic_reg_write(v, APIC_ICR, val);
        break;

    case HV_X64_MSR_TPR:
        vlapic_reg_write(v, APIC_TASKPRI, val);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        /* release any previous mapping */
        viridian_unmap_guest_page(&vv->vp_assist);
        vv->vp_assist.msr.raw = val;
        viridian_dump_guest_page(v, "VP_ASSIST", &vv->vp_assist);
        if ( vv->vp_assist.msr.enabled )
            viridian_map_guest_page(d, &vv->vp_assist);
        break;

    case HV_X64_MSR_SCONTROL:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        vv->scontrol = val;
        break;

    case HV_X64_MSR_SVERSION:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_SIEFP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        vv->siefp = val;
        break;

    case HV_X64_MSR_SIMP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        viridian_unmap_guest_page(&vv->simp);
        vv->simp.msr.raw = val;
        viridian_dump_guest_page(v, "SIMP", &vv->simp);
        if ( vv->simp.msr.enabled )
            viridian_map_guest_page(d, &vv->simp);
        break;

    case HV_X64_MSR_EOM:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        vv->msg_pending = 0;
        break;

    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
    {
        unsigned int sintx = idx - HV_X64_MSR_SINT0;
        union viridian_sint_msr new, *vs =
            &array_access_nospec(vv->sint, sintx);
        uint8_t vector;

        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        /* Vectors must be in the range 0x10-0xff inclusive */
        new.raw = val;
        if ( new.vector < 0x10 )
            return X86EMUL_EXCEPTION;

        /*
         * Invalidate any previous mapping by setting an out-of-range
         * index before setting the new mapping.
         */
        vector = vs->vector;
        vv->vector_to_sintx[vector] = ARRAY_SIZE(vv->sint);

        vector = new.vector;
        vv->vector_to_sintx[vector] = sintx;

        printk(XENLOG_G_INFO "%pv: VIRIDIAN SINT%u: vector: %x\n", v, sintx,
               vector);

        if ( new.polling )
            __clear_bit(sintx, &vv->msg_pending);

        *vs = new;
        break;
    }

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_synic_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    const struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_EOI:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_ICR:
    {
        uint32_t icr2 = vlapic_get_reg(vcpu_vlapic(v), APIC_ICR2);
        uint32_t icr = vlapic_get_reg(vcpu_vlapic(v), APIC_ICR);

        *val = ((uint64_t)icr2 << 32) | icr;
        break;
    }

    case HV_X64_MSR_TPR:
        *val = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        *val = vv->vp_assist.msr.raw;
        break;

    case HV_X64_MSR_SCONTROL:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = vv->scontrol;
        break;

    case HV_X64_MSR_SVERSION:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        /*
         * The specification says that the version number is 0x00000001
         * and should be in the lower 32-bits of the MSR, while the
         * upper 32-bits are reserved... but it doesn't say what they
         * should be set to. Assume everything but the bottom bit
         * should be zero.
         */
        *val = 1ul;
        break;

    case HV_X64_MSR_SIEFP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = vv->siefp;
        break;

    case HV_X64_MSR_SIMP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = vv->simp.msr.raw;
        break;

    case HV_X64_MSR_EOM:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = 0;
        break;

    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
    {
        unsigned int sintx = idx - HV_X64_MSR_SINT0;
        const union viridian_sint_msr *vs =
            &array_access_nospec(vv->sint, sintx);

        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = vs->raw;
        break;
    }

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_synic_vcpu_init(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    /*
     * The specification says that all synthetic interrupts must be
     * initally masked.
     */
    for ( i = 0; i < ARRAY_SIZE(vv->sint); i++ )
        vv->sint[i].mask = 1;

    /* Initialize the mapping array with invalid values */
    for ( i = 0; i < ARRAY_SIZE(vv->vector_to_sintx); i++ )
        vv->vector_to_sintx[i] = ARRAY_SIZE(vv->sint);

    return 0;
}

int viridian_synic_domain_init(const struct domain *d)
{
    return 0;
}

void viridian_synic_vcpu_deinit(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;

    viridian_unmap_guest_page(&vv->vp_assist);
    viridian_unmap_guest_page(&vv->simp);
}

void viridian_synic_domain_deinit(const struct domain *d)
{
}

void viridian_synic_poll(struct vcpu *v)
{
    viridian_time_poll_timers(v);
}

bool viridian_synic_deliver_timer_msg(struct vcpu *v, unsigned int sintx,
                                      unsigned int index,
                                      uint64_t expiration,
                                      uint64_t delivery)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    const union viridian_sint_msr *vs = &vv->sint[sintx];
    struct hv_message *msg = vv->simp.ptr;
    struct {
        uint32_t TimerIndex;
        uint32_t Reserved;
        uint64_t ExpirationTime;
        uint64_t DeliveryTime;
    } payload = {
        .TimerIndex = index,
        .ExpirationTime = expiration,
        .DeliveryTime = delivery,
    };

    if ( test_bit(sintx, &vv->msg_pending) )
        return false;

    /*
     * To avoid using an atomic test-and-set, and barrier before calling
     * vlapic_set_irq(), this function must be called in context of the
     * vcpu receiving the message.
     */
    ASSERT(v == current);

    msg += sintx;

    if ( msg->header.message_type != HVMSG_NONE )
    {
        msg->header.message_flags.msg_pending = 1;
        __set_bit(sintx, &vv->msg_pending);
        return false;
    }

    msg->header.message_type = HVMSG_TIMER_EXPIRED;
    msg->header.message_flags.msg_pending = 0;
    msg->header.payload_size = sizeof(payload);

    BUILD_BUG_ON(sizeof(payload) > sizeof(msg->u.payload));
    memcpy(msg->u.payload, &payload, sizeof(payload));

    if ( !vs->mask )
        vlapic_set_irq(vcpu_vlapic(v), vs->vector, 0);

    return true;
}

bool viridian_synic_is_auto_eoi_sint(const struct vcpu *v,
                                     unsigned int vector)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int sintx = vv->vector_to_sintx[vector];
    const union viridian_sint_msr *vs =
        &array_access_nospec(vv->sint, sintx);

    if ( sintx >= ARRAY_SIZE(vv->sint) )
        return false;

    return vs->auto_eoi;
}

void viridian_synic_ack_sint(const struct vcpu *v, unsigned int vector)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int sintx = vv->vector_to_sintx[vector];

    ASSERT(v == current);

    if ( sintx < ARRAY_SIZE(vv->sint) )
        __clear_bit(array_index_nospec(sintx, ARRAY_SIZE(vv->sint)),
                    &vv->msg_pending);
}

void viridian_synic_save_vcpu_ctxt(const struct vcpu *v,
                                   struct hvm_viridian_vcpu_context *ctxt)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    BUILD_BUG_ON(ARRAY_SIZE(vv->sint) != ARRAY_SIZE(ctxt->sint_msr));

    for ( i = 0; i < ARRAY_SIZE(vv->sint); i++ )
        ctxt->sint_msr[i] = vv->sint[i].raw;

    ctxt->simp_msr = vv->simp.msr.raw;

    ctxt->apic_assist_pending = vv->apic_assist_pending;
    ctxt->vp_assist_msr = vv->vp_assist.msr.raw;
}

void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct domain *d = v->domain;
    unsigned int i;

    vv->vp_assist.msr.raw = ctxt->vp_assist_msr;
    if ( vv->vp_assist.msr.enabled )
        viridian_map_guest_page(d, &vv->vp_assist);

    vv->apic_assist_pending = ctxt->apic_assist_pending;

    vv->simp.msr.raw = ctxt->simp_msr;
    if ( vv->simp.msr.enabled )
        viridian_map_guest_page(d, &vv->simp);

    for ( i = 0; i < ARRAY_SIZE(vv->sint); i++ )
    {
        uint8_t vector;

        vv->sint[i].raw = ctxt->sint_msr[i];

        vector = vv->sint[i].vector;
        if ( vector < 0x10 )
            continue;

        vv->vector_to_sintx[vector] = i;
    }
}

void viridian_synic_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt)
{
}

void viridian_synic_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt)
{
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
