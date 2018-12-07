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
#include <asm/hvm/support.h>

#include "private.h"

typedef struct _HV_VIRTUAL_APIC_ASSIST
{
    uint32_t no_eoi:1;
    uint32_t reserved_zero:31;
} HV_VIRTUAL_APIC_ASSIST;

typedef union _HV_VP_ASSIST_PAGE
{
    HV_VIRTUAL_APIC_ASSIST ApicAssist;
    uint8_t ReservedZBytePadding[PAGE_SIZE];
} HV_VP_ASSIST_PAGE;

void viridian_apic_assist_set(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian.vp_assist.ptr;

    if ( !ptr )
        return;

    /*
     * If there is already an assist pending then something has gone
     * wrong and the VM will most likely hang so force a crash now
     * to make the problem clear.
     */
    if ( v->arch.hvm.viridian.apic_assist_pending )
        domain_crash(v->domain);

    v->arch.hvm.viridian.apic_assist_pending = true;
    ptr->ApicAssist.no_eoi = 1;
}

bool viridian_apic_assist_completed(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian.vp_assist.ptr;

    if ( !ptr )
        return false;

    if ( v->arch.hvm.viridian.apic_assist_pending &&
         !ptr->ApicAssist.no_eoi )
    {
        /* An EOI has been avoided */
        v->arch.hvm.viridian.apic_assist_pending = false;
        return true;
    }

    return false;
}

void viridian_apic_assist_clear(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian.vp_assist.ptr;

    if ( !ptr )
        return;

    ptr->ApicAssist.no_eoi = 0;
    v->arch.hvm.viridian.apic_assist_pending = false;
}

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
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
        viridian_unmap_guest_page(&v->arch.hvm.viridian.vp_assist);
        v->arch.hvm.viridian.vp_assist.msr.raw = val;
        viridian_dump_guest_page(v, "VP_ASSIST",
                                 &v->arch.hvm.viridian.vp_assist);
        if ( v->arch.hvm.viridian.vp_assist.msr.fields.enabled )
            viridian_map_guest_page(v, &v->arch.hvm.viridian.vp_assist);
        break;

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_synic_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
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
        *val = v->arch.hvm.viridian.vp_assist.msr.raw;
        break;

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

void viridian_synic_save_vcpu_ctxt(const struct vcpu *v,
                                   struct hvm_viridian_vcpu_context *ctxt)
{
    ctxt->apic_assist_pending = v->arch.hvm.viridian.apic_assist_pending;
    ctxt->vp_assist_msr = v->arch.hvm.viridian.vp_assist.msr.raw;
}

void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    v->arch.hvm.viridian.vp_assist.msr.raw = ctxt->vp_assist_msr;
    if ( v->arch.hvm.viridian.vp_assist.msr.fields.enabled )
        viridian_map_guest_page(v, &v->arch.hvm.viridian.vp_assist);

    v->arch.hvm.viridian.apic_assist_pending = ctxt->apic_assist_pending;
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
