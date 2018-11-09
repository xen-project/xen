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

static void dump_vp_assist(const struct vcpu *v)
{
    const union viridian_page_msr *va = &v->arch.hvm.viridian.vp_assist.msr;

    if ( !va->fields.enabled )
        return;

    printk(XENLOG_G_INFO "%pv: VIRIDIAN VP_ASSIST_PAGE: pfn: %lx\n",
           v, (unsigned long)va->fields.pfn);
}

static void initialize_vp_assist(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long gmfn = v->arch.hvm.viridian.vp_assist.msr.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    void *va;

    ASSERT(!v->arch.hvm.viridian.vp_assist.va);

    if ( !page )
        goto fail;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        goto fail;
    }

    va = __map_domain_page_global(page);
    if ( !va )
    {
        put_page_and_type(page);
        goto fail;
    }

    clear_page(va);

    v->arch.hvm.viridian.vp_assist.va = va;
    return;

 fail:
    gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
             gmfn, mfn_x(page ? page_to_mfn(page) : INVALID_MFN));
}

static void teardown_vp_assist(struct vcpu *v)
{
    void *va = v->arch.hvm.viridian.vp_assist.va;
    struct page_info *page;

    if ( !va )
        return;

    v->arch.hvm.viridian.vp_assist.va = NULL;

    page = mfn_to_page(domain_page_map_to_mfn(va));

    unmap_domain_page_global(va);
    put_page_and_type(page);
}

void viridian_apic_assist_set(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm.viridian.vp_assist.va;

    if ( !va )
        return;

    /*
     * If there is already an assist pending then something has gone
     * wrong and the VM will most likely hang so force a crash now
     * to make the problem clear.
     */
    if ( v->arch.hvm.viridian.vp_assist.pending )
        domain_crash(v->domain);

    v->arch.hvm.viridian.vp_assist.pending = true;
    *va |= 1u;
}

bool viridian_apic_assist_completed(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm.viridian.vp_assist.va;

    if ( !va )
        return false;

    if ( v->arch.hvm.viridian.vp_assist.pending &&
         !(*va & 1u) )
    {
        /* An EOI has been avoided */
        v->arch.hvm.viridian.vp_assist.pending = false;
        return true;
    }

    return false;
}

void viridian_apic_assist_clear(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm.viridian.vp_assist.va;

    if ( !va )
        return;

    *va &= ~1u;
    v->arch.hvm.viridian.vp_assist.pending = false;
}

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    switch ( idx )
    {
    case HV_X64_MSR_EOI:
        vlapic_EOI_set(vcpu_vlapic(v));
        break;

    case HV_X64_MSR_ICR: {
        u32 eax = (u32)val, edx = (u32)(val >> 32);
        struct vlapic *vlapic = vcpu_vlapic(v);
        eax &= ~(1 << 12);
        edx &= 0xff000000;
        vlapic_set_reg(vlapic, APIC_ICR2, edx);
        vlapic_ipi(vlapic, eax, edx);
        vlapic_set_reg(vlapic, APIC_ICR, eax);
        break;
    }
    case HV_X64_MSR_TPR:
        vlapic_set_reg(vcpu_vlapic(v), APIC_TASKPRI, (uint8_t)val);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        teardown_vp_assist(v); /* release any previous mapping */
        v->arch.hvm.viridian.vp_assist.msr.raw = val;
        dump_vp_assist(v);
        if ( v->arch.hvm.viridian.vp_assist.msr.fields.enabled )
            initialize_vp_assist(v);
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
    ctxt->vp_assist_pending = v->arch.hvm.viridian.vp_assist.pending;
    ctxt->vp_assist_msr = v->arch.hvm.viridian.vp_assist.msr.raw;
}

void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    v->arch.hvm.viridian.vp_assist.msr.raw = ctxt->vp_assist_msr;
    if ( v->arch.hvm.viridian.vp_assist.msr.fields.enabled )
        initialize_vp_assist(v);

    v->arch.hvm.viridian.vp_assist.pending = !!ctxt->vp_assist_pending;
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
