/***************************************************************************
 * time.c
 *
 * An implementation of some time related Viridian enlightenments.
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

typedef struct _HV_REFERENCE_TSC_PAGE
{
    uint32_t TscSequence;
    uint32_t Reserved1;
    uint64_t TscScale;
    int64_t  TscOffset;
    uint64_t Reserved2[509];
} HV_REFERENCE_TSC_PAGE, *PHV_REFERENCE_TSC_PAGE;

static void dump_reference_tsc(const struct domain *d)
{
    const union viridian_page_msr *rt = &d->arch.hvm.viridian.reference_tsc;

    if ( !rt->fields.enabled )
        return;

    printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: pfn: %lx\n",
           d->domain_id, (unsigned long)rt->fields.pfn);
}

static void update_reference_tsc(struct domain *d, bool initialize)
{
    unsigned long gmfn = d->arch.hvm.viridian.reference_tsc.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    HV_REFERENCE_TSC_PAGE *p;

    if ( !page || !get_page_type(page, PGT_writable_page) )
    {
        if ( page )
            put_page(page);
        gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
                 gmfn, mfn_x(page ? page_to_mfn(page) : INVALID_MFN));
        return;
    }

    p = __map_domain_page(page);

    if ( initialize )
        clear_page(p);

    /*
     * This enlightenment must be disabled is the host TSC is not invariant.
     * However it is also disabled if vtsc is true (which means rdtsc is
     * being emulated). This generally happens when guest TSC freq and host
     * TSC freq don't match. The TscScale value could be adjusted to cope
     * with this, allowing vtsc to be turned off, but support for this is
     * not yet present in the hypervisor. Thus is it is possible that
     * migrating a Windows VM between hosts of differing TSC frequencies
     * may result in large differences in guest performance.
     */
    if ( !host_tsc_is_safe() || d->arch.vtsc )
    {
        /*
         * The specification states that valid values of TscSequence range
         * from 0 to 0xFFFFFFFE. The value 0xFFFFFFFF is used to indicate
         * this mechanism is no longer a reliable source of time and that
         * the VM should fall back to a different source.
         *
         * Server 2012 (6.2 kernel) and 2012 R2 (6.3 kernel) actually
         * violate the spec. and rely on a value of 0 to indicate that this
         * enlightenment should no longer be used.
         */
        p->TscSequence = 0;

        printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: invalidated\n",
               d->domain_id);
        goto out;
    }

    /*
     * The guest will calculate reference time according to the following
     * formula:
     *
     * ReferenceTime = ((RDTSC() * TscScale) >> 64) + TscOffset
     *
     * Windows uses a 100ns tick, so we need a scale which is cpu
     * ticks per 100ns shifted left by 64.
     */
    p->TscScale = ((10000ul << 32) / d->arch.tsc_khz) << 32;

    p->TscSequence++;
    if ( p->TscSequence == 0xFFFFFFFF ||
         p->TscSequence == 0 ) /* Avoid both 'invalid' values */
        p->TscSequence = 1;

 out:
    unmap_domain_page(p);

    put_page_and_type(page);
}

static int64_t raw_trc_val(struct domain *d)
{
    uint64_t tsc;
    struct time_scale tsc_to_ns;

    tsc = hvm_get_guest_tsc(pt_global_vcpu_target(d));

    /* convert tsc to count of 100ns periods */
    set_time_scale(&tsc_to_ns, d->arch.tsc_khz * 1000ul);
    return scale_delta(tsc, &tsc_to_ns) / 100ul;
}

void viridian_time_ref_count_freeze(struct domain *d)
{
    struct viridian_time_ref_count *trc;

    trc = &d->arch.hvm.viridian.time_ref_count;

    if ( test_and_clear_bit(_TRC_running, &trc->flags) )
        trc->val = raw_trc_val(d) + trc->off;
}

void viridian_time_ref_count_thaw(struct domain *d)
{
    struct viridian_time_ref_count *trc;

    trc = &d->arch.hvm.viridian.time_ref_count;

    if ( !d->is_shutting_down &&
         !test_and_set_bit(_TRC_running, &trc->flags) )
        trc->off = (int64_t)trc->val - raw_trc_val(d);
}

int viridian_time_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return X86EMUL_EXCEPTION;

        d->arch.hvm.viridian.reference_tsc.raw = val;
        dump_reference_tsc(d);
        if ( d->arch.hvm.viridian.reference_tsc.fields.enabled )
            update_reference_tsc(d, true);
        break;

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_time_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_TSC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return X86EMUL_EXCEPTION;

        *val = (uint64_t)d->arch.tsc_khz * 1000ull;
        break;

    case HV_X64_MSR_APIC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return X86EMUL_EXCEPTION;

        *val = 1000000000ull / APIC_BUS_CYCLE_NS;
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return X86EMUL_EXCEPTION;

        *val = d->arch.hvm.viridian.reference_tsc.raw;
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
    {
        struct viridian_time_ref_count *trc =
            &d->arch.hvm.viridian.time_ref_count;

        if ( !(viridian_feature_mask(d) & HVMPV_time_ref_count) )
            return X86EMUL_EXCEPTION;

        if ( !test_and_set_bit(_TRC_accessed, &trc->flags) )
            printk(XENLOG_G_INFO "d%d: VIRIDIAN MSR_TIME_REF_COUNT: accessed\n",
                   d->domain_id);

        *val = raw_trc_val(d) + trc->off;
        break;
    }

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

void viridian_time_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt)
{
    ctxt->time_ref_count = d->arch.hvm.viridian.time_ref_count.val;
    ctxt->reference_tsc = d->arch.hvm.viridian.reference_tsc.raw;
}

void viridian_time_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt)
{
    d->arch.hvm.viridian.time_ref_count.val = ctxt->time_ref_count;
    d->arch.hvm.viridian.reference_tsc.raw = ctxt->reference_tsc;

    if ( d->arch.hvm.viridian.reference_tsc.fields.enabled )
        update_reference_tsc(d, false);
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
