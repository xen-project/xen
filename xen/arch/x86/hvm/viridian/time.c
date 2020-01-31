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
#include <asm/event.h>
#include <asm/guest/hyperv.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/hvm/support.h>

#include "private.h"

static void update_reference_tsc(const struct domain *d, bool initialize)
{
    struct viridian_domain *vd = d->arch.hvm.viridian;
    const struct viridian_time_ref_count *trc = &vd->time_ref_count;
    const struct viridian_page *rt = &vd->reference_tsc;
    HV_REFERENCE_TSC_PAGE *p = rt->ptr;
    uint32_t seq;

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
     * may result in large differences in guest performance. Any jump in
     * TSC due to migration down-time can, however, be compensated for by
     * setting the TscOffset value (see below).
     */
    if ( !host_tsc_is_safe() || d->arch.vtsc )
    {
        /*
         * The value 0 is used to indicate this mechanism is no longer a
         * reliable source of time and that the VM should fall back to a
         * different source.
         */
        p->tsc_sequence = 0;

        printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: invalidated\n",
               d->domain_id);
        return;
    }

    /*
     * The guest will calculate reference time according to the following
     * formula:
     *
     * ReferenceTime = ((RDTSC() * TscScale) >> 64) + TscOffset
     *
     * Windows uses a 100ns tick, so we need a scale which is cpu
     * ticks per 100ns shifted left by 64.
     * The offset value is calculated on restore after migration and
     * ensures that Windows will not see a large jump in ReferenceTime.
     */
    p->tsc_scale = ((10000ul << 32) / d->arch.tsc_khz) << 32;
    p->tsc_offset = trc->off;
    smp_wmb();

    seq = p->tsc_sequence + 1;
    p->tsc_sequence = seq ? seq : 1; /* Avoid 'invalid' value 0 */
}

static uint64_t trc_val(const struct domain *d, int64_t offset)
{
    uint64_t tsc, scale;

    tsc = hvm_get_guest_tsc(pt_global_vcpu_target(d));
    scale = ((10000ul << 32) / d->arch.tsc_khz) << 32;

    return hv_scale_tsc(tsc, scale, offset);
}

static void time_ref_count_freeze(const struct domain *d)
{
    struct viridian_time_ref_count *trc =
        &d->arch.hvm.viridian->time_ref_count;

    if ( test_and_clear_bit(_TRC_running, &trc->flags) )
        trc->val = trc_val(d, trc->off);
}

static void time_ref_count_thaw(const struct domain *d)
{
    struct viridian_domain *vd = d->arch.hvm.viridian;
    struct viridian_time_ref_count *trc = &vd->time_ref_count;

    if ( d->is_shutting_down ||
         test_and_set_bit(_TRC_running, &trc->flags) )
        return;

    trc->off = (int64_t)trc->val - trc_val(d, 0);

    if ( vd->reference_tsc.msr.enabled )
        update_reference_tsc(d, false);
}

static uint64_t time_ref_count(const struct domain *d)
{
    const struct viridian_time_ref_count *trc =
        &d->arch.hvm.viridian->time_ref_count;

    return trc_val(d, trc->off);
}

static void stop_stimer(struct viridian_stimer *vs)
{
    if ( !vs->started )
        return;

    stop_timer(&vs->timer);
    vs->started = false;
}

static void stimer_expire(void *data)
{
    struct viridian_stimer *vs = data;
    struct vcpu *v = vs->v;
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int stimerx = vs - &vv->stimer[0];

    set_bit(stimerx, &vv->stimer_pending);
    vcpu_kick(v);
}

static void start_stimer(struct viridian_stimer *vs)
{
    const struct vcpu *v = vs->v;
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int stimerx = vs - &vv->stimer[0];
    int64_t now = time_ref_count(v->domain);
    int64_t expiration;
    s_time_t timeout;

    if ( !test_and_set_bit(stimerx, &vv->stimer_enabled) )
        printk(XENLOG_G_INFO "%pv: VIRIDIAN STIMER%u: enabled\n", v,
               stimerx);

    if ( vs->config.periodic )
    {
        /*
         * The specification says that if the timer is lazy then we
         * skip over any missed expirations so we can treat this case
         * as the same as if the timer is currently stopped, i.e. we
         * just schedule expiration to be 'count' ticks from now.
         */
        if ( !vs->started || vs->config.lazy )
            expiration = now + vs->count;
        else
        {
            unsigned int missed = 0;

            /*
             * The timer is already started, so we're re-scheduling.
             * Hence advance the timer expiration by one tick.
             */
            expiration = vs->expiration + vs->count;

            /* Now check to see if any expirations have been missed */
            if ( expiration - now <= 0 )
                missed = ((now - expiration) / vs->count) + 1;

            /*
             * The specification says that if the timer is not lazy then
             * a non-zero missed count should be used to reduce the period
             * of the timer until it catches up, unless the count has
             * reached a 'significant number', in which case the timer
             * should be treated as lazy. Unfortunately the specification
             * does not state what that number is so the choice of number
             * here is a pure guess.
             */
            if ( missed > 3 )
                expiration = now + vs->count;
            else if ( missed )
                expiration = now + (vs->count / missed);
        }
    }
    else
    {
        expiration = vs->count;
        if ( expiration - now <= 0 )
        {
            vs->expiration = expiration;
            stimer_expire(vs);
            return;
        }
    }
    ASSERT(expiration - now > 0);

    vs->expiration = expiration;
    timeout = (expiration - now) * 100ull;

    vs->started = true;
    clear_bit(stimerx, &vv->stimer_pending);
    migrate_timer(&vs->timer, v->processor);
    set_timer(&vs->timer, timeout + NOW());
}

static void poll_stimer(struct vcpu *v, unsigned int stimerx)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct viridian_stimer *vs = &vv->stimer[stimerx];

    /*
     * Timer expiry may race with the timer being disabled. If the timer
     * is disabled make sure the pending bit is cleared to avoid re-
     * polling.
     */
    if ( !vs->config.enable )
    {
        clear_bit(stimerx, &vv->stimer_pending);
        return;
    }

    if ( !test_bit(stimerx, &vv->stimer_pending) )
        return;

    if ( !viridian_synic_deliver_timer_msg(v, vs->config.sintx,
                                           stimerx, vs->expiration,
                                           time_ref_count(v->domain)) )
        return;

    clear_bit(stimerx, &vv->stimer_pending);

    if ( vs->config.periodic )
        start_stimer(vs);
    else
        vs->config.enable = 0;
}

void viridian_time_poll_timers(struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    if ( !vv->stimer_pending )
       return;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
        poll_stimer(v, i);
}

static void time_vcpu_freeze(struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    if ( !is_viridian_vcpu(v) ||
         !(viridian_feature_mask(v->domain) & HVMPV_stimer) )
        return;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        struct viridian_stimer *vs = &vv->stimer[i];

        if ( vs->started )
            stop_timer(&vs->timer);
    }
}

static void time_vcpu_thaw(struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    if ( !is_viridian_vcpu(v) ||
         !(viridian_feature_mask(v->domain) & HVMPV_stimer) )
        return;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        struct viridian_stimer *vs = &vv->stimer[i];

        if ( vs->config.enable )
            start_stimer(vs);
    }
}

void viridian_time_domain_freeze(const struct domain *d)
{
    struct vcpu *v;

    if ( d->is_dying || !is_viridian_domain(d) )
        return;

    for_each_vcpu ( d, v )
        time_vcpu_freeze(v);

    time_ref_count_freeze(d);
}

void viridian_time_domain_thaw(const struct domain *d)
{
    struct vcpu *v;

    if ( d->is_dying || !is_viridian_domain(d) )
        return;

    time_ref_count_thaw(d);

    for_each_vcpu ( d, v )
        time_vcpu_thaw(v);
}

int viridian_time_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct domain *d = v->domain;
    struct viridian_domain *vd = d->arch.hvm.viridian;

    switch ( idx )
    {
    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return X86EMUL_EXCEPTION;

        viridian_unmap_guest_page(&vd->reference_tsc);
        vd->reference_tsc.msr.raw = val;
        viridian_dump_guest_page(v, "REFERENCE_TSC", &vd->reference_tsc);
        if ( vd->reference_tsc.msr.enabled )
        {
            viridian_map_guest_page(d, &vd->reference_tsc);
            update_reference_tsc(d, true);
        }
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        struct viridian_stimer *vs =
            &array_access_nospec(vv->stimer, stimerx);

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        stop_stimer(vs);

        vs->config.as_uint64 = val;

        if ( !vs->config.sintx )
            vs->config.enable = 0;

        if ( vs->config.enable )
            start_stimer(vs);

        break;
    }

    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        struct viridian_stimer *vs =
            &array_access_nospec(vv->stimer, stimerx);

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        stop_stimer(vs);

        vs->count = val;

        if ( !vs->count  )
            vs->config.enable = 0;
        else if ( vs->config.auto_enable )
            vs->config.enable = 1;

        if ( vs->config.enable )
            start_stimer(vs);

        break;
    }

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_time_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    const struct domain *d = v->domain;
    struct viridian_domain *vd = d->arch.hvm.viridian;

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

        *val = vd->reference_tsc.msr.raw;
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
    {
        struct viridian_time_ref_count *trc = &vd->time_ref_count;

        if ( !(viridian_feature_mask(d) & HVMPV_time_ref_count) )
            return X86EMUL_EXCEPTION;

        if ( !test_and_set_bit(_TRC_accessed, &trc->flags) )
            printk(XENLOG_G_INFO "d%d: VIRIDIAN MSR_TIME_REF_COUNT: accessed\n",
                   d->domain_id);

        *val = time_ref_count(d);
        break;
    }

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        const struct viridian_stimer *vs =
            &array_access_nospec(vv->stimer, stimerx);
        union hv_stimer_config config = vs->config;

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        /*
         * If the timer is single-shot and it has expired, make sure
         * the enabled flag is clear.
         */
        if ( !config.periodic && test_bit(stimerx, &vv->stimer_pending) )
            config.enable = 0;

        *val = config.as_uint64;
        break;
    }

    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        const struct viridian_stimer *vs =
            &array_access_nospec(vv->stimer, stimerx);

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        *val = vs->count;
        break;
    }

    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_time_vcpu_init(struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        struct viridian_stimer *vs = &vv->stimer[i];

        vs->v = v;
        init_timer(&vs->timer, stimer_expire, vs, v->processor);
    }

    return 0;
}

int viridian_time_domain_init(const struct domain *d)
{
    return 0;
}

void viridian_time_vcpu_deinit(const struct vcpu *v)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        struct viridian_stimer *vs = &vv->stimer[i];

        if ( !vs->v )
            continue;
        kill_timer(&vs->timer);
        vs->v = NULL;
    }
}

void viridian_time_domain_deinit(const struct domain *d)
{
    viridian_unmap_guest_page(&d->arch.hvm.viridian->reference_tsc);
}

void viridian_time_save_vcpu_ctxt(
    const struct vcpu *v, struct hvm_viridian_vcpu_context *ctxt)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    BUILD_BUG_ON(ARRAY_SIZE(vv->stimer) !=
                 ARRAY_SIZE(ctxt->stimer_config_msr));
    BUILD_BUG_ON(ARRAY_SIZE(vv->stimer) !=
                 ARRAY_SIZE(ctxt->stimer_count_msr));

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        const struct viridian_stimer *vs = &vv->stimer[i];

        ctxt->stimer_config_msr[i] = vs->config.as_uint64;
        ctxt->stimer_count_msr[i] = vs->count;
    }
}

void viridian_time_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(vv->stimer); i++ )
    {
        struct viridian_stimer *vs = &vv->stimer[i];

        vs->config.as_uint64 = ctxt->stimer_config_msr[i];
        vs->count = ctxt->stimer_count_msr[i];
    }
}

void viridian_time_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt)
{
    const struct viridian_domain *vd = d->arch.hvm.viridian;

    ctxt->time_ref_count = vd->time_ref_count.val;
    ctxt->reference_tsc = vd->reference_tsc.msr.raw;
}

void viridian_time_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt)
{
    struct viridian_domain *vd = d->arch.hvm.viridian;

    vd->time_ref_count.val = ctxt->time_ref_count;
    vd->reference_tsc.msr.raw = ctxt->reference_tsc;

    if ( vd->reference_tsc.msr.enabled )
        viridian_map_guest_page(d, &vd->reference_tsc);
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
