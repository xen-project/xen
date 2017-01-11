#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/cpuid.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/processor.h>
#include <asm/xstate.h>

const uint32_t known_features[] = INIT_KNOWN_FEATURES;
const uint32_t special_features[] = INIT_SPECIAL_FEATURES;

static const uint32_t __initconst pv_featuremask[] = INIT_PV_FEATURES;
static const uint32_t __initconst hvm_shadow_featuremask[] = INIT_HVM_SHADOW_FEATURES;
static const uint32_t __initconst hvm_hap_featuremask[] = INIT_HVM_HAP_FEATURES;
static const uint32_t __initconst deep_features[] = INIT_DEEP_FEATURES;

#define EMPTY_LEAF ((struct cpuid_leaf){})

struct cpuid_policy __read_mostly raw_policy,
    __read_mostly host_policy,
    __read_mostly pv_max_policy,
    __read_mostly hvm_max_policy;

static void cpuid_leaf(uint32_t leaf, struct cpuid_leaf *data)
{
    cpuid(leaf, &data->a, &data->b, &data->c, &data->d);
}

static void cpuid_count_leaf(uint32_t leaf, uint32_t subleaf,
                             struct cpuid_leaf *data)
{
    cpuid_count(leaf, subleaf, &data->a, &data->b, &data->c, &data->d);
}

static void __init sanitise_featureset(uint32_t *fs)
{
    /* for_each_set_bit() uses unsigned longs.  Extend with zeroes. */
    uint32_t disabled_features[
        ROUNDUP(FSCAPINTS, sizeof(unsigned long)/sizeof(uint32_t))] = {};
    unsigned int i;

    for ( i = 0; i < FSCAPINTS; ++i )
    {
        /* Clamp to known mask. */
        fs[i] &= known_features[i];

        /*
         * Identify which features with deep dependencies have been
         * disabled.
         */
        disabled_features[i] = ~fs[i] & deep_features[i];
    }

    for_each_set_bit(i, (void *)disabled_features,
                     sizeof(disabled_features) * 8)
    {
        const uint32_t *dfs = lookup_deep_deps(i);
        unsigned int j;

        ASSERT(dfs); /* deep_features[] should guarentee this. */

        for ( j = 0; j < FSCAPINTS; ++j )
        {
            fs[j] &= ~dfs[j];
            disabled_features[j] &= ~dfs[j];
        }
    }

    /*
     * Sort out shared bits.  We are constructing a featureset which needs to
     * be applicable to a cross-vendor case.  Intel strictly clears the common
     * bits in e1d, while AMD strictly duplicates them.
     *
     * We duplicate them here to be compatible with AMD while on Intel, and
     * rely on logic closer to the guest to make the featureset stricter if
     * emulating Intel.
     */
    fs[FEATURESET_e1d] = ((fs[FEATURESET_1d]  &  CPUID_COMMON_1D_FEATURES) |
                          (fs[FEATURESET_e1d] & ~CPUID_COMMON_1D_FEATURES));
}

static void __init calculate_raw_policy(void)
{
    struct cpuid_policy *p = &raw_policy;
    unsigned int i;

    cpuid_leaf(0, &p->basic.raw[0]);
    for ( i = 1; i < min(ARRAY_SIZE(p->basic.raw),
                         p->basic.max_leaf + 1ul); ++i )
    {
        switch ( i )
        {
        case 0x2: case 0x4: case 0x7: case 0xd:
            /* Multi-invocation leaves.  Deferred. */
            continue;
        }

        cpuid_leaf(i, &p->basic.raw[i]);
    }

    if ( p->basic.max_leaf >= 7 )
    {
        cpuid_count_leaf(7, 0, &p->feat.raw[0]);

        for ( i = 1; i < min(ARRAY_SIZE(p->feat.raw),
                             p->feat.max_subleaf + 1ul); ++i )
            cpuid_count_leaf(7, i, &p->feat.raw[i]);
    }

    if ( p->basic.max_leaf >= XSTATE_CPUID )
    {
        uint64_t xstates;

        cpuid_count_leaf(XSTATE_CPUID, 0, &p->xstate.raw[0]);
        cpuid_count_leaf(XSTATE_CPUID, 1, &p->xstate.raw[1]);

        xstates = ((uint64_t)(p->xstate.xcr0_high | p->xstate.xss_high) << 32) |
            (p->xstate.xcr0_low | p->xstate.xss_low);

        for ( i = 2; i < min(63ul, ARRAY_SIZE(p->xstate.raw)); ++i )
        {
            if ( xstates & (1ul << i) )
                cpuid_count_leaf(XSTATE_CPUID, i, &p->xstate.raw[i]);
        }
    }

    /* Extended leaves. */
    cpuid_leaf(0x80000000, &p->extd.raw[0]);
    for ( i = 1; i < min(ARRAY_SIZE(p->extd.raw),
                         p->extd.max_leaf + 1 - 0x80000000ul); ++i )
        cpuid_leaf(0x80000000 + i, &p->extd.raw[i]);

    cpuid_policy_to_featureset(p, p->fs);
}

static void __init calculate_host_policy(void)
{
    struct cpuid_policy *p = &host_policy;

    memcpy(p->fs, boot_cpu_data.x86_capability, sizeof(p->fs));

    cpuid_featureset_to_policy(host_featureset, p);
}

static void __init calculate_pv_max_policy(void)
{
    struct cpuid_policy *p = &pv_max_policy;
    unsigned int i;

    for ( i = 0; i < FSCAPINTS; ++i )
        pv_featureset[i] = host_featureset[i] & pv_featuremask[i];

    /* Unconditionally claim to be able to set the hypervisor bit. */
    __set_bit(X86_FEATURE_HYPERVISOR, pv_featureset);

    /*
     * Allow the toolstack to set HTT, X2APIC and CMP_LEGACY.  These bits
     * affect how to interpret topology information in other cpuid leaves.
     */
    __set_bit(X86_FEATURE_HTT, pv_featureset);
    __set_bit(X86_FEATURE_X2APIC, pv_featureset);
    __set_bit(X86_FEATURE_CMP_LEGACY, pv_featureset);

    sanitise_featureset(pv_featureset);
    cpuid_featureset_to_policy(pv_featureset, p);
}

static void __init calculate_hvm_max_policy(void)
{
    struct cpuid_policy *p = &hvm_max_policy;
    unsigned int i;
    const uint32_t *hvm_featuremask;

    if ( !hvm_enabled )
        return;

    hvm_featuremask = hvm_funcs.hap_supported ?
        hvm_hap_featuremask : hvm_shadow_featuremask;

    for ( i = 0; i < FSCAPINTS; ++i )
        hvm_featureset[i] = host_featureset[i] & hvm_featuremask[i];

    /* Unconditionally claim to be able to set the hypervisor bit. */
    __set_bit(X86_FEATURE_HYPERVISOR, hvm_featureset);

    /*
     * Allow the toolstack to set HTT, X2APIC and CMP_LEGACY.  These bits
     * affect how to interpret topology information in other cpuid leaves.
     */
    __set_bit(X86_FEATURE_HTT, hvm_featureset);
    __set_bit(X86_FEATURE_X2APIC, hvm_featureset);
    __set_bit(X86_FEATURE_CMP_LEGACY, hvm_featureset);

    /*
     * Xen can provide an APIC emulation to HVM guests even if the host's APIC
     * isn't enabled.
     */
    __set_bit(X86_FEATURE_APIC, hvm_featureset);

    /*
     * On AMD, PV guests are entirely unable to use SYSENTER as Xen runs in
     * long mode (and init_amd() has cleared it out of host capabilities), but
     * HVM guests are able if running in protected mode.
     */
    if ( (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) &&
         test_bit(X86_FEATURE_SEP, raw_featureset) )
        __set_bit(X86_FEATURE_SEP, hvm_featureset);

    /*
     * With VT-x, some features are only supported by Xen if dedicated
     * hardware support is also available.
     */
    if ( cpu_has_vmx )
    {
        if ( !cpu_has_vmx_mpx )
            __clear_bit(X86_FEATURE_MPX, hvm_featureset);

        if ( !cpu_has_vmx_xsaves )
            __clear_bit(X86_FEATURE_XSAVES, hvm_featureset);
    }

    sanitise_featureset(hvm_featureset);
    cpuid_featureset_to_policy(hvm_featureset, p);
}

void __init init_guest_cpuid(void)
{
    calculate_raw_policy();
    calculate_host_policy();
    calculate_pv_max_policy();
    calculate_hvm_max_policy();
}

const uint32_t * __init lookup_deep_deps(uint32_t feature)
{
    static const struct {
        uint32_t feature;
        uint32_t fs[FSCAPINTS];
    } deep_deps[] __initconst = INIT_DEEP_DEPS;
    unsigned int start = 0, end = ARRAY_SIZE(deep_deps);

    BUILD_BUG_ON(ARRAY_SIZE(deep_deps) != NR_DEEP_DEPS);

    /* Fast early exit. */
    if ( !test_bit(feature, deep_features) )
        return NULL;

    /* deep_deps[] is sorted.  Perform a binary search. */
    while ( start < end )
    {
        unsigned int mid = start + ((end - start) / 2);

        if ( deep_deps[mid].feature > feature )
            end = mid;
        else if ( deep_deps[mid].feature < feature )
            start = mid + 1;
        else
            return deep_deps[mid].fs;
    }

    return NULL;
}

int init_domain_cpuid_policy(struct domain *d)
{
    d->arch.cpuid = xmalloc(struct cpuid_policy);

    if ( !d->arch.cpuid )
        return -ENOMEM;

    *d->arch.cpuid = is_pv_domain(d) ? pv_max_policy : hvm_max_policy;

    return 0;
}

void guest_cpuid(const struct vcpu *v, uint32_t leaf,
                 uint32_t subleaf, struct cpuid_leaf *res)
{
    const struct domain *d = v->domain;

    *res = EMPTY_LEAF;

    /* {hvm,pv}_cpuid() have this expectation. */
    ASSERT(v == current);

    if ( is_hvm_domain(d) )
    {
        res->c = subleaf;

        hvm_cpuid(leaf, &res->a, &res->b, &res->c, &res->d);
    }
    else
    {
        struct cpu_user_regs regs = *guest_cpu_user_regs();

        regs._eax = leaf;
        regs._ecx = subleaf;

        pv_cpuid(&regs);

        res->a = regs._eax;
        res->b = regs._ebx;
        res->c = regs._ecx;
        res->d = regs._edx;
    }
}

static void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(ARRAY_SIZE(known_features) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(special_features) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(pv_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_shadow_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_hap_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(deep_features) != FSCAPINTS);

    /* Find some more clever allocation scheme if this trips. */
    BUILD_BUG_ON(sizeof(struct cpuid_policy) > PAGE_SIZE);

    BUILD_BUG_ON(sizeof(raw_policy.basic) !=
                 sizeof(raw_policy.basic.raw));
    BUILD_BUG_ON(sizeof(raw_policy.feat) !=
                 sizeof(raw_policy.feat.raw));
    BUILD_BUG_ON(sizeof(raw_policy.xstate) !=
                 sizeof(raw_policy.xstate.raw));
    BUILD_BUG_ON(sizeof(raw_policy.extd) !=
                 sizeof(raw_policy.extd.raw));
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
