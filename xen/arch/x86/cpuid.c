#include <xen/init.h>
#include <xen/lib.h>
#include <asm/cpuid.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/processor.h>

const uint32_t known_features[] = INIT_KNOWN_FEATURES;
const uint32_t special_features[] = INIT_SPECIAL_FEATURES;

static const uint32_t __initconst pv_featuremask[] = INIT_PV_FEATURES;
static const uint32_t __initconst hvm_shadow_featuremask[] = INIT_HVM_SHADOW_FEATURES;
static const uint32_t __initconst hvm_hap_featuremask[] = INIT_HVM_HAP_FEATURES;
static const uint32_t __initconst deep_features[] = INIT_DEEP_FEATURES;

uint32_t __read_mostly raw_featureset[FSCAPINTS];
uint32_t __read_mostly pv_featureset[FSCAPINTS];
uint32_t __read_mostly hvm_featureset[FSCAPINTS];

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

static void __init calculate_raw_featureset(void)
{
    unsigned int max, tmp;

    max = cpuid_eax(0);

    if ( max >= 1 )
        cpuid(0x1, &tmp, &tmp,
              &raw_featureset[FEATURESET_1c],
              &raw_featureset[FEATURESET_1d]);
    if ( max >= 7 )
        cpuid_count(0x7, 0, &tmp,
                    &raw_featureset[FEATURESET_7b0],
                    &raw_featureset[FEATURESET_7c0],
                    &tmp);
    if ( max >= 0xd )
        cpuid_count(0xd, 1,
                    &raw_featureset[FEATURESET_Da1],
                    &tmp, &tmp, &tmp);

    max = cpuid_eax(0x80000000);
    if ( (max >> 16) != 0x8000 )
        return;

    if ( max >= 0x80000001 )
        cpuid(0x80000001, &tmp, &tmp,
              &raw_featureset[FEATURESET_e1c],
              &raw_featureset[FEATURESET_e1d]);
    if ( max >= 0x80000007 )
        cpuid(0x80000007, &tmp, &tmp, &tmp,
              &raw_featureset[FEATURESET_e7d]);
    if ( max >= 0x80000008 )
        cpuid(0x80000008, &tmp,
              &raw_featureset[FEATURESET_e8b],
              &tmp, &tmp);
}

static void __init calculate_pv_featureset(void)
{
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
}

static void __init calculate_hvm_featureset(void)
{
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
}

void __init calculate_featuresets(void)
{
    calculate_raw_featureset();
    calculate_pv_featureset();
    calculate_hvm_featureset();
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

static void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(ARRAY_SIZE(known_features) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(special_features) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(pv_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_shadow_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_hap_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(deep_features) != FSCAPINTS);
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
