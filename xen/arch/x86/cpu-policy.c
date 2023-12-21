/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/cache.h>
#include <xen/kernel.h>
#include <xen/param.h>
#include <xen/sched.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/amd.h>
#include <asm/cpu-policy.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/svm.h>
#include <asm/intel-family.h>
#include <asm/msr-index.h>
#include <asm/paging.h>
#include <asm/setup.h>
#include <asm/xstate.h>

struct cpu_policy __read_mostly       raw_cpu_policy;
struct cpu_policy __ro_after_init    host_cpu_policy;
#ifdef CONFIG_PV
struct cpu_policy __ro_after_init  pv_max_cpu_policy;
struct cpu_policy __ro_after_init  pv_def_cpu_policy;
#endif
#ifdef CONFIG_HVM
struct cpu_policy __ro_after_init hvm_max_cpu_policy;
struct cpu_policy __ro_after_init hvm_def_cpu_policy;
#endif

const uint32_t known_features[] = INIT_KNOWN_FEATURES;

static const uint32_t __initconst pv_max_featuremask[] = INIT_PV_MAX_FEATURES;
static const uint32_t hvm_shadow_max_featuremask[] = INIT_HVM_SHADOW_MAX_FEATURES;
static const uint32_t __initconst hvm_hap_max_featuremask[] =
    INIT_HVM_HAP_MAX_FEATURES;
static const uint32_t __initconst pv_def_featuremask[] = INIT_PV_DEF_FEATURES;
static const uint32_t __initconst hvm_shadow_def_featuremask[] =
    INIT_HVM_SHADOW_DEF_FEATURES;
static const uint32_t __initconst hvm_hap_def_featuremask[] =
    INIT_HVM_HAP_DEF_FEATURES;
static const uint32_t deep_features[] = INIT_DEEP_FEATURES;

static const struct feature_name {
    const char *name;
    unsigned int bit;
} feature_names[] __initconstrel = INIT_FEATURE_NAMES;

/*
 * Parse a list of cpuid feature names -> bool, calling the callback for any
 * matches found.
 *
 * always_inline, because this is init code only and we really don't want a
 * function pointer call in the middle of the loop.
 */
static int __init always_inline parse_cpuid(
    const char *s, void (*callback)(unsigned int feat, bool val))
{
    const char *ss;
    int val, rc = 0;

    do {
        const struct feature_name *lhs, *rhs, *mid = NULL /* GCC... */;
        const char *feat;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        /* Skip the 'no-' prefix for name comparisons. */
        feat = s;
        if ( strncmp(s, "no-", 3) == 0 )
            feat += 3;

        /* (Re)initalise lhs and rhs for binary search. */
        lhs = feature_names;
        rhs = feature_names + ARRAY_SIZE(feature_names);

        while ( lhs < rhs )
        {
            int res;

            mid = lhs + (rhs - lhs) / 2;
            res = cmdline_strcmp(feat, mid->name);

            if ( res < 0 )
            {
                rhs = mid;
                continue;
            }
            if ( res > 0 )
            {
                lhs = mid + 1;
                continue;
            }

            if ( (val = parse_boolean(mid->name, s, ss)) >= 0 )
            {
                callback(mid->bit, val);
                mid = NULL;
            }

            break;
        }

        /*
         * Mid being NULL means that the name and boolean were successfully
         * identified.  Everything else is an error.
         */
        if ( mid )
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}

static void __init cf_check _parse_xen_cpuid(unsigned int feat, bool val)
{
    if ( !val )
        setup_clear_cpu_cap(feat);
    else if ( feat == X86_FEATURE_RDRAND &&
              (cpuid_ecx(1) & cpufeat_mask(X86_FEATURE_RDRAND)) )
        setup_force_cpu_cap(X86_FEATURE_RDRAND);
}

static int __init cf_check parse_xen_cpuid(const char *s)
{
    return parse_cpuid(s, _parse_xen_cpuid);
}
custom_param("cpuid", parse_xen_cpuid);

static bool __initdata dom0_cpuid_cmdline;
static uint32_t __initdata dom0_enable_feat[FSCAPINTS];
static uint32_t __initdata dom0_disable_feat[FSCAPINTS];

static void __init cf_check _parse_dom0_cpuid(unsigned int feat, bool val)
{
    __set_bit  (feat, val ? dom0_enable_feat  : dom0_disable_feat);
    __clear_bit(feat, val ? dom0_disable_feat : dom0_enable_feat );
}

static int __init cf_check parse_dom0_cpuid(const char *s)
{
    dom0_cpuid_cmdline = true;

    return parse_cpuid(s, _parse_dom0_cpuid);
}
custom_param("dom0-cpuid", parse_dom0_cpuid);

#define EMPTY_LEAF ((struct cpuid_leaf){})
static void zero_leaves(struct cpuid_leaf *l,
                        unsigned int first, unsigned int last)
{
    memset(&l[first], 0, sizeof(*l) * (last - first + 1));
}

static void sanitise_featureset(uint32_t *fs)
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
        const uint32_t *dfs = x86_cpu_policy_lookup_deep_deps(i);
        unsigned int j;

        ASSERT(dfs); /* deep_features[] should guarentee this. */

        for ( j = 0; j < FSCAPINTS; ++j )
        {
            fs[j] &= ~dfs[j];
            disabled_features[j] &= ~dfs[j];
        }
    }
}

static void recalculate_xstate(struct cpu_policy *p)
{
    uint64_t xstates = XSTATE_FP_SSE;
    uint32_t xstate_size = XSTATE_AREA_MIN_SIZE;
    unsigned int i, Da1 = p->xstate.Da1;

    /*
     * The Da1 leaf is the only piece of information preserved in the common
     * case.  Everything else is derived from other feature state.
     */
    memset(&p->xstate, 0, sizeof(p->xstate));

    if ( !p->basic.xsave )
        return;

    if ( p->basic.avx )
    {
        xstates |= X86_XCR0_YMM;
        xstate_size = max(xstate_size,
                          xstate_offsets[X86_XCR0_YMM_POS] +
                          xstate_sizes[X86_XCR0_YMM_POS]);
    }

    if ( p->feat.mpx )
    {
        xstates |= X86_XCR0_BNDREGS | X86_XCR0_BNDCSR;
        xstate_size = max(xstate_size,
                          xstate_offsets[X86_XCR0_BNDCSR_POS] +
                          xstate_sizes[X86_XCR0_BNDCSR_POS]);
    }

    if ( p->feat.avx512f )
    {
        xstates |= X86_XCR0_OPMASK | X86_XCR0_ZMM | X86_XCR0_HI_ZMM;
        xstate_size = max(xstate_size,
                          xstate_offsets[X86_XCR0_HI_ZMM_POS] +
                          xstate_sizes[X86_XCR0_HI_ZMM_POS]);
    }

    if ( p->feat.pku )
    {
        xstates |= X86_XCR0_PKRU;
        xstate_size = max(xstate_size,
                          xstate_offsets[X86_XCR0_PKRU_POS] +
                          xstate_sizes[X86_XCR0_PKRU_POS]);
    }

    p->xstate.max_size  =  xstate_size;
    p->xstate.xcr0_low  =  xstates & ~XSTATE_XSAVES_ONLY;
    p->xstate.xcr0_high = (xstates & ~XSTATE_XSAVES_ONLY) >> 32;

    p->xstate.Da1 = Da1;
    if ( p->xstate.xsaves )
    {
        p->xstate.xss_low   =  xstates & XSTATE_XSAVES_ONLY;
        p->xstate.xss_high  = (xstates & XSTATE_XSAVES_ONLY) >> 32;
    }
    else
        xstates &= ~XSTATE_XSAVES_ONLY;

    for ( i = 2; i < min(63UL, ARRAY_SIZE(p->xstate.comp)); ++i )
    {
        uint64_t curr_xstate = 1UL << i;

        if ( !(xstates & curr_xstate) )
            continue;

        p->xstate.comp[i].size   = xstate_sizes[i];
        p->xstate.comp[i].offset = xstate_offsets[i];
        p->xstate.comp[i].xss    = curr_xstate & XSTATE_XSAVES_ONLY;
        p->xstate.comp[i].align  = curr_xstate & xstate_align;
    }
}

/*
 * Misc adjustments to the policy.  Mostly clobbering reserved fields and
 * duplicating shared fields.  Intentionally hidden fields are annotated.
 */
static void recalculate_misc(struct cpu_policy *p)
{
    p->basic.raw_fms &= 0x0fff0fff; /* Clobber Processor Type on Intel. */
    p->basic.apic_id = 0; /* Dynamic. */

    p->basic.raw[0x5] = EMPTY_LEAF; /* MONITOR not exposed to guests. */
    p->basic.raw[0x6] = EMPTY_LEAF; /* Therm/Power not exposed to guests. */

    p->basic.raw[0x8] = EMPTY_LEAF;

    /* TODO: Rework topology logic. */
    memset(p->topo.raw, 0, sizeof(p->topo.raw));

    p->basic.raw[0xc] = EMPTY_LEAF;

    p->extd.e1d &= ~CPUID_COMMON_1D_FEATURES;

    /* Most of Power/RAS hidden from guests. */
    p->extd.raw[0x7].a = p->extd.raw[0x7].b = p->extd.raw[0x7].c = 0;

    p->extd.raw[0x8].d = 0;

    switch ( p->x86_vendor )
    {
    case X86_VENDOR_INTEL:
        p->basic.l2_nr_queries = 1; /* Fixed to 1 query. */
        p->basic.raw[0x3] = EMPTY_LEAF; /* PSN - always hidden. */
        p->basic.raw[0x9] = EMPTY_LEAF; /* DCA - always hidden. */

        p->extd.vendor_ebx = 0;
        p->extd.vendor_ecx = 0;
        p->extd.vendor_edx = 0;

        p->extd.raw[0x1].a = p->extd.raw[0x1].b = 0;

        p->extd.raw[0x5] = EMPTY_LEAF;
        p->extd.raw[0x6].a = p->extd.raw[0x6].b = p->extd.raw[0x6].d = 0;

        p->extd.raw[0x8].a &= 0x0000ffff;
        p->extd.raw[0x8].c = 0;
        break;

    case X86_VENDOR_AMD:
    case X86_VENDOR_HYGON:
        zero_leaves(p->basic.raw, 0x2, 0x3);
        memset(p->cache.raw, 0, sizeof(p->cache.raw));
        zero_leaves(p->basic.raw, 0x9, 0xa);

        p->extd.vendor_ebx = p->basic.vendor_ebx;
        p->extd.vendor_ecx = p->basic.vendor_ecx;
        p->extd.vendor_edx = p->basic.vendor_edx;

        p->extd.raw_fms = p->basic.raw_fms;
        p->extd.raw[0x1].b &= 0xff00ffffU;
        p->extd.e1d |= p->basic._1d & CPUID_COMMON_1D_FEATURES;

        p->extd.raw[0x8].a &= 0x0000ffff; /* GuestMaxPhysAddr hidden. */
        p->extd.raw[0x8].c &= 0x0003f0ff;

        p->extd.raw[0x9] = EMPTY_LEAF;

        zero_leaves(p->extd.raw, 0xb, 0x18);

        /* 0x19 - TLB details.  Pass through. */
        /* 0x1a - Perf hints.   Pass through. */

        p->extd.raw[0x1b] = EMPTY_LEAF; /* IBS - not supported. */
        p->extd.raw[0x1c] = EMPTY_LEAF; /* LWP - not supported. */
        p->extd.raw[0x1d] = EMPTY_LEAF; /* TopoExt Cache */
        p->extd.raw[0x1e] = EMPTY_LEAF; /* TopoExt APIC ID/Core/Node */
        p->extd.raw[0x1f] = EMPTY_LEAF; /* SEV */
        p->extd.raw[0x20] = EMPTY_LEAF; /* Platform QoS */
        break;
    }
}

void calculate_raw_cpu_policy(void)
{
    struct cpu_policy *p = &raw_cpu_policy;

    x86_cpu_policy_fill_native(p);

    /* Nothing good will come from Xen and libx86 disagreeing on vendor. */
    ASSERT(p->x86_vendor == boot_cpu_data.x86_vendor);

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    /* Was already added by probe_cpuid_faulting() */
}

static void __init calculate_host_policy(void)
{
    struct cpu_policy *p = &host_cpu_policy;
    unsigned int max_extd_leaf;

    *p = raw_cpu_policy;

    p->basic.max_leaf =
        min_t(uint32_t, p->basic.max_leaf,   ARRAY_SIZE(p->basic.raw) - 1);
    p->feat.max_subleaf =
        min_t(uint32_t, p->feat.max_subleaf, ARRAY_SIZE(p->feat.raw) - 1);

    max_extd_leaf = p->extd.max_leaf;

    /*
     * For AMD/Hygon hardware before Zen3, we unilaterally modify LFENCE to be
     * dispatch serialising for Spectre mitigations.  Extend max_extd_leaf
     * beyond what hardware supports, to include the feature leaf containing
     * this information.
     */
    if ( cpu_has_lfence_dispatch )
        max_extd_leaf = max(max_extd_leaf, 0x80000021U);

    p->extd.max_leaf = 0x80000000U | min_t(uint32_t, max_extd_leaf & 0xffff,
                                           ARRAY_SIZE(p->extd.raw) - 1);

    x86_cpu_featureset_to_policy(boot_cpu_data.x86_capability, p);
    recalculate_xstate(p);
    recalculate_misc(p);

    /* When vPMU is disabled, drop it from the host policy. */
    if ( vpmu_mode == XENPMU_MODE_OFF )
        p->basic.raw[0xa] = EMPTY_LEAF;

    if ( p->extd.svm )
    {
        /* Clamp to implemented features which require hardware support. */
        p->extd.raw[0xa].d &= ((1u << SVM_FEATURE_NPT) |
                               (1u << SVM_FEATURE_LBRV) |
                               (1u << SVM_FEATURE_NRIPS) |
                               (1u << SVM_FEATURE_PAUSEFILTER) |
                               (1u << SVM_FEATURE_DECODEASSISTS));
        /* Enable features which are always emulated. */
        p->extd.raw[0xa].d |= ((1u << SVM_FEATURE_VMCBCLEAN) |
                               (1u << SVM_FEATURE_TSCRATEMSR));
    }

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    /* probe_cpuid_faulting() sanity checks presence of MISC_FEATURES_ENABLES */
    p->platform_info.cpuid_faulting = cpu_has_cpuid_faulting;
}

static void __init guest_common_max_feature_adjustments(uint32_t *fs)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
    {
        /*
         * MSR_ARCH_CAPS is just feature data, and we can offer it to guests
         * unconditionally, although limit it to Intel systems as it is highly
         * uarch-specific.
         *
         * In particular, the RSBA and RRSBA bits mean "you might migrate to a
         * system where RSB underflow uses alternative predictors (a.k.a
         * Retpoline not safe)", so these need to be visible to a guest in all
         * cases, even when it's only some other server in the pool which
         * suffers the identified behaviour.
         *
         * We can always run any VM which has previously (or will
         * subsequently) run on hardware where Retpoline is not safe.
         * Note:
         *  - The dependency logic may hide RRSBA for other reasons.
         *  - The max policy does not constitute a sensible configuration to
         *    run a guest in.
         */
        __set_bit(X86_FEATURE_ARCH_CAPS, fs);
        __set_bit(X86_FEATURE_RSBA, fs);
        __set_bit(X86_FEATURE_RRSBA, fs);

        /*
         * The Gather Data Sampling microcode mitigation (August 2023) has an
         * adverse performance impact on the CLWB instruction on SKX/CLX/CPX.
         *
         * We hid CLWB in the host policy to stop Xen using it, but VMs which
         * have previously seen the CLWB feature can safely run on this CPU.
         */
        if ( boot_cpu_data.x86 == 6 &&
             boot_cpu_data.x86_model == INTEL_FAM6_SKYLAKE_X &&
             raw_cpu_policy.feat.clwb )
            __set_bit(X86_FEATURE_CLWB, fs);
    }
}

static void __init guest_common_default_feature_adjustments(uint32_t *fs)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
    {
        /*
         * IvyBridge client parts suffer from leakage of RDRAND data due to SRBDS
         * (XSA-320 / CVE-2020-0543), and won't be receiving microcode to
         * compensate.
         *
         * Mitigate by hiding RDRAND from guests by default, unless explicitly
         * overridden on the Xen command line (cpuid=rdrand).  Irrespective of the
         * default setting, guests can use RDRAND if explicitly enabled
         * (cpuid="host,rdrand=1") in the VM's config file, and VMs which were
         * previously using RDRAND can migrate in.
         */
        if ( boot_cpu_data.x86 == 6 &&
             boot_cpu_data.x86_model == INTEL_FAM6_IVYBRIDGE &&
             cpu_has_rdrand && !is_forced_cpu_cap(X86_FEATURE_RDRAND) )
            __clear_bit(X86_FEATURE_RDRAND, fs);

        /*
         * The Gather Data Sampling microcode mitigation (August 2023) has an
         * adverse performance impact on the CLWB instruction on SKX/CLX/CPX.
         *
         * We hid CLWB in the host policy to stop Xen using it, but re-added
         * it to the max policy to let VMs migrate in.  Re-hide it in the
         * default policy to disuade VMs from using it in the common case.
         */
        if ( boot_cpu_data.x86 == 6 &&
             boot_cpu_data.x86_model == INTEL_FAM6_SKYLAKE_X &&
             raw_cpu_policy.feat.clwb )
            __clear_bit(X86_FEATURE_CLWB, fs);
    }

    /*
     * On certain hardware, speculative or errata workarounds can result in
     * TSX being placed in "force-abort" mode, where it doesn't actually
     * function as expected, but is technically compatible with the ISA.
     *
     * Do not advertise RTM to guests by default if it won't actually work.
     */
    if ( rtm_disabled )
        __clear_bit(X86_FEATURE_RTM, fs);
}

static void __init guest_common_feature_adjustments(uint32_t *fs)
{
    /* Unconditionally claim to be able to set the hypervisor bit. */
    __set_bit(X86_FEATURE_HYPERVISOR, fs);

    /*
     * If IBRS is offered to the guest, unconditionally offer STIBP.  It is a
     * nop on non-HT hardware, and has this behaviour to make heterogeneous
     * setups easier to manage.
     */
    if ( test_bit(X86_FEATURE_IBRSB, fs) )
        __set_bit(X86_FEATURE_STIBP, fs);
    if ( test_bit(X86_FEATURE_IBRS, fs) )
        __set_bit(X86_FEATURE_AMD_STIBP, fs);

    /*
     * On hardware which supports IBRS/IBPB, we can offer IBPB independently
     * of IBRS by using the AMD feature bit.  An administrator may wish for
     * performance reasons to offer IBPB without IBRS.
     */
    if ( host_cpu_policy.feat.ibrsb )
        __set_bit(X86_FEATURE_IBPB, fs);
}

static void __init calculate_pv_max_policy(void)
{
    struct cpu_policy *p = &pv_max_cpu_policy;
    uint32_t fs[FSCAPINTS];
    unsigned int i;

    *p = host_cpu_policy;
    x86_cpu_policy_to_featureset(p, fs);

    for ( i = 0; i < ARRAY_SIZE(fs); ++i )
        fs[i] &= pv_max_featuremask[i];

    /*
     * If Xen isn't virtualising MSR_SPEC_CTRL for PV guests (functional
     * availability, or admin choice), hide the feature.
     */
    if ( !boot_cpu_has(X86_FEATURE_SC_MSR_PV) )
    {
        __clear_bit(X86_FEATURE_IBRSB, fs);
        __clear_bit(X86_FEATURE_IBRS, fs);
    }

    guest_common_max_feature_adjustments(fs);
    guest_common_feature_adjustments(fs);

    sanitise_featureset(fs);
    x86_cpu_featureset_to_policy(fs, p);
    recalculate_xstate(p);

    p->extd.raw[0xa] = EMPTY_LEAF; /* No SVM for PV guests. */
}

static void __init calculate_pv_def_policy(void)
{
    struct cpu_policy *p = &pv_def_cpu_policy;
    uint32_t fs[FSCAPINTS];
    unsigned int i;

    *p = pv_max_cpu_policy;
    x86_cpu_policy_to_featureset(p, fs);

    for ( i = 0; i < ARRAY_SIZE(fs); ++i )
        fs[i] &= pv_def_featuremask[i];

    guest_common_feature_adjustments(fs);
    guest_common_default_feature_adjustments(fs);

    sanitise_featureset(fs);

    /*
     * If the host suffers from RSBA of any form, and the guest can see
     * MSR_ARCH_CAPS, reflect the appropriate RSBA/RRSBA property to the guest
     * depending on the visibility of eIBRS.
     */
    if ( test_bit(X86_FEATURE_ARCH_CAPS, fs) &&
         (cpu_has_rsba || cpu_has_rrsba) )
    {
        bool eibrs = test_bit(X86_FEATURE_EIBRS, fs);

        __set_bit(eibrs ? X86_FEATURE_RRSBA
                        : X86_FEATURE_RSBA, fs);
    }

    x86_cpu_featureset_to_policy(fs, p);
    recalculate_xstate(p);
}

static void __init calculate_hvm_max_policy(void)
{
    struct cpu_policy *p = &hvm_max_cpu_policy;
    uint32_t fs[FSCAPINTS];
    unsigned int i;
    const uint32_t *mask;

    *p = host_cpu_policy;
    x86_cpu_policy_to_featureset(p, fs);

    mask = hvm_hap_supported() ?
        hvm_hap_max_featuremask : hvm_shadow_max_featuremask;

    for ( i = 0; i < ARRAY_SIZE(fs); ++i )
        fs[i] &= mask[i];

    /*
     * Xen can provide an (x2)APIC emulation to HVM guests even if the host's
     * (x2)APIC isn't enabled.
     */
    __set_bit(X86_FEATURE_APIC, fs);
    __set_bit(X86_FEATURE_X2APIC, fs);

    /*
     * We don't support EFER.LMSLE at all.  AMD has dropped the feature from
     * hardware and allocated a CPUID bit to indicate its absence.
     */
    __set_bit(X86_FEATURE_NO_LMSL, fs);

    /*
     * On AMD, PV guests are entirely unable to use SYSENTER as Xen runs in
     * long mode (and init_amd() has cleared it out of host capabilities), but
     * HVM guests are able if running in protected mode.
     */
    if ( (boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON)) &&
         raw_cpu_policy.basic.sep )
        __set_bit(X86_FEATURE_SEP, fs);

    /*
     * VIRT_SSBD is exposed in the default policy as a result of
     * amd_virt_spec_ctrl being set, it also needs exposing in the max policy.
     */
    if ( amd_virt_spec_ctrl )
        __set_bit(X86_FEATURE_VIRT_SSBD, fs);

    /*
     * If Xen isn't virtualising MSR_SPEC_CTRL for HVM guests (functional
     * availability, or admin choice), hide the feature.
     */
    if ( !boot_cpu_has(X86_FEATURE_SC_MSR_HVM) )
    {
        __clear_bit(X86_FEATURE_IBRSB, fs);
        __clear_bit(X86_FEATURE_IBRS, fs);
    }
    else if ( boot_cpu_has(X86_FEATURE_AMD_SSBD) )
        /*
         * If SPEC_CTRL.SSBD is available VIRT_SPEC_CTRL.SSBD can be exposed
         * and implemented using the former. Expose in the max policy only as
         * the preference is for guests to use SPEC_CTRL.SSBD if available.
         */
        __set_bit(X86_FEATURE_VIRT_SSBD, fs);

    /*
     * With VT-x, some features are only supported by Xen if dedicated
     * hardware support is also available.
     */
    if ( cpu_has_vmx )
    {
        if ( !cpu_has_vmx_rdtscp )
            __clear_bit(X86_FEATURE_RDTSCP, fs);

        if ( !cpu_has_vmx_invpcid )
            __clear_bit(X86_FEATURE_INVPCID, fs);

        if ( !cpu_has_vmx_mpx )
            __clear_bit(X86_FEATURE_MPX, fs);

        if ( !cpu_has_vmx_xsaves )
            __clear_bit(X86_FEATURE_XSAVES, fs);
    }

    /*
     * Xen doesn't use PKS, so the guest support for it has opted to not use
     * the VMCS load/save controls for efficiency reasons.  This depends on
     * the exact vmentry/exit behaviour, so don't expose PKS in other
     * situations until someone has cross-checked the behaviour for safety.
     */
    if ( !cpu_has_vmx )
        __clear_bit(X86_FEATURE_PKS, fs);

    guest_common_max_feature_adjustments(fs);
    guest_common_feature_adjustments(fs);

    sanitise_featureset(fs);
    x86_cpu_featureset_to_policy(fs, p);
    recalculate_xstate(p);

    /* It's always possible to emulate CPUID faulting for HVM guests */
    p->platform_info.cpuid_faulting = true;
}

static void __init calculate_hvm_def_policy(void)
{
    struct cpu_policy *p = &hvm_def_cpu_policy;
    uint32_t fs[FSCAPINTS];
    unsigned int i;
    const uint32_t *mask;

    *p = hvm_max_cpu_policy;
    x86_cpu_policy_to_featureset(p, fs);

    mask = hvm_hap_supported() ?
        hvm_hap_def_featuremask : hvm_shadow_def_featuremask;

    for ( i = 0; i < ARRAY_SIZE(fs); ++i )
        fs[i] &= mask[i];

    guest_common_feature_adjustments(fs);
    guest_common_default_feature_adjustments(fs);

    /*
     * Only expose VIRT_SSBD if AMD_SSBD is not available, and thus
     * amd_virt_spec_ctrl is set.
     */
    if ( amd_virt_spec_ctrl )
        __set_bit(X86_FEATURE_VIRT_SSBD, fs);

    sanitise_featureset(fs);

    /*
     * If the host suffers from RSBA of any form, and the guest can see
     * MSR_ARCH_CAPS, reflect the appropriate RSBA/RRSBA property to the guest
     * depending on the visibility of eIBRS.
     */
    if ( test_bit(X86_FEATURE_ARCH_CAPS, fs) &&
         (cpu_has_rsba || cpu_has_rrsba) )
    {
        bool eibrs = test_bit(X86_FEATURE_EIBRS, fs);

        __set_bit(eibrs ? X86_FEATURE_RRSBA
                        : X86_FEATURE_RSBA, fs);
    }

    x86_cpu_featureset_to_policy(fs, p);
    recalculate_xstate(p);
}

void __init init_guest_cpu_policies(void)
{
    calculate_raw_cpu_policy();
    calculate_host_policy();

    if ( IS_ENABLED(CONFIG_PV) )
    {
        calculate_pv_max_policy();
        calculate_pv_def_policy();
    }

    if ( hvm_enabled )
    {
        calculate_hvm_max_policy();
        calculate_hvm_def_policy();
    }
}

int init_domain_cpu_policy(struct domain *d)
{
    struct cpu_policy *p = is_pv_domain(d)
        ? (IS_ENABLED(CONFIG_PV)  ?  &pv_def_cpu_policy : NULL)
        : (IS_ENABLED(CONFIG_HVM) ? &hvm_def_cpu_policy : NULL);

    if ( !p )
    {
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

    p = xmemdup(p);
    if ( !p )
        return -ENOMEM;

    d->arch.cpu_policy = p;

    recalculate_cpuid_policy(d);

    return 0;
}

void recalculate_cpuid_policy(struct domain *d)
{
    struct cpu_policy *p = d->arch.cpuid;
    const struct cpu_policy *max = is_pv_domain(d)
        ? (IS_ENABLED(CONFIG_PV)  ?  &pv_max_cpu_policy : NULL)
        : (IS_ENABLED(CONFIG_HVM) ? &hvm_max_cpu_policy : NULL);
    uint32_t fs[FSCAPINTS], max_fs[FSCAPINTS];
    unsigned int i;

    if ( !max )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    p->x86_vendor = x86_cpuid_lookup_vendor(
        p->basic.vendor_ebx, p->basic.vendor_ecx, p->basic.vendor_edx);

    p->basic.max_leaf   = min(p->basic.max_leaf,   max->basic.max_leaf);
    p->feat.max_subleaf = min(p->feat.max_subleaf, max->feat.max_subleaf);
    p->extd.max_leaf    = 0x80000000U | min(p->extd.max_leaf & 0xffff,
                                            ((p->x86_vendor & (X86_VENDOR_AMD |
                                                               X86_VENDOR_HYGON))
                                             ? CPUID_GUEST_NR_EXTD_AMD
                                             : CPUID_GUEST_NR_EXTD_INTEL) - 1);

    x86_cpu_policy_to_featureset(p, fs);
    x86_cpu_policy_to_featureset(max, max_fs);

    if ( is_hvm_domain(d) )
    {
        /*
         * HVM domains using Shadow paging have further restrictions on their
         * available paging features.
         */
        if ( !hap_enabled(d) )
        {
            for ( i = 0; i < ARRAY_SIZE(max_fs); i++ )
                max_fs[i] &= hvm_shadow_max_featuremask[i];
        }

        /* Hide nested-virt if it hasn't been explicitly configured. */
        if ( !nestedhvm_enabled(d) )
        {
            __clear_bit(X86_FEATURE_VMX, max_fs);
            __clear_bit(X86_FEATURE_SVM, max_fs);
        }
    }

    /*
     * Allow the toolstack to set HTT, X2APIC and CMP_LEGACY.  These bits
     * affect how to interpret topology information in other cpuid leaves.
     */
    __set_bit(X86_FEATURE_HTT, max_fs);
    __set_bit(X86_FEATURE_X2APIC, max_fs);
    __set_bit(X86_FEATURE_CMP_LEGACY, max_fs);

    /*
     * 32bit PV domains can't use any Long Mode features, and cannot use
     * SYSCALL on non-AMD hardware.
     */
    if ( is_pv_32bit_domain(d) )
    {
        __clear_bit(X86_FEATURE_LM, max_fs);
        if ( !(boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
            __clear_bit(X86_FEATURE_SYSCALL, max_fs);
    }

    /* Clamp the toolstacks choices to reality. */
    for ( i = 0; i < ARRAY_SIZE(fs); i++ )
        fs[i] &= max_fs[i];

    if ( p->basic.max_leaf < XSTATE_CPUID )
        __clear_bit(X86_FEATURE_XSAVE, fs);

    sanitise_featureset(fs);

    /* Fold host's FDP_EXCP_ONLY and NO_FPU_SEL into guest's view. */
    fs[FEATURESET_7b0] &= ~(cpufeat_mask(X86_FEATURE_FDP_EXCP_ONLY) |
                            cpufeat_mask(X86_FEATURE_NO_FPU_SEL));
    fs[FEATURESET_7b0] |= (host_cpu_policy.feat._7b0 &
                           (cpufeat_mask(X86_FEATURE_FDP_EXCP_ONLY) |
                            cpufeat_mask(X86_FEATURE_NO_FPU_SEL)));

    x86_cpu_featureset_to_policy(fs, p);

    /* Pass host cacheline size through to guests. */
    p->basic.clflush_size = max->basic.clflush_size;

    p->extd.maxphysaddr = min(p->extd.maxphysaddr, max->extd.maxphysaddr);
    p->extd.maxphysaddr = min_t(uint8_t, p->extd.maxphysaddr,
                                domain_max_paddr_bits(d));
    p->extd.maxphysaddr = max_t(uint8_t, p->extd.maxphysaddr,
                                (p->basic.pae || p->basic.pse36) ? 36 : 32);

    p->extd.maxlinaddr = p->extd.lm ? 48 : 32;

    recalculate_xstate(p);
    recalculate_misc(p);

    for ( i = 0; i < ARRAY_SIZE(p->cache.raw); ++i )
    {
        if ( p->cache.subleaf[i].type >= 1 &&
             p->cache.subleaf[i].type <= 3 )
        {
            /* Subleaf has a valid cache type. Zero reserved fields. */
            p->cache.raw[i].a &= 0xffffc3ffu;
            p->cache.raw[i].d &= 0x00000007u;
        }
        else
        {
            /* Subleaf is not valid.  Zero the rest of the union. */
            zero_leaves(p->cache.raw, i, ARRAY_SIZE(p->cache.raw) - 1);
            break;
        }
    }

    if ( vpmu_mode == XENPMU_MODE_OFF ||
         ((vpmu_mode & XENPMU_MODE_ALL) && !is_hardware_domain(d)) )
        p->basic.raw[0xa] = EMPTY_LEAF;

    if ( !p->extd.svm )
        p->extd.raw[0xa] = EMPTY_LEAF;

    if ( !p->extd.page1gb )
        p->extd.raw[0x19] = EMPTY_LEAF;
}

/*
 * Adjust the CPU policy for dom0.  Really, this is "the domain Xen builds
 * automatically on boot", and might not have the domid 0 (e.g. pvshim).
 */
void __init init_dom0_cpuid_policy(struct domain *d)
{
    struct cpu_policy *p = d->arch.cpuid;

    /* Dom0 doesn't migrate relative to Xen.  Give it ITSC if available. */
    if ( cpu_has_itsc )
        p->extd.itsc = true;

    /* Apply dom0-cpuid= command line settings, if provided. */
    if ( dom0_cpuid_cmdline )
    {
        uint32_t fs[FSCAPINTS];
        unsigned int i;

        x86_cpu_policy_to_featureset(p, fs);

        for ( i = 0; i < ARRAY_SIZE(fs); ++i )
        {
            fs[i] |=  dom0_enable_feat [i];
            fs[i] &= ~dom0_disable_feat[i];
        }

        x86_cpu_featureset_to_policy(fs, p);
    }

    /*
     * PV Control domains used to require unfiltered CPUID.  This was fixed in
     * Xen 4.13, but there is an cmdline knob to restore the prior behaviour.
     *
     * If the domain is getting unfiltered CPUID, don't let the guest kernel
     * play with CPUID faulting either, as Xen's CPUID path won't cope.
     */
    if ( !opt_dom0_cpuid_faulting && is_control_domain(d) && is_pv_domain(d) )
        p->platform_info.cpuid_faulting = false;

    recalculate_cpuid_policy(d);
}

static void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(ARRAY_SIZE(known_features) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(pv_max_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_shadow_max_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_hap_max_featuremask) != FSCAPINTS);
    BUILD_BUG_ON(ARRAY_SIZE(deep_features) != FSCAPINTS);

    /* Find some more clever allocation scheme if this trips. */
    BUILD_BUG_ON(sizeof(struct cpu_policy) > PAGE_SIZE);

    BUILD_BUG_ON(sizeof(raw_cpu_policy.basic) !=
                 sizeof(raw_cpu_policy.basic.raw));
    BUILD_BUG_ON(sizeof(raw_cpu_policy.feat) !=
                 sizeof(raw_cpu_policy.feat.raw));
    BUILD_BUG_ON(sizeof(raw_cpu_policy.xstate) !=
                 sizeof(raw_cpu_policy.xstate.raw));
    BUILD_BUG_ON(sizeof(raw_cpu_policy.extd) !=
                 sizeof(raw_cpu_policy.extd.raw));
}
