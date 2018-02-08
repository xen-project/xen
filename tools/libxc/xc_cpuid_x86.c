/******************************************************************************
 * xc_cpuid_x86.c 
 *
 * Compute cpuid of a domain.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include "xc_private.h"
#include "xc_bitops.h"
#include <xen/hvm/params.h>
#include <xen-tools/libs.h>

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};
#include "_xc_cpuid_autogen.h"

#define bitmaskof(idx)      (1u << ((idx) & 31))
#define featureword_of(idx) ((idx) >> 5)
#define clear_feature(idx, dst) ((dst) &= ~bitmaskof(idx))
#define set_feature(idx, dst)   ((dst) |=  bitmaskof(idx))

#define DEF_MAX_BASE 0x0000000du
#define DEF_MAX_INTELEXT  0x80000008u
#define DEF_MAX_AMDEXT    0x8000001cu

int xc_get_cpu_levelling_caps(xc_interface *xch, uint32_t *caps)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_levelling_caps;
    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
        *caps = sysctl.u.cpu_levelling_caps.caps;

    return ret;
}

int xc_get_cpu_featureset(xc_interface *xch, uint32_t index,
                          uint32_t *nr_features, uint32_t *featureset)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(featureset,
                             *nr_features * sizeof(*featureset),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, featureset) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_get_cpu_featureset;
    sysctl.u.cpu_featureset.index = index;
    sysctl.u.cpu_featureset.nr_features = *nr_features;
    set_xen_guest_handle(sysctl.u.cpu_featureset.features, featureset);

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, featureset);

    if ( !ret )
        *nr_features = sysctl.u.cpu_featureset.nr_features;

    return ret;
}

uint32_t xc_get_cpu_featureset_size(void)
{
    return FEATURESET_NR_ENTRIES;
}

const uint32_t *xc_get_static_cpu_featuremask(
    enum xc_static_cpu_featuremask mask)
{
    const static uint32_t known[FEATURESET_NR_ENTRIES] = INIT_KNOWN_FEATURES,
        special[FEATURESET_NR_ENTRIES] = INIT_SPECIAL_FEATURES,
        pv[FEATURESET_NR_ENTRIES] = INIT_PV_FEATURES,
        hvm_shadow[FEATURESET_NR_ENTRIES] = INIT_HVM_SHADOW_FEATURES,
        hvm_hap[FEATURESET_NR_ENTRIES] = INIT_HVM_HAP_FEATURES,
        deep_features[FEATURESET_NR_ENTRIES] = INIT_DEEP_FEATURES;

    BUILD_BUG_ON(ARRAY_SIZE(known) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(special) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(pv) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_shadow) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(hvm_hap) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(deep_features) != FEATURESET_NR_ENTRIES);

    switch ( mask )
    {
    case XC_FEATUREMASK_KNOWN:
        return known;

    case XC_FEATUREMASK_SPECIAL:
        return special;

    case XC_FEATUREMASK_PV:
        return pv;

    case XC_FEATUREMASK_HVM_SHADOW:
        return hvm_shadow;

    case XC_FEATUREMASK_HVM_HAP:
        return hvm_hap;

    case XC_FEATUREMASK_DEEP_FEATURES:
        return deep_features;

    default:
        return NULL;
    }
}

const uint32_t *xc_get_feature_deep_deps(uint32_t feature)
{
    static const struct {
        uint32_t feature;
        uint32_t fs[FEATURESET_NR_ENTRIES];
    } deep_deps[] = INIT_DEEP_DEPS;

    unsigned int start = 0, end = ARRAY_SIZE(deep_deps);

    BUILD_BUG_ON(ARRAY_SIZE(deep_deps) != NR_DEEP_DEPS);

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

struct cpuid_domain_info
{
    enum
    {
        VENDOR_UNKNOWN,
        VENDOR_INTEL,
        VENDOR_AMD,
    } vendor;

    bool hvm;
    uint64_t xfeature_mask;

    uint32_t *featureset;
    unsigned int nr_features;

    /* PV-only information. */
    bool pv64;

    /* HVM-only information. */
    bool pae;
    bool nestedhvm;
};

static void cpuid(const unsigned int *input, unsigned int *regs)
{
    unsigned int count = (input[1] == XEN_CPUID_INPUT_UNUSED) ? 0 : input[1];
#ifdef __i386__
    /* Use the stack to avoid reg constraint failures with some gcc flags */
    asm (
        "push %%ebx; push %%edx\n\t"
        "cpuid\n\t"
        "mov %%ebx,4(%4)\n\t"
        "mov %%edx,12(%4)\n\t"
        "pop %%edx; pop %%ebx\n\t"
        : "=a" (regs[0]), "=c" (regs[2])
        : "0" (input[0]), "1" (count), "S" (regs)
        : "memory" );
#else
    asm (
        "cpuid"
        : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
        : "0" (input[0]), "2" (count) );
#endif
}

static int get_cpuid_domain_info(xc_interface *xch, uint32_t domid,
                                 struct cpuid_domain_info *info,
                                 uint32_t *featureset,
                                 unsigned int nr_features)
{
    struct xen_domctl domctl = {};
    xc_dominfo_t di;
    unsigned int in[2] = { 0, ~0U }, regs[4];
    unsigned int i, host_nr_features = xc_get_cpu_featureset_size();
    int rc;

    cpuid(in, regs);
    if ( regs[1] == 0x756e6547U &&      /* "GenuineIntel" */
         regs[2] == 0x6c65746eU &&
         regs[3] == 0x49656e69U )
        info->vendor = VENDOR_INTEL;
    else if ( regs[1] == 0x68747541U && /* "AuthenticAMD" */
              regs[2] == 0x444d4163U &&
              regs[3] == 0x69746e65U )
        info->vendor = VENDOR_AMD;
    else
        info->vendor = VENDOR_UNKNOWN;

    if ( xc_domain_getinfo(xch, domid, 1, &di) != 1 ||
         di.domid != domid )
        return -ESRCH;

    info->hvm = di.hvm;

    info->featureset = calloc(host_nr_features, sizeof(*info->featureset));
    if ( !info->featureset )
        return -ENOMEM;

    info->nr_features = host_nr_features;

    if ( featureset )
    {
        memcpy(info->featureset, featureset,
               min(host_nr_features, nr_features) * sizeof(*info->featureset));

        /* Check for truncated set bits. */
        for ( i = nr_features; i < host_nr_features; ++i )
            if ( featureset[i] != 0 )
                return -EOPNOTSUPP;
    }

    /* Get xstate information. */
    domctl.cmd = XEN_DOMCTL_getvcpuextstate;
    domctl.domain = domid;
    rc = do_domctl(xch, &domctl);
    if ( rc )
        return rc;

    info->xfeature_mask = domctl.u.vcpuextstate.xfeature_mask;

    if ( di.hvm )
    {
        uint64_t val;

        rc = xc_hvm_param_get(xch, domid, HVM_PARAM_PAE_ENABLED, &val);
        if ( rc )
            return rc;

        info->pae = !!val;

        rc = xc_hvm_param_get(xch, domid, HVM_PARAM_NESTEDHVM, &val);
        if ( rc )
            return rc;

        info->nestedhvm = !!val;

        if ( !featureset )
        {
            rc = xc_get_cpu_featureset(xch, XEN_SYSCTL_cpu_featureset_hvm,
                                       &host_nr_features, info->featureset);
            if ( rc )
                return rc;
        }
    }
    else
    {
        unsigned int width;

        rc = xc_domain_get_guest_width(xch, domid, &width);
        if ( rc )
            return rc;

        info->pv64 = (width == 8);

        if ( !featureset )
        {
            rc = xc_get_cpu_featureset(xch, XEN_SYSCTL_cpu_featureset_pv,
                                       &host_nr_features, info->featureset);
            if ( rc )
                return rc;
        }
    }

    return 0;
}

static void free_cpuid_domain_info(struct cpuid_domain_info *info)
{
    free(info->featureset);
}

static void amd_xc_cpuid_policy(xc_interface *xch,
                                const struct cpuid_domain_info *info,
                                const unsigned int *input, unsigned int *regs)
{
    switch ( input[0] )
    {
    case 0x00000002:
    case 0x00000004:
        regs[0] = regs[1] = regs[2] = 0;
        break;

    case 0x80000000:
        if ( regs[0] > DEF_MAX_AMDEXT )
            regs[0] = DEF_MAX_AMDEXT;
        break;

    case 0x80000008:
        /*
         * ECX[15:12] is ApicIdCoreSize: ECX[7:0] is NumberOfCores (minus one).
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[2] = ((regs[2] + (1u << 12)) & 0xf000u) |
                  ((regs[2] & 0xffu) << 1) | 1u;
        break;

    case 0x8000000a: {
        if ( !info->nestedhvm )
        {
            regs[0] = regs[1] = regs[2] = regs[3] = 0;
            break;
        }

#define SVM_FEATURE_NPT            0x00000001 /* Nested page table support */
#define SVM_FEATURE_LBRV           0x00000002 /* LBR virtualization support */
#define SVM_FEATURE_SVML           0x00000004 /* SVM locking MSR support */
#define SVM_FEATURE_NRIPS          0x00000008 /* Next RIP save on VMEXIT */
#define SVM_FEATURE_TSCRATEMSR     0x00000010 /* TSC ratio MSR support */
#define SVM_FEATURE_VMCBCLEAN      0x00000020 /* VMCB clean bits support */
#define SVM_FEATURE_FLUSHBYASID    0x00000040 /* TLB flush by ASID support */
#define SVM_FEATURE_DECODEASSISTS  0x00000080 /* Decode assists support */
#define SVM_FEATURE_PAUSEFILTER    0x00000400 /* Pause intercept filter */

        /* Pass 1: Only passthrough SVM features which are
         * available in hw and which are implemented
         */
        regs[3] &= (SVM_FEATURE_NPT | SVM_FEATURE_LBRV | \
            SVM_FEATURE_NRIPS | SVM_FEATURE_PAUSEFILTER | \
            SVM_FEATURE_DECODEASSISTS);

        /* Pass 2: Always enable SVM features which are emulated */
        regs[3] |= SVM_FEATURE_VMCBCLEAN | SVM_FEATURE_TSCRATEMSR;
        break;
    }

    }
}

static void intel_xc_cpuid_policy(xc_interface *xch,
                                  const struct cpuid_domain_info *info,
                                  const unsigned int *input, unsigned int *regs)
{
    switch ( input[0] )
    {
    case 0x00000004:
        /*
         * EAX[31:26] is Maximum Cores Per Package (minus one).
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[0] = (((regs[0] & 0x7c000000u) << 1) | 0x04000000u |
                   (regs[0] & 0x3ffu));
        regs[3] &= 0x3ffu;
        break;

    case 0x80000000:
        if ( regs[0] > DEF_MAX_INTELEXT )
            regs[0] = DEF_MAX_INTELEXT;
        break;

    case 0x80000005:
        regs[0] = regs[1] = regs[2] = 0;
        break;

    case 0x80000008:
        /* Mask AMD Number of Cores information. */
        regs[2] = 0;
        break;
    }
}

static void xc_cpuid_hvm_policy(xc_interface *xch,
                                const struct cpuid_domain_info *info,
                                const unsigned int *input, unsigned int *regs)
{
    switch ( input[0] )
    {
    case 0x00000000:
        if ( regs[0] > DEF_MAX_BASE )
            regs[0] = DEF_MAX_BASE;
        break;

    case 0x00000001:
        /*
         * EBX[23:16] is Maximum Logical Processors Per Package.
         * Update to reflect vLAPIC_ID = vCPU_ID * 2.
         */
        regs[1] = (regs[1] & 0x0000ffffu) | ((regs[1] & 0x007f0000u) << 1);

        regs[2] = info->featureset[featureword_of(X86_FEATURE_SSE3)];
        regs[3] = (info->featureset[featureword_of(X86_FEATURE_FPU)] |
                   bitmaskof(X86_FEATURE_HTT));
        break;

    case 0x00000007: /* Intel-defined CPU features */
        if ( input[1] == 0 )
        {
            regs[1] = info->featureset[featureword_of(X86_FEATURE_FSGSBASE)];
            regs[2] = info->featureset[featureword_of(X86_FEATURE_PREFETCHWT1)];
            regs[3] = info->featureset[featureword_of(X86_FEATURE_AVX512_4VNNIW)];
        }
        else
        {
            regs[1] = 0;
            regs[2] = 0;
            regs[3] = 0;
        }
        regs[0] = 0;
        break;

    case 0x0000000d: /* Xen automatically calculates almost everything. */
        if ( input[1] == 1 )
            regs[0] = info->featureset[featureword_of(X86_FEATURE_XSAVEOPT)];
        else
            regs[0] = 0;
        regs[1] = regs[2] = regs[3] = 0;
        break;

    case 0x80000000:
        /* Passthrough to cpu vendor specific functions */
        break;

    case 0x80000001:
        regs[2] = (info->featureset[featureword_of(X86_FEATURE_LAHF_LM)] &
                   ~bitmaskof(X86_FEATURE_CMP_LEGACY));
        regs[3] = info->featureset[featureword_of(X86_FEATURE_SYSCALL)];
        break;

    case 0x80000007:
        /*
         * Keep only TSCInvariant. This may be cleared by the hypervisor
         * depending on guest TSC and migration settings.
         */
        regs[0] = regs[1] = regs[2] = 0;
        regs[3] &= 1u<<8;
        break;

    case 0x80000008:
        regs[0] &= 0x0000ffffu;
        regs[1] = info->featureset[featureword_of(X86_FEATURE_CLZERO)];
        /* regs[2] handled in the per-vendor logic. */
        regs[3] = 0;
        break;

    case 0x00000002: /* Intel cache info (dumped by AMD policy) */
    case 0x00000004: /* Intel cache info (dumped by AMD policy) */
    case 0x0000000a: /* Architectural Performance Monitor Features */
    case 0x80000002: /* Processor name string */
    case 0x80000003: /* ... continued         */
    case 0x80000004: /* ... continued         */
    case 0x80000005: /* AMD L1 cache/TLB info (dumped by Intel policy) */
    case 0x80000006: /* AMD L2/3 cache/TLB info ; Intel L2 cache features */
    case 0x8000000a: /* AMD SVM feature bits */
    case 0x80000019: /* AMD 1G TLB */
    case 0x8000001a: /* AMD perf hints */
    case 0x8000001c: /* AMD lightweight profiling */
        break;

    default:
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        break;
    }

    if ( info->vendor == VENDOR_AMD )
        amd_xc_cpuid_policy(xch, info, input, regs);
    else
        intel_xc_cpuid_policy(xch, info, input, regs);
}

static void xc_cpuid_pv_policy(xc_interface *xch,
                               const struct cpuid_domain_info *info,
                               const unsigned int *input, unsigned int *regs)
{
    switch ( input[0] )
    {
    case 0x00000000:
        if ( regs[0] > DEF_MAX_BASE )
            regs[0] = DEF_MAX_BASE;
        break;

    case 0x00000001:
    {
        /* Host topology exposed to PV guest.  Provide host value. */
        bool host_htt = regs[3] & bitmaskof(X86_FEATURE_HTT);

        /*
         * Don't pick host's Initial APIC ID which can change from run
         * to run.
         */
        regs[1] &= 0x00ffffffu;

        regs[2] = info->featureset[featureword_of(X86_FEATURE_SSE3)];
        regs[3] = (info->featureset[featureword_of(X86_FEATURE_FPU)] &
                   ~bitmaskof(X86_FEATURE_HTT));

        if ( host_htt )
            regs[3] |= bitmaskof(X86_FEATURE_HTT);
        break;
    }

    case 0x00000007:
        if ( input[1] == 0 )
        {
            regs[1] = info->featureset[featureword_of(X86_FEATURE_FSGSBASE)];
            regs[2] = info->featureset[featureword_of(X86_FEATURE_PREFETCHWT1)];
            regs[3] = info->featureset[featureword_of(X86_FEATURE_AVX512_4VNNIW)];
        }
        else
        {
            regs[1] = 0;
            regs[2] = 0;
            regs[3] = 0;
        }
        regs[0] = 0;
        break;

    case 0x0000000d: /* Xen automatically calculates almost everything. */
        if ( input[1] == 1 )
            regs[0] = info->featureset[featureword_of(X86_FEATURE_XSAVEOPT)];
        else
            regs[0] = 0;
        regs[1] = regs[2] = regs[3] = 0;
        break;

    case 0x80000000:
    {
        unsigned int max = info->vendor == VENDOR_AMD
            ? DEF_MAX_AMDEXT : DEF_MAX_INTELEXT;

        if ( regs[0] > max )
            regs[0] = max;
        break;
    }

    case 0x80000001:
    {
        /* Host topology exposed to PV guest.  Provide host CMP_LEGACY value. */
        bool host_cmp_legacy = regs[2] & bitmaskof(X86_FEATURE_CMP_LEGACY);

        regs[2] = (info->featureset[featureword_of(X86_FEATURE_LAHF_LM)] &
                   ~bitmaskof(X86_FEATURE_CMP_LEGACY));
        regs[3] = info->featureset[featureword_of(X86_FEATURE_SYSCALL)];

        if ( host_cmp_legacy )
            regs[2] |= bitmaskof(X86_FEATURE_CMP_LEGACY);

        break;
    }

    case 0x00000005: /* MONITOR/MWAIT */
    case 0x0000000b: /* Extended Topology Enumeration */
    case 0x8000000a: /* SVM revision and features */
    case 0x8000001b: /* Instruction Based Sampling */
    case 0x8000001c: /* Light Weight Profiling */
    case 0x8000001e: /* Extended topology reporting */
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        break;
    }
}

static int xc_cpuid_policy(xc_interface *xch,
                           const struct cpuid_domain_info *info,
                           const unsigned int *input, unsigned int *regs)
{
    /*
     * For hypervisor leaves (0x4000XXXX) only 0x4000xx00.EAX[7:0] bits (max
     * number of leaves) can be set by user. Hypervisor will enforce this so
     * all other bits are don't-care and we can set them to zero.
     */
    if ( (input[0] & 0xffff0000) == 0x40000000 )
    {
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        return 0;
    }

    if ( info->hvm )
        xc_cpuid_hvm_policy(xch, info, input, regs);
    else
        xc_cpuid_pv_policy(xch, info, input, regs);

    return 0;
}

static int xc_cpuid_do_domctl(
    xc_interface *xch, uint32_t domid,
    const unsigned int *input, const unsigned int *regs)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof (domctl));
    domctl.domain = domid;
    domctl.cmd = XEN_DOMCTL_set_cpuid;
    domctl.u.cpuid.input[0] = input[0];
    domctl.u.cpuid.input[1] = input[1];
    domctl.u.cpuid.eax = regs[0];
    domctl.u.cpuid.ebx = regs[1];
    domctl.u.cpuid.ecx = regs[2];
    domctl.u.cpuid.edx = regs[3];

    return do_domctl(xch, &domctl);
}

static char *alloc_str(void)
{
    char *s = malloc(33);
    if ( s == NULL )
        return s;
    memset(s, 0, 33);
    return s;
}

void xc_cpuid_to_str(const unsigned int *regs, char **strs)
{
    int i, j;

    for ( i = 0; i < 4; i++ )
    {
        strs[i] = alloc_str();
        if ( strs[i] == NULL )
            continue;
        for ( j = 0; j < 32; j++ )
            strs[i][j] = !!((regs[i] & (1U << (31 - j)))) ? '1' : '0';
    }
}

static void sanitise_featureset(struct cpuid_domain_info *info)
{
    const uint32_t fs_size = xc_get_cpu_featureset_size();
    uint32_t disabled_features[fs_size];
    static const uint32_t deep_features[] = INIT_DEEP_FEATURES;
    unsigned int i, b;

    if ( info->hvm )
    {
        /* HVM Guest */

        if ( !info->pae )
            clear_bit(X86_FEATURE_PAE, info->featureset);

        if ( !info->nestedhvm )
        {
            clear_bit(X86_FEATURE_SVM, info->featureset);
            clear_bit(X86_FEATURE_VMX, info->featureset);
        }
    }
    else
    {
        /* PV or PVH Guest */

        if ( !info->pv64 )
        {
            clear_bit(X86_FEATURE_LM, info->featureset);
            if ( info->vendor != VENDOR_AMD )
                clear_bit(X86_FEATURE_SYSCALL, info->featureset);
        }

        clear_bit(X86_FEATURE_PSE, info->featureset);
        clear_bit(X86_FEATURE_PSE36, info->featureset);
        clear_bit(X86_FEATURE_PGE, info->featureset);
        clear_bit(X86_FEATURE_PAGE1GB, info->featureset);
    }

    if ( info->xfeature_mask == 0 )
        clear_bit(X86_FEATURE_XSAVE, info->featureset);

    /* Disable deep dependencies of disabled features. */
    for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
        disabled_features[i] = ~info->featureset[i] & deep_features[i];

    for ( b = 0; b < sizeof(disabled_features) * CHAR_BIT; ++b )
    {
        const uint32_t *dfs;

        if ( !test_bit(b, disabled_features) ||
             !(dfs = xc_get_feature_deep_deps(b)) )
             continue;

        for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
        {
            info->featureset[i] &= ~dfs[i];
            disabled_features[i] &= ~dfs[i];
        }
    }
}

int xc_cpuid_apply_policy(xc_interface *xch, uint32_t domid,
                          uint32_t *featureset,
                          unsigned int nr_features)
{
    struct cpuid_domain_info info = {};
    unsigned int input[2] = { 0, 0 }, regs[4];
    unsigned int base_max, ext_max;
    int rc;

    rc = get_cpuid_domain_info(xch, domid, &info, featureset, nr_features);
    if ( rc )
        goto out;

    cpuid(input, regs);
    base_max = (regs[0] <= DEF_MAX_BASE) ? regs[0] : DEF_MAX_BASE;
    input[0] = 0x80000000;
    cpuid(input, regs);

    if ( info.vendor == VENDOR_AMD )
        ext_max = (regs[0] <= DEF_MAX_AMDEXT) ? regs[0] : DEF_MAX_AMDEXT;
    else
        ext_max = (regs[0] <= DEF_MAX_INTELEXT) ? regs[0] : DEF_MAX_INTELEXT;

    sanitise_featureset(&info);

    input[0] = 0;
    input[1] = XEN_CPUID_INPUT_UNUSED;
    for ( ; ; )
    {
        cpuid(input, regs);
        xc_cpuid_policy(xch, &info, input, regs);

        if ( regs[0] || regs[1] || regs[2] || regs[3] )
        {
            rc = xc_cpuid_do_domctl(xch, domid, input, regs);
            if ( rc )
                goto out;
        }

        /* Intel cache descriptor leaves. */
        if ( input[0] == 4 )
        {
            input[1]++;
            /* More to do? Then loop keeping %%eax==0x00000004. */
            if ( (regs[0] & 0x1f) != 0 )
                continue;
        }

        input[0]++;
        if ( !(input[0] & 0x80000000u) && (input[0] > base_max ) )
            input[0] = 0x80000000u;

        input[1] = XEN_CPUID_INPUT_UNUSED;
        if ( (input[0] == 4) || (input[0] == 7) )
            input[1] = 0;
        else if ( input[0] == 0xd )
            input[1] = 1; /* Xen automatically calculates almost everything. */

        if ( (input[0] & 0x80000000u) && (input[0] > ext_max) )
            break;
    }

 out:
    free_cpuid_domain_info(&info);
    return rc;
}

/*
 * Configure a single input with the informatiom from config.
 *
 * Config is an array of strings:
 *   config[0] = eax
 *   config[1] = ebx
 *   config[2] = ecx
 *   config[3] = edx
 *
 * The format of the string is the following:
 *   '1' -> force to 1
 *   '0' -> force to 0
 *   'x' -> we don't care (use default)
 *   'k' -> pass through host value
 *   's' -> pass through the first time and then keep the same value
 *          across save/restore and migration.
 * 
 * For 's' and 'x' the configuration is overwritten with the value applied.
 */
int xc_cpuid_set(
    xc_interface *xch, uint32_t domid, const unsigned int *input,
    const char **config, char **config_transformed)
{
    int rc;
    unsigned int i, j, regs[4], polregs[4];
    struct cpuid_domain_info info = {};

    memset(config_transformed, 0, 4 * sizeof(*config_transformed));

    rc = get_cpuid_domain_info(xch, domid, &info, NULL, 0);
    if ( rc )
        goto out;

    cpuid(input, regs);

    memcpy(polregs, regs, sizeof(regs));
    xc_cpuid_policy(xch, &info, input, polregs);

    for ( i = 0; i < 4; i++ )
    {
        if ( config[i] == NULL )
        {
            regs[i] = polregs[i];
            continue;
        }
        
        config_transformed[i] = alloc_str();
        if ( config_transformed[i] == NULL )
        {
            rc = -ENOMEM;
            goto fail;
        }

        for ( j = 0; j < 32; j++ )
        {
            unsigned char val = !!((regs[i] & (1U << (31 - j))));
            unsigned char polval = !!((polregs[i] & (1U << (31 - j))));

            rc = -EINVAL;
            if ( !strchr("10xks", config[i][j]) )
                goto fail;

            if ( config[i][j] == '1' )
                val = 1;
            else if ( config[i][j] == '0' )
                val = 0;
            else if ( config[i][j] == 'x' )
                val = polval;

            if ( val )
                set_feature(31 - j, regs[i]);
            else
                clear_feature(31 - j, regs[i]);

            config_transformed[i][j] = config[i][j];
            if ( config[i][j] == 's' )
                config_transformed[i][j] = '0' + val;
        }
    }

    rc = xc_cpuid_do_domctl(xch, domid, input, regs);
    if ( rc == 0 )
        goto out;

 fail:
    for ( i = 0; i < 4; i++ )
    {
        free(config_transformed[i]);
        config_transformed[i] = NULL;
    }

 out:
    free_cpuid_domain_info(&info);
    return rc;
}
