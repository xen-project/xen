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

#include <xen/asm/x86-vendors.h>

#include <xen/lib/x86/cpu-policy.h>

#define bitmaskof(idx)      (1u << ((idx) & 31))
#define featureword_of(idx) ((idx) >> 5)

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
    static const uint32_t masks[][FEATURESET_NR_ENTRIES] = {
#define MASK(x) [XC_FEATUREMASK_ ## x] = INIT_ ## x ## _FEATURES

        MASK(KNOWN),
        MASK(SPECIAL),
        MASK(PV_MAX),
        MASK(PV_DEF),
        MASK(HVM_SHADOW_MAX),
        MASK(HVM_SHADOW_DEF),
        MASK(HVM_HAP_MAX),
        MASK(HVM_HAP_DEF),

#undef MASK
    };

    if ( (unsigned int)mask >= ARRAY_SIZE(masks) )
        return NULL;

    return masks[mask];
}

int xc_get_cpu_policy_size(xc_interface *xch, uint32_t *nr_leaves,
                           uint32_t *nr_msrs)
{
    struct xen_sysctl sysctl = {};
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_policy;

    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

int xc_get_system_cpu_policy(xc_interface *xch, uint32_t index,
                             uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                             uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    struct xen_sysctl sysctl = {};
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, leaves) ||
         xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_get_cpu_policy;
    sysctl.u.cpu_policy.index = index;
    sysctl.u.cpu_policy.nr_leaves = *nr_leaves;
    set_xen_guest_handle(sysctl.u.cpu_policy.cpuid_policy, leaves);
    sysctl.u.cpu_policy.nr_msrs = *nr_msrs;
    set_xen_guest_handle(sysctl.u.cpu_policy.msr_policy, msrs);

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

int xc_get_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                             uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                             uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, leaves) ||
         xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    domctl.cmd = XEN_DOMCTL_get_cpu_policy;
    domctl.domain = domid;
    domctl.u.cpu_policy.nr_leaves = *nr_leaves;
    set_xen_guest_handle(domctl.u.cpu_policy.cpuid_policy, leaves);
    domctl.u.cpu_policy.nr_msrs = *nr_msrs;
    set_xen_guest_handle(domctl.u.cpu_policy.msr_policy, msrs);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = domctl.u.cpu_policy.nr_leaves;
        *nr_msrs = domctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

int xc_set_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                             uint32_t nr_leaves, xen_cpuid_leaf_t *leaves,
                             uint32_t nr_msrs, xen_msr_entry_t *msrs,
                             uint32_t *err_leaf_p, uint32_t *err_subleaf_p,
                             uint32_t *err_msr_p)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int ret;

    if ( err_leaf_p )
        *err_leaf_p = -1;
    if ( err_subleaf_p )
        *err_subleaf_p = -1;
    if ( err_msr_p )
        *err_msr_p = -1;

    if ( xc_hypercall_bounce_pre(xch, leaves) )
        return -1;

    if ( xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    domctl.cmd = XEN_DOMCTL_set_cpu_policy;
    domctl.domain = domid;
    domctl.u.cpu_policy.nr_leaves = nr_leaves;
    set_xen_guest_handle(domctl.u.cpu_policy.cpuid_policy, leaves);
    domctl.u.cpu_policy.nr_msrs = nr_msrs;
    set_xen_guest_handle(domctl.u.cpu_policy.msr_policy, msrs);
    domctl.u.cpu_policy.err_leaf = -1;
    domctl.u.cpu_policy.err_subleaf = -1;
    domctl.u.cpu_policy.err_msr = -1;

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( err_leaf_p )
        *err_leaf_p = domctl.u.cpu_policy.err_leaf;
    if ( err_subleaf_p )
        *err_subleaf_p = domctl.u.cpu_policy.err_subleaf;
    if ( err_msr_p )
        *err_msr_p = domctl.u.cpu_policy.err_msr;

    return ret;
}

static int compare_leaves(const void *l, const void *r)
{
    const xen_cpuid_leaf_t *lhs = l;
    const xen_cpuid_leaf_t *rhs = r;

    if ( lhs->leaf != rhs->leaf )
        return lhs->leaf < rhs->leaf ? -1 : 1;

    if ( lhs->subleaf != rhs->subleaf )
        return lhs->subleaf < rhs->subleaf ? -1 : 1;

    return 0;
}

static xen_cpuid_leaf_t *find_leaf(
    xen_cpuid_leaf_t *leaves, unsigned int nr_leaves,
    const struct xc_xend_cpuid *xend)
{
    const xen_cpuid_leaf_t key = { xend->leaf, xend->subleaf };

    return bsearch(&key, leaves, nr_leaves, sizeof(*leaves), compare_leaves);
}

static int xc_cpuid_xend_policy(
    xc_interface *xch, uint32_t domid, const struct xc_xend_cpuid *xend)
{
    int rc;
    xc_dominfo_t di;
    unsigned int nr_leaves, nr_msrs;
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    /*
     * Three full policies.  The host, domain max, and domain current for the
     * domain type.
     */
    xen_cpuid_leaf_t *host = NULL, *max = NULL, *cur = NULL;
    unsigned int nr_host, nr_max, nr_cur;

    if ( xc_domain_getinfo(xch, domid, 1, &di) != 1 ||
         di.domid != domid )
    {
        ERROR("Failed to obtain d%d info", domid);
        rc = -ESRCH;
        goto fail;
    }

    rc = xc_get_cpu_policy_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto fail;
    }

    rc = -ENOMEM;
    if ( (host = calloc(nr_leaves, sizeof(*host))) == NULL ||
         (max  = calloc(nr_leaves, sizeof(*max)))  == NULL ||
         (cur  = calloc(nr_leaves, sizeof(*cur)))  == NULL )
    {
        ERROR("Unable to allocate memory for %u CPUID leaves", nr_leaves);
        goto fail;
    }

    /* Get the domain's current policy. */
    nr_msrs = 0;
    nr_cur = nr_leaves;
    rc = xc_get_domain_cpu_policy(xch, domid, &nr_cur, cur, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain d%d current policy", domid);
        rc = -errno;
        goto fail;
    }

    /* Get the domain's max policy. */
    nr_msrs = 0;
    nr_max = nr_leaves;
    rc = xc_get_system_cpu_policy(xch, di.hvm ? XEN_SYSCTL_cpu_policy_hvm_max
                                              : XEN_SYSCTL_cpu_policy_pv_max,
                                  &nr_max, max, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain %s max policy", di.hvm ? "hvm" : "pv");
        rc = -errno;
        goto fail;
    }

    /* Get the host policy. */
    nr_msrs = 0;
    nr_host = nr_leaves;
    rc = xc_get_system_cpu_policy(xch, XEN_SYSCTL_cpu_policy_host,
                                  &nr_host, host, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain host policy");
        rc = -errno;
        goto fail;
    }

    rc = -EINVAL;
    for ( ; xend->leaf != XEN_CPUID_INPUT_UNUSED; ++xend )
    {
        xen_cpuid_leaf_t *cur_leaf = find_leaf(cur, nr_cur, xend);
        const xen_cpuid_leaf_t *max_leaf = find_leaf(max, nr_max, xend);
        const xen_cpuid_leaf_t *host_leaf = find_leaf(host, nr_host, xend);

        if ( cur_leaf == NULL || max_leaf == NULL || host_leaf == NULL )
        {
            ERROR("Missing leaf %#x, subleaf %#x", xend->leaf, xend->subleaf);
            goto fail;
        }

        for ( unsigned int i = 0; i < ARRAY_SIZE(xend->policy); i++ )
        {
            uint32_t *cur_reg = &cur_leaf->a + i;
            const uint32_t *max_reg = &max_leaf->a + i;
            const uint32_t *host_reg = &host_leaf->a + i;

            if ( xend->policy[i] == NULL )
                continue;

            for ( unsigned int j = 0; j < 32; j++ )
            {
                bool val;

                if ( xend->policy[i][j] == '1' )
                    val = true;
                else if ( xend->policy[i][j] == '0' )
                    val = false;
                else if ( xend->policy[i][j] == 'x' )
                    val = test_bit(31 - j, max_reg);
                else if ( xend->policy[i][j] == 'k' ||
                          xend->policy[i][j] == 's' )
                    val = test_bit(31 - j, host_reg);
                else
                {
                    ERROR("Bad character '%c' in policy[%d] string '%s'",
                          xend->policy[i][j], i, xend->policy[i]);
                    goto fail;
                }

                clear_bit(31 - j, cur_reg);
                if ( val )
                    set_bit(31 - j, cur_reg);
            }
        }
    }

    /* Feed the transformed currrent policy back up to Xen. */
    rc = xc_set_domain_cpu_policy(xch, domid, nr_cur, cur, 0, NULL,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto fail;
    }

    /* Success! */

 fail:
    free(cur);
    free(max);
    free(host);

    return rc;
}

int xc_cpuid_apply_policy(xc_interface *xch, uint32_t domid, bool restore,
                          const uint32_t *featureset, unsigned int nr_features,
                          bool pae,
                          const struct xc_xend_cpuid *xend)
{
    int rc;
    xc_dominfo_t di;
    unsigned int i, nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    struct cpuid_policy *p = NULL;
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    uint32_t host_featureset[FEATURESET_NR_ENTRIES] = {};
    uint32_t len = ARRAY_SIZE(host_featureset);

    if ( xc_domain_getinfo(xch, domid, 1, &di) != 1 ||
         di.domid != domid )
    {
        ERROR("Failed to obtain d%d info", domid);
        rc = -ESRCH;
        goto out;
    }

    rc = xc_get_cpu_policy_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto out;
    }

    rc = -ENOMEM;
    if ( (leaves = calloc(nr_leaves, sizeof(*leaves))) == NULL ||
         (p = calloc(1, sizeof(*p))) == NULL )
        goto out;

    /* Get the host policy. */
    rc = xc_get_cpu_featureset(xch, XEN_SYSCTL_cpu_featureset_host,
                               &len, host_featureset);
    if ( rc )
    {
        /* Tolerate "buffer too small", as we've got the bits we need. */
        if ( errno == ENOBUFS )
            rc = 0;
        else
        {
            PERROR("Failed to obtain host featureset");
            rc = -errno;
            goto out;
        }
    }

    /* Get the domain's default policy. */
    nr_msrs = 0;
    rc = xc_get_system_cpu_policy(xch, di.hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                              : XEN_SYSCTL_cpu_policy_pv_default,
                                  &nr_leaves, leaves, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain %s default policy", di.hvm ? "hvm" : "pv");
        rc = -errno;
        goto out;
    }

    rc = x86_cpuid_copy_from_buffer(p, leaves, nr_leaves,
                                    &err_leaf, &err_subleaf);
    if ( rc )
    {
        ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
              err_leaf, err_subleaf, -rc, strerror(-rc));
        goto out;
    }

    /*
     * Account for feature which have been disabled by default since Xen 4.13,
     * so migrated-in VM's don't risk seeing features disappearing.
     */
    if ( restore )
    {
        p->basic.rdrand = test_bit(X86_FEATURE_RDRAND, host_featureset);

        if ( di.hvm )
        {
            p->feat.mpx = test_bit(X86_FEATURE_MPX, host_featureset);
        }
    }

    if ( featureset )
    {
        uint32_t disabled_features[FEATURESET_NR_ENTRIES],
            feat[FEATURESET_NR_ENTRIES] = {};
        static const uint32_t deep_features[] = INIT_DEEP_FEATURES;
        unsigned int i, b;

        /*
         * The user supplied featureset may be shorter or longer than
         * FEATURESET_NR_ENTRIES.  Shorter is fine, and we will zero-extend.
         * Longer is fine, so long as it only padded with zeros.
         */
        unsigned int user_len = min(FEATURESET_NR_ENTRIES + 0u, nr_features);

        /* Check for truncated set bits. */
        rc = -EOPNOTSUPP;
        for ( i = user_len; i < nr_features; ++i )
            if ( featureset[i] != 0 )
                goto out;

        memcpy(feat, featureset, sizeof(*featureset) * user_len);

        /* Disable deep dependencies of disabled features. */
        for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
            disabled_features[i] = ~feat[i] & deep_features[i];

        for ( b = 0; b < sizeof(disabled_features) * CHAR_BIT; ++b )
        {
            const uint32_t *dfs;

            if ( !test_bit(b, disabled_features) ||
                 !(dfs = x86_cpuid_lookup_deep_deps(b)) )
                continue;

            for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
            {
                feat[i] &= ~dfs[i];
                disabled_features[i] &= ~dfs[i];
            }
        }

        cpuid_featureset_to_policy(feat, p);
    }
    else
    {
        if ( di.hvm )
            p->basic.pae = pae;
    }

    if ( !di.hvm )
    {
        /*
         * On hardware without CPUID Faulting, PV guests see real topology.
         * As a consequence, they also need to see the host htt/cmp fields.
         */
        p->basic.htt       = test_bit(X86_FEATURE_HTT, host_featureset);
        p->extd.cmp_legacy = test_bit(X86_FEATURE_CMP_LEGACY, host_featureset);
    }
    else
    {
        /*
         * Topology for HVM guests is entirely controlled by Xen.  For now, we
         * hardcode APIC_ID = vcpu_id * 2 to give the illusion of no SMT.
         */
        p->basic.htt = true;
        p->extd.cmp_legacy = false;

        /*
         * Leaf 1 EBX[23:16] is Maximum Logical Processors Per Package.
         * Update to reflect vLAPIC_ID = vCPU_ID * 2, but make sure to avoid
         * overflow.
         */
        if ( !(p->basic.lppp & 0x80) )
            p->basic.lppp *= 2;

        switch ( p->x86_vendor )
        {
        case X86_VENDOR_INTEL:
            for ( i = 0; (p->cache.subleaf[i].type &&
                          i < ARRAY_SIZE(p->cache.raw)); ++i )
            {
                p->cache.subleaf[i].cores_per_package =
                    (p->cache.subleaf[i].cores_per_package << 1) | 1;
                p->cache.subleaf[i].threads_per_cache = 0;
            }
            break;

        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            /*
             * Leaf 0x80000008 ECX[15:12] is ApicIdCoreSize.
             * Leaf 0x80000008 ECX[7:0] is NumberOfCores (minus one).
             * Update to reflect vLAPIC_ID = vCPU_ID * 2.  But avoid
             * - overflow,
             * - going out of sync with leaf 1 EBX[23:16],
             * - incrementing ApicIdCoreSize when it's zero (which changes the
             *   meaning of bits 7:0).
             *
             * UPDATE: I addition to avoiding overflow, some
             * proprietary operating systems have trouble with
             * apic_id_size values greater than 7.  Limit the value to
             * 7 for now.
             */
            if ( p->extd.nc < 0x7f )
            {
                if ( p->extd.apic_id_size != 0 && p->extd.apic_id_size < 0x7 )
                    p->extd.apic_id_size++;

                p->extd.nc = (p->extd.nc << 1) | 1;
            }
            break;
        }

        /*
         * These settings are necessary to cause earlier HVM_PARAM_NESTEDHVM /
         * XEN_DOMCTL_disable_migrate settings to be reflected correctly in
         * CPUID.  Xen will discard these bits if configuration hasn't been
         * set for the domain.
         */
        p->extd.itsc = true;
        p->basic.vmx = true;
        p->extd.svm = true;
    }

    rc = x86_cpuid_copy_to_buffer(p, leaves, &nr_leaves);
    if ( rc )
    {
        ERROR("Failed to serialise CPUID (%d = %s)", -rc, strerror(-rc));
        goto out;
    }

    rc = xc_set_domain_cpu_policy(xch, domid, nr_leaves, leaves, 0, NULL,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto out;
    }

    if ( xend && (rc = xc_cpuid_xend_policy(xch, domid, xend)) )
        goto out;

    rc = 0;

out:
    free(p);
    free(leaves);

    return rc;
}
