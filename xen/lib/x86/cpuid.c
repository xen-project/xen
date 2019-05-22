#include "private.h"

#include <xen/lib/x86/cpuid.h>

unsigned int x86_cpuid_lookup_vendor(uint32_t ebx, uint32_t ecx, uint32_t edx)
{
    switch ( ebx )
    {
    case X86_VENDOR_INTEL_EBX:
        if ( ecx == X86_VENDOR_INTEL_ECX &&
             edx == X86_VENDOR_INTEL_EDX )
            return X86_VENDOR_INTEL;
        break;

    case X86_VENDOR_AMD_EBX:
        if ( ecx == X86_VENDOR_AMD_ECX &&
             edx == X86_VENDOR_AMD_EDX )
            return X86_VENDOR_AMD;
        break;

    case X86_VENDOR_CENTAUR_EBX:
        if ( ecx == X86_VENDOR_CENTAUR_ECX &&
             edx == X86_VENDOR_CENTAUR_EDX )
            return X86_VENDOR_CENTAUR;
        break;

    case X86_VENDOR_SHANGHAI_EBX:
        if ( ecx == X86_VENDOR_SHANGHAI_ECX &&
             edx == X86_VENDOR_SHANGHAI_EDX )
            return X86_VENDOR_SHANGHAI;
        break;
    }

    return X86_VENDOR_UNKNOWN;
}

const char *x86_cpuid_vendor_to_str(unsigned int vendor)
{
    switch ( vendor )
    {
    case X86_VENDOR_INTEL:    return "Intel";
    case X86_VENDOR_AMD:      return "AMD";
    case X86_VENDOR_CENTAUR:  return "Centaur";
    case X86_VENDOR_SHANGHAI: return "Shanghai";
    default:                  return "Unknown";
    }
}

/* Recalculate the content in a CPUID policy which is derived from raw data. */
static void recalculate_synth(struct cpuid_policy *p)
{
    p->x86_vendor = x86_cpuid_lookup_vendor(
        p->basic.vendor_ebx, p->basic.vendor_ecx, p->basic.vendor_edx);
}

void x86_cpuid_policy_fill_native(struct cpuid_policy *p)
{
    unsigned int i;

    cpuid_leaf(0, &p->basic.raw[0]);
    for ( i = 1; i < min_t(unsigned int, ARRAY_SIZE(p->basic.raw),
                           p->basic.max_leaf); ++i )
    {
        switch ( i )
        {
        case 0x4: case 0x7: case 0xb: case 0xd:
            /* Multi-invocation leaves.  Deferred. */
            continue;
        }

        cpuid_leaf(i, &p->basic.raw[i]);
    }

    if ( p->basic.max_leaf >= 4 )
    {
        for ( i = 0; i < ARRAY_SIZE(p->cache.raw); ++i )
        {
            union {
                struct cpuid_leaf l;
                struct cpuid_cache_leaf c;
            } u;

            cpuid_count_leaf(4, i, &u.l);

            if ( u.c.type == 0 )
                break;

            p->cache.subleaf[i] = u.c;
        }

        /*
         * The choice of CPUID_GUEST_NR_CACHE is arbitrary.  It is expected
         * that it will eventually need increasing for future hardware.
         */
#ifdef __XEN__
        if ( i == ARRAY_SIZE(p->cache.raw) )
            printk(XENLOG_WARNING
                   "CPUID: Insufficient Leaf 4 space for this hardware\n");
#endif
    }

    if ( p->basic.max_leaf >= 7 )
    {
        cpuid_count_leaf(7, 0, &p->feat.raw[0]);

        for ( i = 1; i < min_t(unsigned int, ARRAY_SIZE(p->feat.raw),
                               p->feat.max_subleaf); ++i )
            cpuid_count_leaf(7, i, &p->feat.raw[i]);
    }

    if ( p->basic.max_leaf >= 0xb )
    {
        union {
            struct cpuid_leaf l;
            struct cpuid_topo_leaf t;
        } u;

        for ( i = 0; i < ARRAY_SIZE(p->topo.raw); ++i )
        {
            cpuid_count_leaf(0xb, i, &u.l);

            if ( u.t.type == 0 )
                break;

            p->topo.subleaf[i] = u.t;
        }

        /*
         * The choice of CPUID_GUEST_NR_TOPO is per the manual.  It may need
         * to grow for future hardware.
         */
#ifdef __XEN__
        if ( i == ARRAY_SIZE(p->topo.raw) &&
             (cpuid_count_leaf(0xb, i, &u.l), u.t.type != 0) )
            printk(XENLOG_WARNING
                   "CPUID: Insufficient Leaf 0xb space for this hardware\n");
#endif
    }

    if ( p->basic.max_leaf >= 0xd )
    {
        uint64_t xstates;

        cpuid_count_leaf(0xd, 0, &p->xstate.raw[0]);
        cpuid_count_leaf(0xd, 1, &p->xstate.raw[1]);

        xstates = cpuid_policy_xstates(p);

        for ( i = 2; i < min_t(unsigned int, 63,
                               ARRAY_SIZE(p->xstate.raw)); ++i )
        {
            if ( xstates & (1ul << i) )
                cpuid_count_leaf(0xd, i, &p->xstate.raw[i]);
        }
    }

    /* Extended leaves. */
    cpuid_leaf(0x80000000, &p->extd.raw[0]);
    for ( i = 1; i < min_t(unsigned int, ARRAY_SIZE(p->extd.raw),
                           p->extd.max_leaf + 1 - 0x80000000); ++i )
        cpuid_leaf(0x80000000 + i, &p->extd.raw[i]);

    recalculate_synth(p);
}

const uint32_t *x86_cpuid_lookup_deep_deps(uint32_t feature)
{
    static const uint32_t deep_features[] = INIT_DEEP_FEATURES;
    static const struct {
        uint32_t feature;
        uint32_t fs[FEATURESET_NR_ENTRIES];
    } deep_deps[] = INIT_DEEP_DEPS;
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

/*
 * Copy a single cpuid_leaf into a provided xen_cpuid_leaf_t buffer,
 * performing boundary checking against the buffer size.
 */
static int copy_leaf_to_buffer(uint32_t leaf, uint32_t subleaf,
                               const struct cpuid_leaf *data,
                               cpuid_leaf_buffer_t leaves,
                               uint32_t *curr_entry, const uint32_t nr_entries)
{
    const xen_cpuid_leaf_t val = {
        leaf, subleaf, data->a, data->b, data->c, data->d,
    };

    if ( *curr_entry == nr_entries )
        return -ENOBUFS;

    if ( copy_to_buffer_offset(leaves, *curr_entry, &val, 1) )
        return -EFAULT;

    ++*curr_entry;

    return 0;
}

int x86_cpuid_copy_to_buffer(const struct cpuid_policy *p,
                             cpuid_leaf_buffer_t leaves, uint32_t *nr_entries_p)
{
    const uint32_t nr_entries = *nr_entries_p;
    uint32_t curr_entry = 0, leaf, subleaf;

#define COPY_LEAF(l, s, data)                                       \
    ({                                                              \
        int ret;                                                    \
                                                                    \
        if ( (ret = copy_leaf_to_buffer(                            \
                  l, s, data, leaves, &curr_entry, nr_entries)) )   \
            return ret;                                             \
    })

    /* Basic leaves. */
    for ( leaf = 0; leaf <= MIN(p->basic.max_leaf,
                                ARRAY_SIZE(p->basic.raw) - 1); ++leaf )
    {
        switch ( leaf )
        {
        case 0x4:
            for ( subleaf = 0; subleaf < ARRAY_SIZE(p->cache.raw); ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->cache.raw[subleaf]);
            break;

        case 0x7:
            for ( subleaf = 0;
                  subleaf <= MIN(p->feat.max_subleaf,
                                 ARRAY_SIZE(p->feat.raw) - 1); ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->feat.raw[subleaf]);
            break;

        case 0xb:
            for ( subleaf = 0; subleaf < ARRAY_SIZE(p->topo.raw); ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->topo.raw[subleaf]);
            break;

        case 0xd:
            for ( subleaf = 0; subleaf < ARRAY_SIZE(p->xstate.raw); ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->xstate.raw[subleaf]);
            break;

        default:
            COPY_LEAF(leaf, XEN_CPUID_NO_SUBLEAF, &p->basic.raw[leaf]);
            break;
        }
    }

    /* TODO: Port Xen and Viridian leaves to the new CPUID infrastructure. */
    COPY_LEAF(0x40000000, XEN_CPUID_NO_SUBLEAF,
              &(struct cpuid_leaf){ p->hv_limit });
    COPY_LEAF(0x40000100, XEN_CPUID_NO_SUBLEAF,
              &(struct cpuid_leaf){ p->hv2_limit });

    /* Extended leaves. */
    for ( leaf = 0; leaf <= MIN(p->extd.max_leaf & 0xfffful,
                                ARRAY_SIZE(p->extd.raw) - 1); ++leaf )
        COPY_LEAF(0x80000000 | leaf, XEN_CPUID_NO_SUBLEAF, &p->extd.raw[leaf]);

#undef COPY_LEAF

    *nr_entries_p = curr_entry;

    return 0;
}

int x86_cpuid_copy_from_buffer(struct cpuid_policy *p,
                               const cpuid_leaf_buffer_t leaves,
                               uint32_t nr_entries, uint32_t *err_leaf,
                               uint32_t *err_subleaf)
{
    unsigned int i;
    xen_cpuid_leaf_t data;

    /*
     * A well formed caller is expected to pass an array with leaves in order,
     * and without any repetitions.  However, due to per-vendor differences,
     * and in the case of upgrade or levelled scenarios, we typically expect
     * fewer than MAX leaves to be passed.
     *
     * Detecting repeated entries is prohibitively complicated, so we don't
     * bother.  That said, one way or another if more than MAX leaves are
     * passed, something is wrong.
     */
    if ( nr_entries > CPUID_MAX_SERIALISED_LEAVES )
        return -E2BIG;

    for ( i = 0; i < nr_entries; ++i )
    {
        struct cpuid_leaf l;

        if ( copy_from_buffer_offset(&data, leaves, i, 1) )
            return -EFAULT;

        l = (struct cpuid_leaf){ data.a, data.b, data.c, data.d };

        switch ( data.leaf )
        {
        case 0 ... ARRAY_SIZE(p->basic.raw) - 1:
            switch ( data.leaf )
            {
            case 0x4:
                if ( data.subleaf >= ARRAY_SIZE(p->cache.raw) )
                    goto out_of_range;

                array_access_nospec(p->cache.raw, data.subleaf) = l;
                break;

            case 0x7:
                if ( data.subleaf >= ARRAY_SIZE(p->feat.raw) )
                    goto out_of_range;

                array_access_nospec(p->feat.raw, data.subleaf) = l;
                break;

            case 0xb:
                if ( data.subleaf >= ARRAY_SIZE(p->topo.raw) )
                    goto out_of_range;

                array_access_nospec(p->topo.raw, data.subleaf) = l;
                break;

            case 0xd:
                if ( data.subleaf >= ARRAY_SIZE(p->xstate.raw) )
                    goto out_of_range;

                array_access_nospec(p->xstate.raw, data.subleaf) = l;
                break;

            default:
                if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                    goto out_of_range;

                array_access_nospec(p->basic.raw, data.leaf) = l;
                break;
            }
            break;

        case 0x40000000:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            p->hv_limit = l.a;
            break;

        case 0x40000100:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            p->hv2_limit = l.a;
            break;

        case 0x80000000 ... 0x80000000 + ARRAY_SIZE(p->extd.raw) - 1:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            array_access_nospec(p->extd.raw, data.leaf & 0xffff) = l;
            break;

        default:
            goto out_of_range;
        }
    }

    recalculate_synth(p);

    return 0;

 out_of_range:
    if ( err_leaf )
        *err_leaf = data.leaf;
    if ( err_subleaf )
        *err_subleaf = data.subleaf;

    return -ERANGE;
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
