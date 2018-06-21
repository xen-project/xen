#include "private.h"

#include <xen/lib/x86/cpuid.h>

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
