#include "private.h"

#include <xen/lib/x86/msr.h>

/*
 * Copy a single MSR into the provided msr_entry_buffer_t buffer, performing a
 * boundary check against the buffer size.
 */
static int copy_msr_to_buffer(uint32_t idx, uint64_t val,
                              msr_entry_buffer_t msrs,
                              uint32_t *curr_entry, const uint32_t nr_entries)
{
    const xen_msr_entry_t ent = { .idx = idx, .val = val };

    if ( *curr_entry == nr_entries )
        return -ENOBUFS;

    if ( copy_to_buffer_offset(msrs, *curr_entry, &ent, 1) )
        return -EFAULT;

    ++*curr_entry;

    return 0;
}

int x86_msr_copy_to_buffer(const struct msr_policy *p,
                           msr_entry_buffer_t msrs, uint32_t *nr_entries_p)
{
    const uint32_t nr_entries = *nr_entries_p;
    uint32_t curr_entry = 0;

#define COPY_MSR(idx, val)                                      \
    ({                                                          \
        int ret;                                                \
                                                                \
        if ( (ret = copy_msr_to_buffer(                         \
                  idx, val, msrs, &curr_entry, nr_entries)) )   \
            return ret;                                         \
    })

    COPY_MSR(MSR_INTEL_PLATFORM_INFO, p->platform_info.raw);

#undef COPY_MSR

    *nr_entries_p = curr_entry;

    return 0;
}

int x86_msr_copy_from_buffer(struct msr_policy *p,
                             const msr_entry_buffer_t msrs, uint32_t nr_entries,
                             uint32_t *err_msr)
{
    unsigned int i;
    xen_msr_entry_t data;
    int rc;

    if ( err_msr )
        *err_msr = -1;

    /*
     * A well formed caller is expected to pass an array with entries in
     * order, and without any repetitions.  However, due to per-vendor
     * differences, and in the case of upgrade or levelled scenarios, we
     * typically expect fewer than MAX entries to be passed.
     *
     * Detecting repeated entries is prohibitively complicated, so we don't
     * bother.  That said, one way or another if more than MAX entries are
     * passed, something is wrong.
     */
    if ( nr_entries > MSR_MAX_SERIALISED_ENTRIES )
        return -E2BIG;

    for ( i = 0; i < nr_entries; i++ )
    {
        if ( copy_from_buffer_offset(&data, msrs, i, 1) )
            return -EFAULT;

        if ( data.flags ) /* .flags MBZ */
        {
            rc = -EINVAL;
            goto err;
        }

        switch ( data.idx )
        {
            /*
             * Assign data.val to p->field, checking for truncation if the
             * backing storage for field is smaller than uint64_t
             */
#define ASSIGN(field)                             \
({                                                \
    if ( (typeof(p->field))data.val != data.val ) \
    {                                             \
        rc = -EOVERFLOW;                          \
        goto err;                                 \
    }                                             \
    p->field = data.val;                          \
})

        case MSR_INTEL_PLATFORM_INFO: ASSIGN(platform_info.raw); break;

#undef ASSIGN

        default:
            rc = -ERANGE;
            goto err;
        }
    }

    return 0;

 err:
    if ( err_msr )
        *err_msr = data.idx;

    return rc;
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
