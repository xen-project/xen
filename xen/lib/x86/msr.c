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

    COPY_MSR(MSR_INTEL_PLATFORM_INFO, p->plaform_info.raw);

#undef COPY_MSR

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
