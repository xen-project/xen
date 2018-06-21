/* Common data structures and functions consumed by hypervisor and toolstack */
#ifndef XEN_LIB_X86_MSR_H
#define XEN_LIB_X86_MSR_H

/* Maximum number of MSRs written when serialising msr_policy. */
#define MSR_MAX_SERIALISED_ENTRIES 1

/* MSR policy object for shared per-domain MSRs */
struct msr_policy
{
    /*
     * 0x000000ce - MSR_INTEL_PLATFORM_INFO
     *
     * This MSR is non-architectural, but for simplicy we allow it to be read
     * unconditionally.  CPUID Faulting support can be fully emulated for HVM
     * guests so can be offered unconditionally, while support for PV guests
     * is dependent on real hardware support.
     */
    union {
        uint32_t raw;
        struct {
            uint32_t :31;
            bool cpuid_faulting:1;
        };
    } plaform_info;
};

#ifdef __XEN__
#include <public/arch-x86/xen.h>
typedef XEN_GUEST_HANDLE_64(xen_msr_entry_t) msr_entry_buffer_t;
#else
#include <xen/arch-x86/xen.h>
typedef xen_msr_entry_t msr_entry_buffer_t[];
#endif

/**
 * Serialise an msr_policy object into an array.
 *
 * @param policy     The msr_policy to serialise.
 * @param msrs       The array of msrs to serialise into.
 * @param nr_entries The number of entries in 'msrs'.
 * @returns -errno
 *
 * Writes at most MSR_MAX_SERIALISED_ENTRIES.  May fail with -ENOBUFS if the
 * buffer array is too short.  On success, nr_entries is updated with the
 * actual number of msrs written.
 */
int x86_msr_copy_to_buffer(const struct msr_policy *policy,
                           msr_entry_buffer_t msrs, uint32_t *nr_entries);

#endif /* !XEN_LIB_X86_MSR_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
