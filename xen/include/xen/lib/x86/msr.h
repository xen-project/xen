/* Common data structures and functions consumed by hypervisor and toolstack */
#ifndef XEN_LIB_X86_MSR_H
#define XEN_LIB_X86_MSR_H

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
