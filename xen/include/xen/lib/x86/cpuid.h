/* Common data structures and functions consumed by hypervisor and toolstack */
#ifndef XEN_LIB_X86_CPUID_H
#define XEN_LIB_X86_CPUID_H

#include <xen/lib/x86/cpuid-autogen.h>

struct cpuid_leaf
{
    uint32_t a, b, c, d;
};

#endif /* !XEN_LIB_X86_CPUID_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
