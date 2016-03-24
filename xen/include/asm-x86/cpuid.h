#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>
#include <asm/cpuid-autogen.h>

#define FSCAPINTS FEATURESET_NR_ENTRIES

#ifndef __ASSEMBLY__
#include <xen/types.h>

extern const uint32_t known_features[FSCAPINTS];
extern const uint32_t special_features[FSCAPINTS];

#endif /* __ASSEMBLY__ */
#endif /* !__X86_CPUID_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
