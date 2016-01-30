#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>
#include <asm/cpuid-autogen.h>

#define FSCAPINTS FEATURESET_NR_ENTRIES

#define FEATURESET_1d     0 /* 0x00000001.edx      */
#define FEATURESET_1c     1 /* 0x00000001.ecx      */
#define FEATURESET_e1d    2 /* 0x80000001.edx      */
#define FEATURESET_e1c    3 /* 0x80000001.ecx      */
#define FEATURESET_Da1    4 /* 0x0000000d:1.eax    */
#define FEATURESET_7b0    5 /* 0x00000007:0.ebx    */
#define FEATURESET_7c0    6 /* 0x00000007:0.ecx    */
#define FEATURESET_e7d    7 /* 0x80000007.edx      */
#define FEATURESET_e8b    8 /* 0x80000008.ebx      */

#ifndef __ASSEMBLY__
#include <xen/types.h>

extern const uint32_t known_features[FSCAPINTS];
extern const uint32_t special_features[FSCAPINTS];

extern uint32_t raw_featureset[FSCAPINTS];
#define host_featureset boot_cpu_data.x86_capability
extern uint32_t pv_featureset[FSCAPINTS];
extern uint32_t hvm_featureset[FSCAPINTS];

void calculate_featuresets(void);

const uint32_t *lookup_deep_deps(uint32_t feature);

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
