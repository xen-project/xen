#ifndef __XEN_X86_CPUFEATURESET_H__
#define __XEN_X86_CPUFEATURESET_H__

#ifndef __ASSEMBLY__

#include <xen/stringify.h>

#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
enum {
#include <public/arch-x86/cpufeatureset.h>
#include <asm/cpufeature.h>
};
#undef XEN_CPUFEATURE

#define XEN_CPUFEATURE(name, value) asm (".equ X86_FEATURE_" #name ", " \
                                         __stringify(value));
#include <public/arch-x86/cpufeatureset.h>
#include <asm/cpufeature.h>

#else /* !__ASSEMBLY__ */

#define XEN_CPUFEATURE(name, value) .equ X86_FEATURE_##name, value
#include <public/arch-x86/cpufeatureset.h>
#include <asm/cpufeature.h>

#endif /* __ASSEMBLY__ */

#undef XEN_CPUFEATURE

#endif /* !__XEN_X86_CPUFEATURESET_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
