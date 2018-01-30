#ifndef __ARM_CPUERRATA_H__
#define __ARM_CPUERRATA_H__

#include <asm/cpufeature.h>
#include <asm/alternative.h>

void check_local_cpu_errata(void);
void enable_errata_workarounds(void);

#define CHECK_WORKAROUND_HELPER(erratum, feature, arch)         \
static inline bool check_workaround_##erratum(void)             \
{                                                               \
    if ( !IS_ENABLED(arch) )                                    \
        return false;                                           \
    else                                                        \
    {                                                           \
        bool ret;                                               \
                                                                \
        asm volatile (ALTERNATIVE("mov %0, #0",                 \
                                  "mov %0, #1",                 \
                                  feature)                      \
                      : "=r" (ret));                            \
                                                                \
        return unlikely(ret);                                   \
    }                                                           \
}

CHECK_WORKAROUND_HELPER(766422, ARM32_WORKAROUND_766422, CONFIG_ARM_32)
CHECK_WORKAROUND_HELPER(834220, ARM64_WORKAROUND_834220, CONFIG_ARM_64)

#undef CHECK_WORKAROUND_HELPER

#endif /* __ARM_CPUERRATA_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
