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
        register_t ret;                                         \
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
CHECK_WORKAROUND_HELPER(ssbd, ARM_SSBD, CONFIG_ARM_SSBD)

#undef CHECK_WORKAROUND_HELPER

enum ssbd_state
{
    ARM_SSBD_UNKNOWN,
    ARM_SSBD_FORCE_DISABLE,
    ARM_SSBD_RUNTIME,
    ARM_SSBD_FORCE_ENABLE,
    ARM_SSBD_MITIGATED,
};

#ifdef CONFIG_ARM_SSBD

#include <asm/current.h>

extern enum ssbd_state ssbd_state;

static inline enum ssbd_state get_ssbd_state(void)
{
    return ssbd_state;
}

DECLARE_PER_CPU(register_t, ssbd_callback_required);

static inline bool cpu_require_ssbd_mitigation(void)
{
    return this_cpu(ssbd_callback_required);
}

#else

static inline bool cpu_require_ssbd_mitigation(void)
{
    return false;
}

static inline enum ssbd_state get_ssbd_state(void)
{
    return ARM_SSBD_UNKNOWN;
}

#endif

#endif /* __ARM_CPUERRATA_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
