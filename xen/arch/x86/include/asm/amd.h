/*
 * amd.h - AMD processor specific definitions
 */

#ifndef __AMD_H__
#define __AMD_H__

#include <asm/cpufeature.h>

/* AMD errata checking
 *
 * Errata are defined using the AMD_LEGACY_ERRATUM() or AMD_OSVW_ERRATUM()
 * macros. The latter is intended for newer errata that have an OSVW id
 * assigned, which it takes as first argument. Both take a variable number
 * of family-specific model-stepping ranges created by AMD_MODEL_RANGE().
 *
 * Example 1:
 * #define AMD_ERRATUM_319                                              \
 *   AMD_LEGACY_ERRATUM(AMD_MODEL_RANGE(0x10, 0x2, 0x1, 0x4, 0x2),      \
 *                      AMD_MODEL_RANGE(0x10, 0x8, 0x0, 0x8, 0x0),      \
 *                      AMD_MODEL_RANGE(0x10, 0x9, 0x0, 0x9, 0x0))
 * Example 2:
 * #define AMD_ERRATUM_400                                              \
 *   AMD_OSVW_ERRATUM(1, AMD_MODEL_RANGE(0xf, 0x41, 0x2, 0xff, 0xf),    \
 *                       AMD_MODEL_RANGE(0x10, 0x2, 0x1, 0xff, 0xf))
 *   
 */

#define AMD_LEGACY_ERRATUM(...)         -1 /* legacy */, __VA_ARGS__, 0
#define AMD_OSVW_ERRATUM(osvw_id, ...)  osvw_id, __VA_ARGS__, 0
#define AMD_MODEL_RANGE(f, m_start, s_start, m_end, s_end)              \
    (((f) << 24) | ((m_start) << 16) | ((s_start) << 12) | \
     ((m_end) << 4) | (s_end))
#define AMD_MODEL_RANGE_FAMILY(range)   (((range) >> 24) & 0xff)
#define AMD_MODEL_RANGE_START(range)    (((range) >> 12) & 0xfff)
#define AMD_MODEL_RANGE_END(range)      ((range) & 0xfff)

#define AMD_ERRATUM_121                                                 \
    AMD_LEGACY_ERRATUM(AMD_MODEL_RANGE(0x0f, 0x0, 0x0, 0x3f, 0xf))

#define AMD_ERRATUM_170                                                 \
    AMD_LEGACY_ERRATUM(AMD_MODEL_RANGE(0x0f, 0x0, 0x0, 0x67, 0xf))

#define AMD_ERRATUM_383                                                 \
    AMD_OSVW_ERRATUM(3, AMD_MODEL_RANGE(0x10, 0x2, 0x1, 0xff, 0xf),	\
		        AMD_MODEL_RANGE(0x12, 0x0, 0x0, 0x1, 0x0))

#define AMD_ERRATUM_573							\
    AMD_LEGACY_ERRATUM(AMD_MODEL_RANGE(0x0f, 0x0, 0x0, 0xff, 0xf),	\
                       AMD_MODEL_RANGE(0x10, 0x0, 0x0, 0xff, 0xf),	\
                       AMD_MODEL_RANGE(0x11, 0x0, 0x0, 0xff, 0xf),	\
                       AMD_MODEL_RANGE(0x12, 0x0, 0x0, 0xff, 0xf))

/*
 * The Zen1 and Zen2 microarchitectures are implemented by AMD (Fam17h) and
 * Hygon (Fam18h) but without simple model number rules.  Instead, use STIBP
 * as a heuristic that distinguishes the two.
 *
 * For Zen3 and Zen4 (Fam19h) the heuristic is the presence of AutoIBRS, as
 * it's Zen4-specific.
 *
 * The caller is required to perform the appropriate vendor/family checks
 * first.
 */
#define is_zen1_uarch() (!boot_cpu_has(X86_FEATURE_AMD_STIBP))
#define is_zen2_uarch()   boot_cpu_has(X86_FEATURE_AMD_STIBP)
#define is_zen3_uarch() (!boot_cpu_has(X86_FEATURE_AUTO_IBRS))
#define is_zen4_uarch()   boot_cpu_has(X86_FEATURE_AUTO_IBRS)

struct cpuinfo_x86;
int cpu_has_amd_erratum(const struct cpuinfo_x86 *cpu, int osvw_id, ...);

extern int8_t opt_allow_unsafe;

void fam10h_check_enable_mmcfg(void);
void check_enable_amd_mmconf_dmi(void);

extern bool amd_acpi_c1e_quirk;
void amd_check_disable_c1e(unsigned int port, u8 value);

extern bool amd_legacy_ssbd;
extern bool amd_virt_spec_ctrl;
bool amd_setup_legacy_ssbd(void);
void amd_set_legacy_ssbd(bool enable);
void amd_set_cpuid_user_dis(bool enable);
void amd_process_freq(const struct cpuinfo_x86 *c, unsigned int *low_mhz,
                      unsigned int *nom_mhz, unsigned int *hi_mhz);

#endif /* __AMD_H__ */
