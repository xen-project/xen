/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_TSC_H
#define X86_TSC_H

#include <asm/alternative.h>

static inline uint64_t rdtsc(void)
{
    uint64_t low, high;

    asm volatile ( "rdtsc" : "=a" (low), "=d" (high) );

    return (high << 32) | low;
}

static inline uint64_t rdtsc_ordered(void)
{
    uint64_t low, high, aux;

    /*
     * The RDTSC instruction is not serializing.  Make it dispatch serializing
     * for the purposes here by issuing LFENCE (or MFENCE if necessary) ahead
     * of it.
     *
     * RDTSCP, otoh, "does wait until all previous instructions have executed
     * and all previous loads are globally visible" (SDM) / "forces all older
     * instructions to retire before reading the timestamp counter" (APM).
     */
    alternative_io_2("lfence; rdtsc",
                     "mfence; rdtsc", X86_FEATURE_MFENCE_RDTSC,
                     "rdtscp",        X86_FEATURE_RDTSCP,
                     ASM_OUTPUT2("=a" (low), "=d" (high), "=c" (aux)),
                     /* no inputs */);

    return (high << 32) | low;
}

#define __write_tsc(val) wrmsrl(MSR_IA32_TSC, val)

/*
 * Reliable TSCs are in lockstep across all CPUs. We should never write to
 * them.
 */
#define write_tsc(val) ({                                       \
    ASSERT(!boot_cpu_has(X86_FEATURE_TSC_RELIABLE));            \
    __write_tsc(val);                                           \
})

#endif /* X86_TSC_H */
