/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_MATCH_CPU_H
#define X86_MATCH_CPU_H

#include <xen/stdint.h>

#include <asm/cpufeature.h>
#include <asm/intel-family.h>
#include <asm/x86-vendors.h>

#define X86_STEPPING_ANY 0xffff
#define X86_FEATURE_ANY X86_FEATURE_LM

struct x86_cpu_id {
    uint8_t  vendor;
    uint8_t  family;
    uint16_t model;
    uint16_t steppings; /* Stepping bitmap, or X86_STEPPING_ANY */
    uint16_t feature;   /* X86_FEATURE_*, or X86_FEATURE_ANY */
    const void *driver_data;
};

#define X86_MATCH_CPU(v, f, m, steps, feat, data)               \
    {                                                           \
        .vendor       = (v),                                    \
        .family       = (f),                                    \
        .model        = (m),                                    \
        .steppings    = (steps),                                \
        .feature      = (feat),                                 \
        .driver_data  = (const void *)(unsigned long)(data),    \
    }

#define X86_MATCH_VFM(vfm, data)                                \
    X86_MATCH_CPU(VFM_VENDOR(vfm), VFM_FAMILY(vfm),             \
                  VFM_MODEL(vfm), X86_STEPPING_ANY,             \
                  X86_FEATURE_ANY, data)

#define X86_MATCH_VFMS(vfm, stepping, data)                     \
    X86_MATCH_CPU(VFM_VENDOR(vfm), VFM_FAMILY(vfm),             \
                  VFM_MODEL(vfm), 1U << (stepping),             \
                  X86_FEATURE_ANY, data)

/*
 * x86_match_cpu() - match the CPU against an array of x86_cpu_ids[]
 *
 * @table: Array of x86_cpu_ids. Table terminated with {}.
 *
 * Returns the first matching entry, otherwise NULL.  This always matches
 * against the boot CPU, assuming models and features are consistent over all
 * CPUs.
 */
const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id table[]);

#endif /* X86_MATCH_CPU_H */
