/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_MATCH_CPU_H
#define X86_MATCH_CPU_H

#include <xen/stdint.h>

struct x86_cpu_id {
    uint16_t vendor;
    uint16_t family;
    uint16_t model;
    uint16_t feature;
    const void *driver_data;
};

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
