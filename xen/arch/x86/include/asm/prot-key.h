/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021-2022 Citrix Systems Ltd.
 */
#ifndef ASM_PROT_KEY_H
#define ASM_PROT_KEY_H

#include <xen/percpu.h>
#include <xen/types.h>

#include <asm/msr.h>

#define PKEY_AD 1 /* Access Disable */
#define PKEY_WD 2 /* Write Disable */

#define PKEY_WIDTH 2 /* Two bits per protection key */

static inline uint32_t rdpkru(void)
{
    uint32_t pkru;

    asm volatile ( ".byte 0x0f,0x01,0xee"
                   : "=a" (pkru) : "c" (0) : "dx" );

    return pkru;
}

static inline void wrpkru(uint32_t pkru)
{
    asm volatile ( ".byte 0x0f,0x01,0xef"
                   :: "a" (pkru), "d" (0), "c" (0) );
}

/*
 * Xen does not use PKS.
 *
 * Guest kernel use is expected to be one default key, except for tiny windows
 * with a double write to switch to a non-default key in a permitted critical
 * section.
 *
 * As such, we want MSR_PKRS un-intercepted.  Furthermore, as we only need it
 * in Xen for emulation or migration purposes (i.e. possibly never in a
 * domain's lifetime), we don't want to re-sync the hardware value on every
 * vmexit.
 *
 * Therefore, we read and cache the guest value in ctxt_switch_from(), in the
 * expectation that we can short-circuit the write in ctxt_switch_to().
 * During regular operations in current context, the guest value is in
 * hardware and the per-cpu cache is stale.
 */
DECLARE_PER_CPU(uint32_t, pkrs);

static inline uint32_t rdpkrs(void)
{
    uint32_t pkrs, tmp;

    rdmsr(MSR_PKRS, pkrs, tmp);

    return pkrs;
}

static inline uint32_t rdpkrs_and_cache(void)
{
    return this_cpu(pkrs) = rdpkrs();
}

static inline void wrpkrs(uint32_t pkrs)
{
    uint32_t *this_pkrs = &this_cpu(pkrs);

    if ( *this_pkrs != pkrs )
    {
        *this_pkrs = pkrs;

        wrmsr_ns(MSR_PKRS, pkrs, 0);
    }
}

static inline void wrpkrs_and_cache(uint32_t pkrs)
{
    this_cpu(pkrs) = pkrs;
    wrmsr_ns(MSR_PKRS, pkrs, 0);
}

#endif /* ASM_PROT_KEY_H */
