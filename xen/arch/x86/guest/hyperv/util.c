/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hyperv/util.c
 *
 * Hyper-V utility functions
 *
 * Copyright (c) 2020 Microsoft.
 */

#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/errno.h>

#include <asm/guest/hyperv.h>
#include <asm/guest/hyperv-tlfs.h>

#include "private.h"

int cpumask_to_vpset(struct hv_vpset *vpset,
                     const cpumask_t *mask)
{
    int nr = 1;
    unsigned int cpu, vcpu_bank, vcpu_offset;
    unsigned int max_banks = hv_max_vp_index / 64;

    /* Up to 64 banks can be represented by valid_bank_mask */
    if ( max_banks > 64 )
        return -E2BIG;

    /* Clear all banks to avoid flushing unwanted CPUs */
    for ( vcpu_bank = 0; vcpu_bank < max_banks; vcpu_bank++ )
        vpset->bank_contents[vcpu_bank] = 0;

    vpset->format = HV_GENERIC_SET_SPARSE_4K;

    for_each_cpu ( cpu, mask )
    {
        unsigned int vcpu = hv_vp_index(cpu);

        vcpu_bank = vcpu / 64;
        vcpu_offset = vcpu % 64;

        __set_bit(vcpu_offset, &vpset->bank_contents[vcpu_bank]);

        if ( vcpu_bank >= nr )
            nr = vcpu_bank + 1;
    }

    /* Some banks may be empty but that's ok */
    vpset->valid_bank_mask = ~0ULL >> (64 - nr);

    return nr;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
