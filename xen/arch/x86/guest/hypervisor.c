/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hypervisor.c
 *
 * Support for detecting and running under a hypervisor.
 *
 * Copyright (c) 2019 Microsoft.
 */
#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/guest.h>

static struct hypervisor_ops __ro_after_init ops;

const char *__init hypervisor_probe(void)
{
    const struct hypervisor_ops *fns;

    if ( !cpu_has_hypervisor )
        return NULL;

    fns = xg_probe();
    if ( !fns )
        /*
         * Detection of Hyper-V must come after Xen to avoid false positive due
         * to viridian support
         */
        fns = hyperv_probe();

    if ( fns )
        ops = *fns;

    return ops.name;
}

void __init hypervisor_setup(void)
{
    if ( ops.setup )
        ops.setup();

    /* Check if assisted flush is available and disable the TLB clock if so. */
    if ( !hypervisor_flush_tlb(cpumask_of(smp_processor_id()), NULL, 0) )
        tlb_clk_enabled = false;
}

int hypervisor_ap_setup(void)
{
    if ( ops.ap_setup )
        return alternative_call(ops.ap_setup);

    return 0;
}

void hypervisor_resume(void)
{
    if ( ops.resume )
        alternative_vcall(ops.resume);
}

void __init hypervisor_e820_fixup(void)
{
    if ( ops.e820_fixup )
        ops.e820_fixup();
}

int hypervisor_flush_tlb(const cpumask_t *mask, const void *va,
                         unsigned int flags)
{
    if ( ops.flush_tlb )
        return alternative_call(ops.flush_tlb, mask, va, flags);

    return -EOPNOTSUPP;
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
