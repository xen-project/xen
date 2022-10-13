/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/processor.c
 *
 * Helpers to execute processor specific code.
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2014 Linaro Limited.
 */
#include <asm/procinfo.h>

static DEFINE_PER_CPU(struct processor *, processor);

void processor_setup(void)
{
    const struct proc_info_list *procinfo;

    procinfo = lookup_processor_type();
    if ( !procinfo )
        return;

    this_cpu(processor) = procinfo->processor;
}

void processor_vcpu_initialise(struct vcpu *v)
{
    if ( !this_cpu(processor) || !this_cpu(processor)->vcpu_initialise )
        return;

    this_cpu(processor)->vcpu_initialise(v);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
