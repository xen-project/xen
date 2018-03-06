/*
 * xen/arch/arm/processor.c
 *
 * Helpers to execute processor specific code.
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2014 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <asm/procinfo.h>

static DEFINE_PER_CPU(struct processor *, processor);

void __init processor_setup(void)
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
