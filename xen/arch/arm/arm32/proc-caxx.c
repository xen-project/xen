/*
 * xen/arch/arm/arm32/proc-caxx.c
 *
 * arm V7 Cortex A15 and A7 initialisation
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2014 Linaro Limited.
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
#include <asm/processor.h>

#define ACTLR_SMP (1 << 6)

static void caxx_vcpu_initialise(struct vcpu *v)
{
    /* If the guest has more 1 VCPU, enable the SMP bit in ACTLR */
    if ( v->domain->max_vcpus > 1 )
        v->arch.actlr |= ACTLR_SMP;
    else
        v->arch.actlr &= ~ACTLR_SMP;
}

const struct processor caxx_processor = {
    .vcpu_initialise = caxx_vcpu_initialise,
};
