/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/vaplic.c
 *
 * Virtual RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) Microchip.
 * Copyright (c) Vates
 */

#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/xvmalloc.h>

#include <asm/aia.h>
#include <asm/imsic.h>
#include <asm/intc.h>
#include <asm/vaplic.h>

#include "aplic-priv.h"

static const struct vintc_ops vintc_ops = {
    .vcpu_init = vcpu_imsic_init,
    .vcpu_deinit = vcpu_imsic_deinit,
};

int domain_vaplic_init(struct domain *d)
{
    struct vaplic *vaplic = xvzalloc(struct vaplic);

    if ( !vaplic )
        return -ENOMEM;

    d->arch.vintc = &vaplic->vintc;
    d->arch.vintc->ops = &vintc_ops;

    vaplic->regs.domaincfg = APLIC_DOMAINCFG_RO;

    return 0;
}

void domain_vaplic_deinit(struct domain *d)
{
    struct vaplic *vaplic;

    if ( !d->arch.vintc )
        return;

    vaplic = to_vaplic(d);
    d->arch.vintc = NULL;
    xvfree(vaplic);
}
