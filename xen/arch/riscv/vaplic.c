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
#include <xen/fdt-kernel.h>
#include <xen/libfdt/libfdt.h>
#include <xen/sched.h>
#include <xen/xvmalloc.h>

#include <asm/aia.h>
#include <asm/imsic.h>
#include <asm/intc.h>
#include <asm/vaplic.h>

#include "aplic-priv.h"

unsigned int __ro_after_init guest_aplic_num_sources;

#define VAPLIC_COMPATIBLE "riscv,aplic"

#define FDT_VAPLIC_INT_CELLS 2

static int __init cf_check vaplic_make_domu_dt_node(struct kernel_info *kinfo)
{
    struct domain *d = kinfo->bd.d;
    int res;
    void *fdt = kinfo->fdt;
    unsigned int msi_parent_phandle;
    char vaplic_name[32];
    unsigned int aplic_size = APLIC_SIZE(d->max_vcpus);
    const __be32 reg[] = {
        cpu_to_be32(GUEST_APLIC_S_BASE >> 32),
        cpu_to_be32(GUEST_APLIC_S_BASE),
        cpu_to_be32(0),
        cpu_to_be32(aplic_size),
    };

    BUILD_BUG_ON(APLIC_SIZE(MAX_VIRT_CPUS) > UINT_MAX);

    res = snprintf(vaplic_name, ARRAY_SIZE(vaplic_name), "/soc/aplic@%lx",
                   GUEST_APLIC_S_BASE);
    if ( res >= sizeof(vaplic_name) )
    {
        dprintk(XENLOG_DEBUG, "vaplic name is truncated\n");
        return -ENOBUFS;
    }

    res = vimsic_make_domu_dt_node(kinfo, &msi_parent_phandle);
    if ( res )
        return res;

    res = fdt_begin_node(fdt, vaplic_name);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", FDT_VAPLIC_INT_CELLS);
    if ( res )
        return res;

    res = fdt_property(fdt, "reg", reg, sizeof(reg));
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "riscv,num-sources", guest_aplic_num_sources);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", VAPLIC_COMPATIBLE);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "msi-parent", msi_parent_phandle);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_intc);
    if ( res )
        return res;

    return fdt_end_node(fdt);
}

static const struct vintc_init_ops __initconstrel init_ops = {
    .make_domu_dt_node = vaplic_make_domu_dt_node,
};

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
    d->arch.vintc->init_ops = &init_ops;

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
