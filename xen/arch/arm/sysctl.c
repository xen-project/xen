/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * Arch-specific sysctl.c
 *
 * System management operations. For use by node control stack.
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/dt-overlay.h>
#include <xen/errno.h>
#include <xen/hypercall.h>

#include <asm/arm64/sve.h>
#include <asm/gic.h>
#include <asm/vgic.h>

#include <public/sysctl.h>

void arch_do_physinfo(struct xen_sysctl_physinfo *pi)
{
    pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm | XEN_SYSCTL_PHYSCAP_hap;

    pi->arch_capabilities |= MASK_INSR(sve_encode_vl(get_sys_vl_len()),
                                       XEN_SYSCTL_PHYSCAP_ARM_SVE_MASK);

    switch ( gic_hw_version() )
    {
    case GIC_V2:
        pi->arch_capabilities |= XEN_SYSCTL_PHYSCAP_ARM_GIC_V2;
        break;

    case GIC_V3:
        pi->arch_capabilities |= XEN_SYSCTL_PHYSCAP_ARM_GIC_V3;

        /* GICv3 may additionally support GICv2-compatible guests. */
        if ( vgic_v2_hw_enabled() )
            pi->arch_capabilities |= XEN_SYSCTL_PHYSCAP_ARM_GIC_V2;
        break;

    default:
        /*
         * Running a control domain without having the GIC sorted yet?
         * Something's broken, but there's nothing we can do about it here.
         */
        printk_once(XENLOG_ERR "Unrecognised GIC version %d\n",
                    gic_hw_version());
        ASSERT_UNREACHABLE();
        break;
    }
}

long arch_do_sysctl(struct xen_sysctl *sysctl,
                    XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    long ret;

    switch ( sysctl->cmd )
    {
    case XEN_SYSCTL_dt_overlay:
        ret = dt_overlay_sysctl(&sysctl->u.dt_overlay);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
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
