/******************************************************************************
 * Arch-specific domctl.c
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <public/domctl.h>

long arch_do_domctl(struct xen_domctl *domctl,
                    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
