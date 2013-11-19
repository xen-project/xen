/******************************************************************************
 * Subarch-specific domctl.c
 *
 * Copyright (c) 2013, Citrix Systems
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/hypercall.h>
#include <public/domctl.h>

long subarch_do_domctl(struct xen_domctl *domctl, struct domain *d,
               XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_set_address_size:
        return domctl->u.address_size.size == 32 ? 0 : -EINVAL;
    default:
        return -ENOSYS;
    }
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
