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
#include <asm/cpufeature.h>

static long switch_mode(struct domain *d, enum domain_type type)
{
    if ( d == NULL )
        return -EINVAL;
    if ( d->tot_pages != 0 )
        return -EBUSY;
    if ( d->arch.type == type )
        return 0;

    d->arch.type = type;

    return 0;
}

long subarch_do_domctl(struct xen_domctl *domctl, struct domain *d,
                       XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_set_address_size:
        switch ( domctl->u.address_size.size )
        {
        case 32:
            if ( !cpu_has_el1_32 )
                return -EINVAL;
            return switch_mode(d, DOMAIN_32BIT);
        case 64:
            return switch_mode(d, DOMAIN_64BIT);
        default:
            return -EINVAL;
        }
        break;

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
