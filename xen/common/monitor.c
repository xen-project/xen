/*
 * xen/common/monitor.c
 *
 * Common monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/monitor.h>
#include <xen/sched.h>
#include <xsm/xsm.h>
#include <public/domctl.h>
#include <asm/monitor.h>

int monitor_domctl(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    int rc;

    if ( unlikely(current->domain == d) ) /* no domain_pause() */
        return -EPERM;

    rc = xsm_vm_event_control(XSM_PRIV, d, mop->op, mop->event);
    if ( unlikely(rc) )
        return rc;

    switch ( mop->op )
    {
    case XEN_DOMCTL_MONITOR_OP_ENABLE:
    case XEN_DOMCTL_MONITOR_OP_DISABLE:
        /* Check if event type is available. */
        /* sanity check: avoid left-shift undefined behavior */
        if ( unlikely(mop->event > 31) )
            return -EINVAL;
        if ( unlikely(!(arch_monitor_get_capabilities(d) & (1U << mop->event))) )
            return -EOPNOTSUPP;
        /* Arch-side handles enable/disable ops. */
        return arch_monitor_domctl_event(d, mop);

    case XEN_DOMCTL_MONITOR_OP_GET_CAPABILITIES:
        mop->event = arch_monitor_get_capabilities(d);
        return 0;

    default:
        /* The monitor op is probably handled on the arch-side. */
        return arch_monitor_domctl_op(d, mop);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
