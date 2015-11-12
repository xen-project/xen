/******************************************************************************
 * platform_hypercall.c
 *
 * Hardware platform operations. Intended for use by domain-0 kernel.
 *
 * Copyright (c) 2015, Citrix
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <xen/spinlock.h>
#include <public/platform.h>
#include <xsm/xsm.h>
#include <asm/current.h>
#include <asm/event.h>

DEFINE_SPINLOCK(xenpf_lock);

long do_platform_op(XEN_GUEST_HANDLE_PARAM(xen_platform_op_t) u_xenpf_op)
{
    long ret;
    struct xen_platform_op curop, *op = &curop;
    struct domain *d;

    if ( copy_from_guest(op, u_xenpf_op, 1) )
        return -EFAULT;

    if ( op->interface_version != XENPF_INTERFACE_VERSION )
        return -EACCES;

    d = rcu_lock_current_domain();
    if ( d == NULL )
        return -ESRCH;

    ret = xsm_platform_op(XSM_PRIV, op->cmd);
    if ( ret )
        return ret;

    /*
     * Trylock here avoids deadlock with an existing platform critical section
     * which might (for some current or future reason) want to synchronise
     * with this vcpu.
     */
    while ( !spin_trylock(&xenpf_lock) )
        if ( hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_platform_op, "h", u_xenpf_op);

    switch ( op->cmd )
    {
    case XENPF_settime64:
        if ( likely(!op->u.settime64.mbz) )
            do_settime(op->u.settime64.secs,
                       op->u.settime64.nsecs,
                       op->u.settime64.system_time + SECONDS(d->time_offset_seconds));
        else
            ret = -EINVAL;
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    spin_unlock(&xenpf_lock);
    rcu_unlock_domain(d);
    return ret;
}
