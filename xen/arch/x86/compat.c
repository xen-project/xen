/******************************************************************************
 * compat.c
 * 
 * Implementations of legacy hypercalls. These call through to the new
 * hypercall after doing necessary argument munging.
 */

#include <xen/config.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>

#ifndef COMPAT
typedef long ret_t;
#endif

/* Legacy hypercall (as of 0x00030202). */
ret_t do_physdev_op_compat(XEN_GUEST_HANDLE(physdev_op_t) uop)
{
    struct physdev_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    return do_physdev_op(op.cmd, guest_handle_from_ptr(&uop.p->u, void));
}

#ifndef COMPAT

/* Legacy hypercall (as of 0x00030202). */
long do_event_channel_op_compat(XEN_GUEST_HANDLE_PARAM(evtchn_op_t) uop)
{
    struct evtchn_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    return do_event_channel_op(op.cmd, guest_handle_from_ptr(&uop.p->u, void));
}

#endif
