/******************************************************************************
 * compat.c
 * 
 * Implementations of legacy hypercalls. These call through to the new
 * hypercall after doing necessary argument munging.
 */

#include <xen/config.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>

/* Legacy hypercall (as of 0x00030202). */
long do_physdev_op_compat(XEN_GUEST_HANDLE(physdev_op_t) uop)
{
    struct physdev_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    return do_physdev_op(op.cmd, (XEN_GUEST_HANDLE(void)) { &uop.p->u });
}

/* Legacy hypercall (as of 0x00030202). */
long do_event_channel_op_compat(XEN_GUEST_HANDLE(evtchn_op_t) uop)
{
    struct evtchn_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    return do_event_channel_op(op.cmd, (XEN_GUEST_HANDLE(void)) {&uop.p->u });
}
