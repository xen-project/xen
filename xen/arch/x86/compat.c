/******************************************************************************
 * compat.c
 * 
 * Implementations of legacy hypercalls. These call through to the new
 * hypercall after doing necessary argument munging.
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/trace.h>
#include <public/sched.h>

#ifndef COMPAT
typedef long ret_t;
#endif

/* Legacy hypercall (as of 0x00030202). */
ret_t do_physdev_op_compat(XEN_GUEST_HANDLE(physdev_op_t) uop)
{
    typeof(do_physdev_op) *fn =
        (void *)pv_hypercall_table[__HYPERVISOR_physdev_op].native;
    struct physdev_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    return fn(op.cmd, guest_handle_from_ptr(&uop.p->u, void));
}

#ifndef COMPAT

/* Legacy hypercall (as of 0x00030101). */
long do_sched_op_compat(int cmd, unsigned long arg)
{
    typeof(do_sched_op) *fn =
        (void *)pv_hypercall_table[__HYPERVISOR_sched_op].native;

    switch ( cmd )
    {
    case SCHEDOP_yield:
    case SCHEDOP_block:
        return fn(cmd, guest_handle_from_ptr(NULL, void));

    case SCHEDOP_shutdown:
        TRACE_3D(TRC_SCHED_SHUTDOWN,
                 current->domain->domain_id, current->vcpu_id, arg);
        domain_shutdown(current->domain, (u8)arg);
        break;

    default:
        return -ENOSYS;
    }

    return 0;
}

/* Legacy hypercall (as of 0x00030202). */
long do_event_channel_op_compat(XEN_GUEST_HANDLE_PARAM(evtchn_op_t) uop)
{
    typeof(do_event_channel_op) *fn =
        (void *)pv_hypercall_table[__HYPERVISOR_event_channel_op].native;
    struct evtchn_op op;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
        return -EFAULT;

    switch ( op.cmd )
    {
    case EVTCHNOP_bind_interdomain:
    case EVTCHNOP_bind_virq:
    case EVTCHNOP_bind_pirq:
    case EVTCHNOP_close:
    case EVTCHNOP_send:
    case EVTCHNOP_status:
    case EVTCHNOP_alloc_unbound:
    case EVTCHNOP_bind_ipi:
    case EVTCHNOP_bind_vcpu:
    case EVTCHNOP_unmask:
        return fn(op.cmd, guest_handle_from_ptr(&uop.p->u, void));

    default:
        return -ENOSYS;
    }
}

#endif
