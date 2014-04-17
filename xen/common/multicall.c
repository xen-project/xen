/******************************************************************************
 * multicall.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/multicall.h>
#include <xen/guest_access.h>
#include <xen/perfc.h>
#include <xen/trace.h>
#include <asm/current.h>
#include <asm/hardirq.h>

#ifndef COMPAT
typedef long ret_t;
#define xlat_multicall_entry(mcs)

static void __trace_multicall_call(multicall_entry_t *call)
{
    __trace_hypercall(TRC_PV_HYPERCALL_SUBCALL, call->op, call->args);
}
#endif

static void trace_multicall_call(multicall_entry_t *call)
{
    if ( !tb_init_done )
        return;

    __trace_multicall_call(call);
}

ret_t
do_multicall(
    XEN_GUEST_HANDLE_PARAM(multicall_entry_t) call_list, uint32_t nr_calls)
{
    struct mc_state *mcs = &current->mc_state;
    uint32_t         i;
    int              rc = 0;

    if ( unlikely(__test_and_set_bit(_MCSF_in_multicall, &mcs->flags)) )
    {
        gdprintk(XENLOG_INFO, "Multicall reentry is disallowed.\n");
        return -EINVAL;
    }

    if ( unlikely(!guest_handle_okay(call_list, nr_calls)) )
        rc = -EFAULT;

    for ( i = 0; !rc && i < nr_calls; i++ )
    {
        if ( i && hypercall_preempt_check() )
            goto preempted;

        if ( unlikely(__copy_from_guest(&mcs->call, call_list, 1)) )
        {
            rc = -EFAULT;
            break;
        }

        trace_multicall_call(&mcs->call);

        do_multicall_call(&mcs->call);

#ifndef NDEBUG
        {
            /*
             * Deliberately corrupt the contents of the multicall structure.
             * The caller must depend only on the 'result' field on return.
             */
            struct multicall_entry corrupt;
            memset(&corrupt, 0xAA, sizeof(corrupt));
            (void)__copy_to_guest(call_list, &corrupt, 1);
        }
#endif

        if ( unlikely(__copy_field_to_guest(call_list, &mcs->call, result)) )
            rc = -EFAULT;
        else if ( test_bit(_MCSF_call_preempted, &mcs->flags) )
        {
            /* Translate sub-call continuation to guest layout */
            xlat_multicall_entry(mcs);

            /* Copy the sub-call continuation. */
            if ( likely(!__copy_to_guest(call_list, &mcs->call, 1)) )
                goto preempted;
            rc = -EFAULT;
        }
        else
            guest_handle_add_offset(call_list, 1);
    }

    perfc_incr(calls_to_multicall);
    perfc_add(calls_from_multicall, i);
    mcs->flags = 0;
    return rc;

 preempted:
    perfc_add(calls_from_multicall, i);
    mcs->flags = 0;
    return hypercall_create_continuation(
        __HYPERVISOR_multicall, "hi", call_list, nr_calls-i);
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
