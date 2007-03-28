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
#include <asm/current.h>
#include <asm/hardirq.h>

#ifndef COMPAT
DEFINE_PER_CPU(struct mc_state, mc_state);
typedef long ret_t;
#endif

ret_t
do_multicall(
    XEN_GUEST_HANDLE(multicall_entry_t) call_list, unsigned int nr_calls)
{
    struct mc_state *mcs = &this_cpu(mc_state);
    unsigned int     i;

    if ( unlikely(__test_and_set_bit(_MCSF_in_multicall, &mcs->flags)) )
    {
        gdprintk(XENLOG_INFO, "Multicall reentry is disallowed.\n");
        return -EINVAL;
    }

    if ( unlikely(!guest_handle_okay(call_list, nr_calls)) )
        goto fault;

    for ( i = 0; i < nr_calls; i++ )
    {
        if ( hypercall_preempt_check() )
            goto preempted;

        if ( unlikely(__copy_from_guest(&mcs->call, call_list, 1)) )
            goto fault;

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
            goto fault;

        if ( test_bit(_MCSF_call_preempted, &mcs->flags) )
        {
            /* Copy the sub-call continuation. */
            (void)__copy_to_guest(call_list, &mcs->call, 1);
            goto preempted;
        }

        guest_handle_add_offset(call_list, 1);
    }

    perfc_incr(calls_to_multicall);
    perfc_add(calls_from_multicall, nr_calls);
    mcs->flags = 0;
    return 0;

 fault:
    perfc_incr(calls_to_multicall);
    mcs->flags = 0;
    return -EFAULT;

 preempted:
    perfc_add(calls_from_multicall, i);
    mcs->flags = 0;
    return hypercall_create_continuation(
        __HYPERVISOR_multicall, "hi", call_list, nr_calls-i);
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
