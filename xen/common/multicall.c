/******************************************************************************
 * multicall.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/multicall.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/hardirq.h>

struct mc_state mc_state[NR_CPUS];

long
do_multicall(
    GUEST_HANDLE(multicall_entry_t) call_list, unsigned int nr_calls)
{
    struct mc_state *mcs = &mc_state[smp_processor_id()];
    unsigned int     i;

    if ( unlikely(__test_and_set_bit(_MCSF_in_multicall, &mcs->flags)) )
    {
        DPRINTK("Multicall reentry is disallowed.\n");
        return -EINVAL;
    }

    if ( unlikely(!guest_handle_okay(call_list, nr_calls)) )
        goto fault;

    for ( i = 0; i < nr_calls; i++ )
    {
        if ( unlikely(__copy_from_guest_offset(&mcs->call, call_list, i, 1)) )
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
            (void)__copy_to_guest_offset(call_list, i, &corrupt, 1);
        }
#endif

        if ( unlikely(__copy_to_guest_offset(call_list, i, &mcs->call, 1)) )
            goto fault;

        if ( hypercall_preempt_check() )
        {
            /*
             * Copy the sub-call continuation if it was preempted.
             * Otherwise skip over the sub-call entirely.
             */
            if ( !test_bit(_MCSF_call_preempted, &mcs->flags) )
                i++;
            else
                (void)__copy_to_guest_offset(call_list, i, &mcs->call, 1);

            /* Only create a continuation if there is work left to be done. */
            if ( i < nr_calls )
            {
                mcs->flags = 0;
                guest_handle_add_offset(call_list, i);
                return hypercall_create_continuation(
                    __HYPERVISOR_multicall, "hi", call_list, nr_calls-i);
            }
        }
    }

    mcs->flags = 0;
    return 0;

 fault:
    mcs->flags = 0;
    return -EFAULT;
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
