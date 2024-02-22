/****************************************************************************
 * schedule.c
 *
 */

#ifndef __COMMON_SCHED_COMPAT_C__
#define __COMMON_SCHED_COMPAT_C__


#include <compat/sched.h>

#define COMPAT
#define ret_t int

#define do_sched_op compat_sched_op

#define xen_sched_pin_override sched_pin_override
CHECK_sched_pin_override;
#undef xen_sched_pin_override

#define xen_sched_shutdown sched_shutdown
CHECK_sched_shutdown;
#undef xen_sched_shutdown

#define xen_sched_remote_shutdown sched_remote_shutdown
CHECK_sched_remote_shutdown;
#undef xen_sched_remote_shutdown

static int compat_poll(const struct compat_sched_poll *compat)
{
    struct sched_poll native;

#define XLAT_sched_poll_HNDL_ports(_d_, _s_) \
    guest_from_compat_handle((_d_)->ports, (_s_)->ports)
    XLAT_sched_poll(&native, compat);
#undef XLAT_sched_poll_HNDL_ports

    return do_poll(&native);
}

#define do_poll compat_poll
#define sched_poll compat_sched_poll

#include "core.c"

int compat_set_timer_op(uint32_t lo, uint32_t hi)
{
    return do_set_timer_op(((uint64_t)hi << 32) | lo);
}

#endif /* __COMMON_SCHED_COMPAT_C__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
