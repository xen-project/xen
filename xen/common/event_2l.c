/*
 * Event channel port operations.
 *
 * Copyright (c) 2003-2006, K A Fraser.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/event.h>

static void evtchn_2l_set_pending(struct vcpu *v, struct evtchn *evtchn)
{
    struct domain *d = v->domain;
    unsigned int port = evtchn->port;

    /*
     * The following bit operations must happen in strict order.
     * NB. On x86, the atomic bit operations also act as memory barriers.
     * There is therefore sufficiently strict ordering for this architecture --
     * others may require explicit memory barriers.
     */

    if ( test_and_set_bit(port, &shared_info(d, evtchn_pending)) )
        return;

    if ( !test_bit        (port, &shared_info(d, evtchn_mask)) &&
         !test_and_set_bit(port / BITS_PER_EVTCHN_WORD(d),
                           &vcpu_info(v, evtchn_pending_sel)) )
    {
        vcpu_mark_events_pending(v);
    }

    evtchn_check_pollers(d, port);
}

static void evtchn_2l_clear_pending(struct domain *d, struct evtchn *evtchn)
{
    clear_bit(evtchn->port, &shared_info(d, evtchn_pending));
}

static void evtchn_2l_unmask(struct domain *d, struct evtchn *evtchn)
{
    struct vcpu *v = d->vcpu[evtchn->notify_vcpu_id];
    unsigned int port = evtchn->port;

    /*
     * These operations must happen in strict order. Based on
     * evtchn_2l_set_pending() above.
     */
    if ( test_and_clear_bit(port, &shared_info(d, evtchn_mask)) &&
         test_bit          (port, &shared_info(d, evtchn_pending)) &&
         !test_and_set_bit (port / BITS_PER_EVTCHN_WORD(d),
                            &vcpu_info(v, evtchn_pending_sel)) )
    {
        vcpu_mark_events_pending(v);
    }
}

static bool_t evtchn_2l_is_pending(struct domain *d, evtchn_port_t port)
{
    unsigned int max_ports = BITS_PER_EVTCHN_WORD(d) * BITS_PER_EVTCHN_WORD(d);

    ASSERT(port < max_ports);
    return port < max_ports && test_bit(port, &shared_info(d, evtchn_pending));
}

static bool_t evtchn_2l_is_masked(struct domain *d, evtchn_port_t port)
{
    unsigned int max_ports = BITS_PER_EVTCHN_WORD(d) * BITS_PER_EVTCHN_WORD(d);

    ASSERT(port < max_ports);
    return port >= max_ports || test_bit(port, &shared_info(d, evtchn_mask));
}

static void evtchn_2l_print_state(struct domain *d,
                                  const struct evtchn *evtchn)
{
    struct vcpu *v = d->vcpu[evtchn->notify_vcpu_id];

    printk("%d", !!test_bit(evtchn->port / BITS_PER_EVTCHN_WORD(d),
                            &vcpu_info(v, evtchn_pending_sel)));
}

static const struct evtchn_port_ops evtchn_port_ops_2l =
{
    .set_pending   = evtchn_2l_set_pending,
    .clear_pending = evtchn_2l_clear_pending,
    .unmask        = evtchn_2l_unmask,
    .is_pending    = evtchn_2l_is_pending,
    .is_masked     = evtchn_2l_is_masked,
    .print_state   = evtchn_2l_print_state,
};

void evtchn_2l_init(struct domain *d)
{
    d->evtchn_port_ops = &evtchn_port_ops_2l;
    d->max_evtchns = BITS_PER_EVTCHN_WORD(d) * BITS_PER_EVTCHN_WORD(d);
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
