/* Event channel handling private header. */

#include <xen/event.h>

static inline unsigned int max_evtchns(const struct domain *d)
{
    return d->evtchn_fifo ? EVTCHN_FIFO_NR_CHANNELS
                          : BITS_PER_EVTCHN_WORD(d) * BITS_PER_EVTCHN_WORD(d);
}

static inline bool evtchn_is_busy(const struct domain *d,
                                  const struct evtchn *evtchn)
{
    return d->evtchn_port_ops->is_busy &&
           d->evtchn_port_ops->is_busy(d, evtchn);
}

static inline void evtchn_port_unmask(struct domain *d,
                                      struct evtchn *evtchn)
{
    if ( evtchn_usable(evtchn) )
        d->evtchn_port_ops->unmask(d, evtchn);
}

static inline int evtchn_port_set_priority(struct domain *d,
                                           struct evtchn *evtchn,
                                           unsigned int priority)
{
    if ( !d->evtchn_port_ops->set_priority )
        return -ENOSYS;
    if ( !evtchn_usable(evtchn) )
        return -EACCES;
    return d->evtchn_port_ops->set_priority(d, evtchn, priority);
}

static inline void evtchn_port_print_state(struct domain *d,
                                           const struct evtchn *evtchn)
{
    d->evtchn_port_ops->print_state(d, evtchn);
}

/* 2-level */

void evtchn_2l_init(struct domain *d);

/* FIFO */

struct evtchn_init_control;
struct evtchn_expand_array;

int evtchn_fifo_init_control(struct evtchn_init_control *init_control);
int evtchn_fifo_expand_array(const struct evtchn_expand_array *expand_array);
void evtchn_fifo_destroy(struct domain *d);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
