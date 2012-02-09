#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

void vcpu_kick(struct vcpu *v);
void vcpu_mark_events_pending(struct vcpu *v);

static inline int local_events_need_delivery(void)
{
    /* TODO
     * return (vcpu_info(v, evtchn_upcall_pending) &&
                        !vcpu_info(v, evtchn_upcall_mask)); */
        return 0;
}

int local_event_delivery_is_enabled(void);

static inline void local_event_delivery_disable(void)
{
    /* TODO current->vcpu_info->evtchn_upcall_mask = 1; */
}

static inline void local_event_delivery_enable(void)
{
    /* TODO current->vcpu_info->evtchn_upcall_mask = 0; */
}

/* No arch specific virq definition now. Default to global. */
static inline int arch_virq_is_global(int virq)
{
    return 1;
}

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
