#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

#include <asm/gic.h>
#include <asm/domain.h>

void vcpu_kick(struct vcpu *v);
void vcpu_mark_events_pending(struct vcpu *v);
void vcpu_block_unless_event_pending(struct vcpu *v);

static inline int vcpu_event_delivery_is_enabled(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;
    return !(regs->cpsr & PSR_IRQ_MASK);
}

static inline int local_events_need_delivery_nomask(void)
{
    struct pending_irq *p = irq_to_pending(current,
                                           current->domain->arch.evtchn_irq);

    /* XXX: if the first interrupt has already been delivered, we should
     * check whether any other interrupts with priority higher than the
     * one in GICV_IAR are in the lr_pending queue or in the LR
     * registers and return 1 only in that case.
     * In practice the guest interrupt handler should run with
     * interrupts disabled so this shouldn't be a problem in the general
     * case.
     */
    if ( gic_events_need_delivery() )
        return 1;

    if ( vcpu_info(current, evtchn_upcall_pending) &&
        list_empty(&p->inflight) )
        return 1;

    return 0;
}

static inline int local_events_need_delivery(void)
{
    if ( !vcpu_event_delivery_is_enabled(current) )
        return 0;
    return local_events_need_delivery_nomask();
}

static inline void local_event_delivery_enable(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    regs->cpsr &= ~PSR_IRQ_MASK;
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
