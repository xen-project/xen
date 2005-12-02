/* NOTE: This file split off from evtchn.c because there was
   some discussion that the mechanism is sufficiently different.
   It may be possible to merge it back in the future... djm */
#include <linux/config.h>
#include <linux/kernel.h>
#include <asm/hw_irq.h>
#include <asm-xen/evtchn.h>

#define MAX_EVTCHN 1024

/* Xen will never allocate port zero for any purpose. */
#define VALID_EVTCHN(_chn) (((_chn) != 0) && ((_chn) < MAX_EVTCHN))

/* Binding types. Hey, only IRQT_VIRQ and IRQT_EVTCHN are supported now
 * for XEN/IA64 - ktian1
 */
enum { IRQT_UNBOUND, IRQT_PIRQ, IRQT_VIRQ, IRQT_IPI, IRQT_EVTCHN };

/* Constructor for packed IRQ information. */
#define mk_irq_info(type, index, evtchn)				\
	(((u32)(type) << 24) | ((u32)(index) << 16) | (u32)(evtchn))
/* Convenient shorthand for packed representation of an unbound IRQ. */
#define IRQ_UNBOUND	mk_irq_info(IRQT_UNBOUND, 0, 0)
/* Accessor macros for packed IRQ information. */
#define evtchn_from_irq(irq) ((u16)(irq_info[irq]))
#define index_from_irq(irq)  ((u8)(irq_info[irq] >> 16))
#define type_from_irq(irq)   ((u8)(irq_info[irq] >> 24))

/* Packed IRQ information: binding type, sub-type index, and event channel. */
static u32 irq_info[NR_IRQS];

/* One note for XEN/IA64 is that we have all event channels bound to one
 * physical irq vector. So we always mean evtchn vector identical to 'irq'
 * vector in this context. - ktian1
 */
static struct {
	irqreturn_t (*handler)(int, void *, struct pt_regs *);
	void *dev_id;
	char opened;	/* Whether allocated */
} evtchns[MAX_EVTCHN];

/*
 * This lock protects updates to the following mapping and reference-count
 * arrays. The lock does not need to be acquired to read the mapping tables.
 */
static spinlock_t irq_mapping_update_lock;

#define unbound_irq(e) (VALID_EVTCHN(e) && (!evtchns[(e)].opened))
int bind_virq_to_irqhandler(
	unsigned int virq,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
    evtchn_op_t op;
    int evtchn;

    spin_lock(&irq_mapping_update_lock);

    op.cmd = EVTCHNOP_bind_virq;
    op.u.bind_virq.virq = virq;
    op.u.bind_virq.vcpu = cpu;
    BUG_ON(HYPERVISOR_event_channel_op(&op) != 0 );
    evtchn = op.u.bind_virq.port;

    if (!unbound_irq(evtchn))
	return -EINVAL;

    evtchns[evtchn].handler = handler;
    evtchns[evtchn].dev_id = dev_id;
    evtchns[evtchn].opened = 1;
    irq_info[evtchn] = mk_irq_info(IRQT_VIRQ, virq, evtchn);

    unmask_evtchn(evtchn);
    spin_unlock(&irq_mapping_update_lock);
    return evtchn;
}

int bind_evtchn_to_irqhandler(unsigned int evtchn,
                   irqreturn_t (*handler)(int, void *, struct pt_regs *),
                   unsigned long irqflags, const char * devname, void *dev_id)
{
    spin_lock(&irq_mapping_update_lock);

    if (!unbound_irq(evtchn))
	return -EINVAL;

    evtchns[evtchn].handler = handler;
    evtchns[evtchn].dev_id = dev_id;
    evtchns[evtchn].opened = 1;
    irq_info[evtchn] = mk_irq_info(IRQT_EVTCHN, 0, evtchn);

    unmask_evtchn(evtchn);
    spin_unlock(&irq_mapping_update_lock);
    return evtchn;
}

int bind_ipi_to_irqhandler(
	unsigned int ipi,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
    printk("%s is called which has not been supported now...?\n", __FUNCTION__);
    while(1);
}

void unbind_from_irqhandler(unsigned int irq, void *dev_id)
{
    evtchn_op_t op;
    int evtchn = evtchn_from_irq(irq);

    spin_lock(&irq_mapping_update_lock);

    if (unbound_irq(irq))
        return;

    op.cmd = EVTCHNOP_close;
    op.u.close.port = evtchn;
    BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);

    switch (type_from_irq(irq)) {
	case IRQT_VIRQ:
	    /* Add smp stuff later... */
	    break;
	case IRQT_IPI:
	    /* Add smp stuff later... */
	    break;
	default:
	    break;
    }

    mask_evtchn(evtchn);
    evtchns[evtchn].handler = NULL;
    evtchns[evtchn].opened = 0;

    spin_unlock(&irq_mapping_update_lock);
}

void notify_remote_via_irq(int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (!unbound_irq(evtchn))
		notify_remote_via_evtchn(evtchn);
}

irqreturn_t evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned long  l1, l2;
    unsigned int   l1i, l2i, port;
    irqreturn_t (*handler)(int, void *, struct pt_regs *);
    shared_info_t *s = HYPERVISOR_shared_info;
    vcpu_info_t   *vcpu_info = &s->vcpu_info[smp_processor_id()];

    vcpu_info->evtchn_upcall_mask = 1;
    vcpu_info->evtchn_upcall_pending = 0;

    /* NB. No need for a barrier here -- XCHG is a barrier on x86. */
    l1 = xchg(&vcpu_info->evtchn_pending_sel, 0);
    while ( l1 != 0 )
    {
        l1i = __ffs(l1);
        l1 &= ~(1UL << l1i);

        while ( (l2 = s->evtchn_pending[l1i] & ~s->evtchn_mask[l1i]) != 0 )
        {
            l2i = __ffs(l2);
            l2 &= ~(1UL << l2i);

            port = (l1i * BITS_PER_LONG) + l2i;
            if ( (handler = evtchns[port].handler) != NULL )
	    {
		clear_evtchn(port);
                handler(port, evtchns[port].dev_id, regs);
	    }
            else
	    {
                evtchn_device_upcall(port);
	    }
        }
    }
    vcpu_info->evtchn_upcall_mask = 0;
    return IRQ_HANDLED;
}

void force_evtchn_callback(void)
{
	//(void)HYPERVISOR_xen_version(0, NULL);
}

static struct irqaction evtchn_irqaction = {
	.handler =	evtchn_interrupt,
	.flags =	SA_INTERRUPT,
	.name =		"xen-event-channel"
};

int evtchn_irq = 0xe9;
void __init evtchn_init(void)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    vcpu_info_t   *vcpu_info = &s->vcpu_info[smp_processor_id()];

#if 0
    int ret;
    irq = assign_irq_vector(AUTO_ASSIGN);
    ret = request_irq(irq, evtchn_interrupt, 0, "xen-event-channel", NULL);
    if (ret < 0)
    {
	printk("xen-event-channel unable to get irq %d (%d)\n", irq, ret);
	return;
    }
#endif
    register_percpu_irq(evtchn_irq, &evtchn_irqaction);

    vcpu_info->arch.evtchn_vector = evtchn_irq;
    printk("xen-event-channel using irq %d\n", evtchn_irq);

    spin_lock_init(&irq_mapping_update_lock);
    memset(evtchns, 0, sizeof(evtchns));
}
