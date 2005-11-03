/* NOTE: This file split off from evtchn.c because there was
   some discussion that the mechanism is sufficiently different.
   It may be possible to merge it back in the future... djm */
#include <linux/config.h>
#include <linux/kernel.h>
#include <asm/hw_irq.h>
#include <asm-xen/evtchn.h>

#define MAX_EVTCHN 256

#define VALID_EVTCHN(_chn) ((_chn) >= 0)

static struct {
	irqreturn_t (*handler)(int, void *, struct pt_regs *);
	void *dev_id;
} evtchns[MAX_EVTCHN];

int virq_to_evtchn[NR_VIRQS] = {-1};
unsigned int bind_virq_to_evtchn(int virq)
{
    evtchn_op_t op;

    op.cmd = EVTCHNOP_bind_virq;
    op.u.bind_virq.virq = virq;
    op.u.bind_virq.vcpu = 0;
    if ( HYPERVISOR_event_channel_op(&op) != 0 )
        BUG();

    virq_to_evtchn[virq] = op.u.bind_virq.port;
    return op.u.bind_virq.port;
}

int bind_virq_to_irq(int virq, int cpu)
{
	printk("bind_virq_to_irq called... FIXME??\n");
	while(1);
}

#if 0
void notify_remote_via_irq(int virq)
{
	printk("notify_remote_via_irq called... FIXME??\n");
	while(1);
}
#endif

void unbind_virq_from_evtchn(int virq)
{
    evtchn_op_t op;

    op.cmd = EVTCHNOP_close;
//    op.u.close.dom = DOMID_SELF;
    op.u.close.port = virq_to_evtchn[virq];
    if ( HYPERVISOR_event_channel_op(&op) != 0 )
	BUG();

    virq_to_evtchn[virq] = -1;
}

int bind_evtchn_to_irqhandler(unsigned int evtchn,
                   irqreturn_t (*handler)(int, void *, struct pt_regs *),
                   unsigned long irqflags, const char * devname, void *dev_id)
{
    if (evtchn >= MAX_EVTCHN)
        return -EINVAL;

    evtchns[evtchn].handler = handler;
    evtchns[evtchn].dev_id = dev_id;
    unmask_evtchn(evtchn);
    //return 0;
    /* On ia64, there's only one irq vector allocated for all event channels,
     * so let's just return evtchn as handle for later communication
     */
    return evtchn;
}

void unbind_evtchn_from_irqhandler(unsigned int evtchn, void *dev_id)
{
    if (evtchn >= MAX_EVTCHN)
        return;

    mask_evtchn(evtchn);
    evtchns[evtchn].handler = NULL;
}

void unbind_evtchn_from_irq(unsigned int evtchn)
{
	printk("unbind_evtchn_from_irq called... FIXME??\n");
	while(1);
}

void notify_remote_via_irq(int irq)
{
	int evtchn = virq_to_evtchn[irq];	// FIXME... is this right??

	if (VALID_EVTCHN(evtchn))
		notify_remote_via_evtchn(evtchn);
}

irqreturn_t evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned long  l1, l2;
    unsigned int   l1i, l2i, port;
    irqreturn_t (*handler)(int, void *, struct pt_regs *);
    shared_info_t *s = HYPERVISOR_shared_info;
    vcpu_info_t   *vcpu_info = &s->vcpu_data[smp_processor_id()];

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
    vcpu_info_t   *vcpu_info = &s->vcpu_data[smp_processor_id()];

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
}

/* Following are set of interfaces unused on IA64/XEN, just keep it here */

void bind_evtchn_to_cpu(unsigned int chn, unsigned int cpu) {}
int teardown_irq(unsigned int irq, struct irqaction * old) {return 0;}
