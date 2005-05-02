/******************************************************************************
 * evtchn.c
 * 
 * Communication via Xen event channels.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <machine/cpufunc.h>
#include <machine/intr_machdep.h>
#include <machine/xen-os.h>
#include <machine/xen_intr.h>
#include <machine/synch_bitops.h>
#include <machine/evtchn.h>
#include <machine/hypervisor.h>
#include <machine/hypervisor-ifs.h>


static struct mtx irq_mapping_update_lock;

#define TODO            printf("%s: not implemented!\n", __func__) 

/* IRQ <-> event-channel mappings. */
static int evtchn_to_irq[NR_EVENT_CHANNELS];
static int irq_to_evtchn[NR_IRQS];

static int virq_to_irq[MAX_VIRT_CPUS][NR_VIRQS];
static int ipi_to_evtchn[MAX_VIRT_CPUS][NR_VIRQS];


/* Reference counts for bindings to IRQs. */
static int irq_bindcount[NR_IRQS];

#define VALID_EVTCHN(_chn) ((_chn) != -1)

/*
 * Force a proper event-channel callback from Xen after clearing the
 * callback mask. We do this in a very simple manner, by making a call
 * down into Xen. The pending flag will be checked by Xen on return.
 */
void force_evtchn_callback(void)
{
    (void)HYPERVISOR_xen_version(0);
}

void 
evtchn_do_upcall(struct intrframe *frame) 
{
    unsigned long  l1, l2;
    unsigned int   l1i, l2i, port;
    int            irq, owned;
    unsigned long  flags;
    shared_info_t *s = HYPERVISOR_shared_info;
    vcpu_info_t   *vcpu_info = &s->vcpu_data[smp_processor_id()];

    local_irq_save(flags);

    while ( s->vcpu_data[0].evtchn_upcall_pending )
    {
        s->vcpu_data[0].evtchn_upcall_pending = 0;
        /* NB. No need for a barrier here -- XCHG is a barrier on x86. */
        l1 = xen_xchg(&vcpu_info->evtchn_pending_sel, 0);
        while ( (l1i = ffs(l1)) != 0 )
        {
            l1i--;
            l1 &= ~(1 << l1i);
        
            l2 = s->evtchn_pending[l1i] & ~s->evtchn_mask[l1i];
            while ( (l2i = ffs(l2)) != 0 )
            {
                l2i--;
                l2 &= ~(1 << l2i);
            
                port = (l1i << 5) + l2i;
                if ( (owned = mtx_owned(&sched_lock)) != 0 )
                    mtx_unlock_spin_flags(&sched_lock, MTX_QUIET);
                if ( (irq = evtchn_to_irq[port]) != -1 ) {
		    struct intsrc *isrc = intr_lookup_source(irq);
		    intr_execute_handlers(isrc, frame);
		} else {
                    evtchn_device_upcall(port);
		}
                if ( owned )
                    mtx_lock_spin_flags(&sched_lock, MTX_QUIET);                    
            }
        }
    }

    local_irq_restore(flags);

}


static int 
find_unbound_irq(void)
{
    int irq;

    for ( irq = 0; irq < NR_IRQS; irq++ )
        if ( irq_bindcount[irq] == 0 )
            break;

    if ( irq == NR_IRQS )
        panic("No available IRQ to bind to: increase NR_IRQS!\n");

    return irq;
}

int 
bind_virq_to_irq(int virq)
{
    evtchn_op_t op;
    int evtchn, irq;

    mtx_lock(&irq_mapping_update_lock);

    if ( (irq = PCPU_GET(virq_to_irq)[virq]) == -1 )
    {
        op.cmd              = EVTCHNOP_bind_virq;
        op.u.bind_virq.virq = virq;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IRQ %d\n", virq);
        evtchn = op.u.bind_virq.port;

        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        PCPU_GET(virq_to_irq)[virq] = irq;
    }

    irq_bindcount[irq]++;

    mtx_unlock(&irq_mapping_update_lock);
    
    return irq;
}

void 
unbind_virq_from_irq(int virq)
{
    evtchn_op_t op;
    int irq    = PCPU_GET(virq_to_irq)[virq];
    int evtchn = irq_to_evtchn[irq];

    mtx_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
        op.cmd          = EVTCHNOP_close;
        op.u.close.dom  = DOMID_SELF;
        op.u.close.port = evtchn;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to unbind virtual IRQ %d\n", virq);

        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
        PCPU_GET(virq_to_irq)[virq]     = -1;
    }

    mtx_unlock(&irq_mapping_update_lock);
}


int 
bind_ipi_on_cpu_to_irq(int cpu, int ipi)
{
    evtchn_op_t op;
    int evtchn, irq;

    mtx_lock(&irq_mapping_update_lock);

    if ( (evtchn = PCPU_GET(ipi_to_evtchn)[ipi]) == 0 )
    {
        op.cmd                 = EVTCHNOP_bind_ipi;
        op.u.bind_ipi.ipi_edom = cpu;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IPI %d on cpu %d\n", ipi, cpu);
        evtchn = op.u.bind_ipi.port;

        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        PCPU_GET(ipi_to_evtchn)[ipi] = evtchn;
    } else
	irq = evtchn_to_irq[evtchn];

    irq_bindcount[irq]++;

    mtx_unlock(&irq_mapping_update_lock);

    return irq;
}

void 
unbind_ipi_on_cpu_from_irq(int cpu, int ipi)
{
    evtchn_op_t op;
    int evtchn = PCPU_GET(ipi_to_evtchn)[ipi];
    int irq    = irq_to_evtchn[evtchn];

    mtx_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
	op.cmd          = EVTCHNOP_close;
	op.u.close.dom  = DOMID_SELF;
	op.u.close.port = evtchn;
	if ( HYPERVISOR_event_channel_op(&op) != 0 )
	    panic("Failed to unbind virtual IPI %d on cpu %d\n", ipi, cpu);

        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
	PCPU_GET(ipi_to_evtchn)[ipi] = 0;
    }

    mtx_unlock(&irq_mapping_update_lock);
}

int 
bind_evtchn_to_irq(int evtchn)
{
    int irq;

    mtx_lock(&irq_mapping_update_lock);

    if ( (irq = evtchn_to_irq[evtchn]) == -1 )
    {
        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;
    }

    irq_bindcount[irq]++;

    mtx_unlock(&irq_mapping_update_lock);
    
    return irq;
}

void 
unbind_evtchn_from_irq(int evtchn)
{
    int irq = evtchn_to_irq[evtchn];

    mtx_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
    }

    mtx_unlock(&irq_mapping_update_lock);
}


/*
 * Interface to generic handling in intr_machdep.c
 */


/*------------ interrupt handling --------------------------------------*/
#define TODO            printf("%s: not implemented!\n", __func__) 

 struct mtx xenpic_lock;

struct xenpic_intsrc {
    struct intsrc xp_intsrc;
    uint8_t       xp_vector;
    boolean_t	  xp_masked;
};

struct xenpic { 
    struct pic xp_pic; /* this MUST be first */
    uint16_t xp_numintr; 
    struct xenpic_intsrc xp_pins[0]; 
}; 

static void     xenpic_enable_dynirq_source(struct intsrc *isrc); 
static void     xenpic_disable_dynirq_source(struct intsrc *isrc, int); 
static void     xenpic_eoi_source(struct intsrc *isrc); 
static void     xenpic_enable_dynirq_intr(struct intsrc *isrc); 
static int      xenpic_vector(struct intsrc *isrc); 
static int      xenpic_source_pending(struct intsrc *isrc); 
static void     xenpic_suspend(struct intsrc *isrc); 
static void     xenpic_resume(struct intsrc *isrc); 


struct pic xenpic_template  =  { 
    xenpic_enable_dynirq_source, 
    xenpic_disable_dynirq_source,
    xenpic_eoi_source, 
    xenpic_enable_dynirq_intr, 
    xenpic_vector, 
    xenpic_source_pending,
    xenpic_suspend, 
    xenpic_resume 
};


void 
xenpic_enable_dynirq_source(struct intsrc *isrc)
{
    unsigned int irq;
    struct xenpic_intsrc *xp;

    xp = (struct xenpic_intsrc *)isrc;

    if (xp->xp_masked) {
	irq = xenpic_vector(isrc);
	unmask_evtchn(irq_to_evtchn[irq]);
	xp->xp_masked = FALSE;
    }
}

static void 
xenpic_disable_dynirq_source(struct intsrc *isrc, int foo)
{
    unsigned int irq;
    struct xenpic_intsrc *xp;

    xp = (struct xenpic_intsrc *)isrc;

    if (!xp->xp_masked) {
	irq = xenpic_vector(isrc);
	mask_evtchn(irq_to_evtchn[irq]);
	xp->xp_masked = TRUE;
    }

}

static void 
xenpic_enable_dynirq_intr(struct intsrc *isrc)
{
    unsigned int irq;

    irq = xenpic_vector(isrc);
    unmask_evtchn(irq_to_evtchn[irq]);
}

static void 
xenpic_eoi_source(struct intsrc *isrc)
{
    unsigned int irq = xenpic_vector(isrc);
    clear_evtchn(irq_to_evtchn[irq]);
}

static int
xenpic_vector(struct intsrc *isrc)
{
    struct xenpic_intsrc *pin = (struct xenpic_intsrc *)isrc;
    return (pin->xp_vector);
}

static int
xenpic_source_pending(struct intsrc *isrc)
{
    TODO;
    return 0;
}

static void 
xenpic_suspend(struct intsrc *isrc) 
{ 
    TODO; 
} 
 
static void 
xenpic_resume(struct intsrc *isrc) 
{ 
    TODO; 
} 

#ifdef CONFIG_PHYSDEV
/* required for support of physical devices */
static inline void 
pirq_unmask_notify(int pirq)
{
    physdev_op_t op;
    if ( unlikely(test_bit(pirq, &pirq_needs_unmask_notify[0])) )
    {
        op.cmd = PHYSDEVOP_IRQ_UNMASK_NOTIFY;
        (void)HYPERVISOR_physdev_op(&op);
    }
}

static inline void 
pirq_query_unmask(int pirq)
{
    physdev_op_t op;
    op.cmd = PHYSDEVOP_IRQ_STATUS_QUERY;
    op.u.irq_status_query.irq = pirq;
    (void)HYPERVISOR_physdev_op(&op);
    clear_bit(pirq, &pirq_needs_unmask_notify[0]);
    if ( op.u.irq_status_query.flags & PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY )
        set_bit(pirq, &pirq_needs_unmask_notify[0]);
}

/*
 * On startup, if there is no action associated with the IRQ then we are
 * probing. In this case we should not share with others as it will confuse us.
 */
#define probing_irq(_irq) (irq_desc[(_irq)].action == NULL)

static unsigned int startup_pirq(unsigned int irq)
{
    evtchn_op_t op;
    int evtchn;

    op.cmd               = EVTCHNOP_bind_pirq;
    op.u.bind_pirq.pirq  = irq;
    /* NB. We are happy to share unless we are probing. */
    op.u.bind_pirq.flags = probing_irq(irq) ? 0 : BIND_PIRQ__WILL_SHARE;
    if ( HYPERVISOR_event_channel_op(&op) != 0 )
    {
        if ( !probing_irq(irq) ) /* Some failures are expected when probing. */
            printk(KERN_INFO "Failed to obtain physical IRQ %d\n", irq);
        return 0;
    }
    evtchn = op.u.bind_pirq.port;

    pirq_query_unmask(irq_to_pirq(irq));

    evtchn_to_irq[evtchn] = irq;
    irq_to_evtchn[irq]    = evtchn;

    unmask_evtchn(evtchn);
    pirq_unmask_notify(irq_to_pirq(irq));

    return 0;
}

static void shutdown_pirq(unsigned int irq)
{
    evtchn_op_t op;
    int evtchn = irq_to_evtchn[irq];

    if ( !VALID_EVTCHN(evtchn) )
        return;

    mask_evtchn(evtchn);

    op.cmd          = EVTCHNOP_close;
    op.u.close.dom  = DOMID_SELF;
    op.u.close.port = evtchn;
    if ( HYPERVISOR_event_channel_op(&op) != 0 )
        panic("Failed to unbind physical IRQ %d\n", irq);

    evtchn_to_irq[evtchn] = -1;
    irq_to_evtchn[irq]    = -1;
}

static void enable_pirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];
    if ( !VALID_EVTCHN(evtchn) )
        return;
    unmask_evtchn(evtchn);
    pirq_unmask_notify(irq_to_pirq(irq));
}

static void disable_pirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];
    if ( !VALID_EVTCHN(evtchn) )
        return;
    mask_evtchn(evtchn);
}

static void ack_pirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];
    if ( !VALID_EVTCHN(evtchn) )
        return;
    mask_evtchn(evtchn);
    clear_evtchn(evtchn);
}

static void end_pirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];
    if ( !VALID_EVTCHN(evtchn) )
        return;
    if ( !(irq_desc[irq].status & IRQ_DISABLED) )
    {
        unmask_evtchn(evtchn);
        pirq_unmask_notify(irq_to_pirq(irq));
    }
}

static struct hw_interrupt_type pirq_type = {
    "Phys-irq",
    startup_pirq,
    shutdown_pirq,
    enable_pirq,
    disable_pirq,
    ack_pirq,
    end_pirq,
    NULL
};
#endif

#if 0
static void 
misdirect_interrupt(void *sc)
{
}
#endif
void irq_suspend(void)
{
    int virq, irq, evtchn;

    /* Unbind VIRQs from event channels. */
    for ( virq = 0; virq < NR_VIRQS; virq++ )
    {
        if ( (irq = PCPU_GET(virq_to_irq)[virq]) == -1 )
            continue;
        evtchn = irq_to_evtchn[irq];

        /* Mark the event channel as unused in our table. */
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
    }

    /*
     * We should now be unbound from all event channels. Stale bindings to 
     * PIRQs and/or inter-domain event channels will cause us to barf here.
     */
    for ( evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++ )
        if ( evtchn_to_irq[evtchn] != -1 )
            panic("Suspend attempted while bound to evtchn %d.\n", evtchn);
}


void irq_resume(void)
{
    evtchn_op_t op;
    int         virq, irq, evtchn;

    for ( evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++ )
        mask_evtchn(evtchn); /* New event-channel space is not 'live' yet. */

    for ( virq = 0; virq < NR_VIRQS; virq++ )
    {
        if ( (irq = PCPU_GET(virq_to_irq)[virq]) == -1 )
            continue;

        /* Get a new binding from Xen. */
        op.cmd              = EVTCHNOP_bind_virq;
        op.u.bind_virq.virq = virq;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IRQ %d\n", virq);
        evtchn = op.u.bind_virq.port;
        
        /* Record the new mapping. */
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        /* Ready for use. */
        unmask_evtchn(evtchn);
    }
}

void
ap_evtchn_init(int cpu)
{
    int i;

    /* XXX -- expedience hack */
    PCPU_SET(virq_to_irq, (int  *)&virq_to_irq[cpu]);
    PCPU_SET(ipi_to_evtchn, (int *)&ipi_to_evtchn[cpu]);

    /* No VIRQ -> IRQ mappings. */
    for ( i = 0; i < NR_VIRQS; i++ )
        PCPU_GET(virq_to_irq)[i] = -1;
}

static void 
evtchn_init(void *dummy __unused)
{
    int i;
    struct xenpic *xp;
    struct xenpic_intsrc *pin;

    /*
     * xenpic_lock: in order to allow an interrupt to occur in a critical
     * 	        section, to set pcpu->ipending (etc...) properly, we
     *	        must be able to get the icu lock, so it can't be
     *	        under witness.
     */
    mtx_init(&irq_mapping_update_lock, "xp", NULL, MTX_DEF);

    /* XXX -- expedience hack */
    PCPU_SET(virq_to_irq, (int *)&virq_to_irq[0]);
    PCPU_SET(ipi_to_evtchn, (int *)&ipi_to_evtchn[0]);

    /* No VIRQ -> IRQ mappings. */
    for ( i = 0; i < NR_VIRQS; i++ )
        PCPU_GET(virq_to_irq)[i] = -1;

    /* No event-channel -> IRQ mappings. */
    for ( i = 0; i < NR_EVENT_CHANNELS; i++ )
    {
        evtchn_to_irq[i] = -1;
        mask_evtchn(i); /* No event channels are 'live' right now. */
    }

    /* No IRQ -> event-channel mappings. */
    for ( i = 0; i < NR_IRQS; i++ )
        irq_to_evtchn[i] = -1;

    xp = malloc(sizeof(struct xenpic) + NR_DYNIRQS*sizeof(struct xenpic_intsrc), M_DEVBUF, M_WAITOK);
    xp->xp_pic = xenpic_template;
    xp->xp_numintr = NR_DYNIRQS;
    bzero(xp->xp_pins, sizeof(struct xenpic_intsrc) * NR_DYNIRQS);

    for ( i = 0, pin = xp->xp_pins; i < NR_DYNIRQS; i++, pin++ )
    {
        /* Dynamic IRQ space is currently unbound. Zero the refcnts. */
        irq_bindcount[dynirq_to_irq(i)] = 0;

	pin->xp_intsrc.is_pic = (struct pic *)xp;
	pin->xp_vector = i;
	intr_register_source(&pin->xp_intsrc);
    }
    /* We don't currently have any support for physical devices in XenoFreeBSD 
     * so leaving this out for the moment for the sake of expediency.
     */
#ifdef notyet
    for ( i = 0; i < NR_PIRQS; i++ )
    {
        /* Phys IRQ space is statically bound (1:1 mapping). Nail refcnts. */
        irq_bindcount[pirq_to_irq(i)] = 1;

        irq_desc[pirq_to_irq(i)].status  = IRQ_DISABLED;
        irq_desc[pirq_to_irq(i)].action  = 0;
        irq_desc[pirq_to_irq(i)].depth   = 1;
        irq_desc[pirq_to_irq(i)].handler = &pirq_type;
    }

#endif
#if 0
    (void) intr_add_handler("xb_mis", bind_virq_to_irq(VIRQ_MISDIRECT),
	    	            (driver_intr_t *)misdirect_interrupt, 
			    NULL, INTR_TYPE_MISC, NULL);

#endif
}

SYSINIT(evtchn_init, SI_SUB_INTR, SI_ORDER_ANY, evtchn_init, NULL);
