/******************************************************************************
 * evtchn.c
 * 
 * Communication via Xen event channels.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/hypervisor.h>
#include <asm/hypervisor-ifs/event_channel.h>

/* Dynamic IRQ <-> event-channel mappings. */
static int evtchn_to_dynirq[1024];
static int dynirq_to_evtchn[NR_IRQS];

/* Dynamic IRQ <-> VIRQ mapping. */
static int virq_to_dynirq[NR_VIRQS];

/*
 * Reference counts for bindings to dynamic IRQs.
 * NB. This array is referenced with respect to DYNIRQ_BASE!
 */
static int dynirq_bindcount[NR_DYNIRQS];
static spinlock_t dynirq_lock;

/* Upcall to generic IRQ layer. */
extern asmlinkage unsigned int do_IRQ(int irq, struct pt_regs *regs);

static void evtchn_handle_normal(shared_info_t *s, struct pt_regs *regs)
{
    unsigned long l1, l2;
    unsigned int  l1i, l2i, port;
    int           dynirq;

    l1 = xchg(&s->evtchn_pending_sel, 0);
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
            if ( (dynirq = evtchn_to_dynirq[port]) != -1 )
                do_IRQ(dynirq + DYNIRQ_BASE, regs);
            else
                evtchn_device_upcall(port, 0);
        }
    }
}

static void evtchn_handle_exceptions(shared_info_t *s, struct pt_regs *regs)
{
    unsigned long l1, l2;
    unsigned int  l1i, l2i, port;
    int           dynirq;

    l1 = xchg(&s->evtchn_exception_sel, 0);
    while ( (l1i = ffs(l1)) != 0 )
    {
        l1i--;
        l1 &= ~(1 << l1i);
        
        l2 = s->evtchn_exception[l1i] & ~s->evtchn_mask[l1i];
        while ( (l2i = ffs(l2)) != 0 )
        {
            l2i--;
            l2 &= ~(1 << l2i);
            
            port = (l1i << 5) + l2i;
            if ( (dynirq = evtchn_to_dynirq[port]) != -1 )
            {
                printk(KERN_ALERT "Error on IRQ line %d!\n", 
                       dynirq + DYNIRQ_BASE);
                clear_bit(port, &s->evtchn_exception[0]);
            }
            else
                evtchn_device_upcall(port, 1);
        }
    }
}

void evtchn_do_upcall(struct pt_regs *regs)
{
    unsigned long flags;
    shared_info_t *s = HYPERVISOR_shared_info;

    local_irq_save(flags);
    
    while ( test_and_clear_bit(0, &s->evtchn_upcall_pending) )
    {
        if ( s->evtchn_pending_sel != 0 )
            evtchn_handle_normal(s, regs);
        if ( s->evtchn_exception_sel != 0 )
            evtchn_handle_exceptions(s, regs);
    }

    local_irq_restore(flags);
}


static int find_unbound_dynirq(void)
{
    int i;

    for ( i = 0; i < NR_DYNIRQS; i++ )
        if ( dynirq_bindcount[i] == 0 )
            break;

    if ( i == NR_DYNIRQS )
        BUG();

    return i;
}

int bind_virq_to_irq(int virq)
{
    evtchn_op_t op;
    int evtchn, dynirq;

    spin_lock(&dynirq_lock);

    if ( (dynirq = virq_to_dynirq[virq]) == -1 )
    {
        op.cmd              = EVTCHNOP_bind_virq;
        op.u.bind_virq.virq = virq;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            BUG();
        evtchn = op.u.bind_virq.port;

        dynirq = find_unbound_dynirq();
        evtchn_to_dynirq[evtchn] = dynirq;
        dynirq_to_evtchn[dynirq] = evtchn;

        virq_to_dynirq[virq] = dynirq;
    }

    dynirq_bindcount[dynirq]++;

    spin_unlock(&dynirq_lock);
    
    return dynirq + DYNIRQ_BASE;
}

void unbind_virq_from_irq(int virq)
{
    evtchn_op_t op;
    int dynirq = virq_to_dynirq[virq];
    int evtchn = dynirq_to_evtchn[dynirq];

    spin_lock(&dynirq_lock);

    if ( --dynirq_bindcount[dynirq] == 0 )
    {
        op.cmd          = EVTCHNOP_close;
        op.u.close.dom  = DOMID_SELF;
        op.u.close.port = evtchn;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            BUG();

        evtchn_to_dynirq[evtchn] = -1;
        dynirq_to_evtchn[dynirq] = -1;
        virq_to_dynirq[virq]     = -1;
    }

    spin_unlock(&dynirq_lock);
}

int bind_evtchn_to_irq(int evtchn)
{
    int dynirq;

    spin_lock(&dynirq_lock);

    if ( (dynirq = evtchn_to_dynirq[evtchn]) == -1 )
    {
        dynirq = find_unbound_dynirq();
        evtchn_to_dynirq[evtchn] = dynirq;
        dynirq_to_evtchn[dynirq] = evtchn;
    }

    dynirq_bindcount[dynirq]++;

    spin_unlock(&dynirq_lock);
    
    return dynirq + DYNIRQ_BASE;
}

void unbind_evtchn_from_irq(int evtchn)
{
    int dynirq = evtchn_to_dynirq[evtchn];

    spin_lock(&dynirq_lock);

    if ( --dynirq_bindcount[dynirq] == 0 )
    {
        evtchn_to_dynirq[evtchn] = -1;
        dynirq_to_evtchn[dynirq] = -1;
    }

    spin_unlock(&dynirq_lock);
}


/*
 * Interface to generic handling in irq.c
 */

static unsigned int startup_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    unmask_evtchn(dynirq_to_evtchn[dynirq]);
    return 0;
}

static void shutdown_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    mask_evtchn(dynirq_to_evtchn[dynirq]);
}

static void enable_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    unmask_evtchn(dynirq_to_evtchn[dynirq]);
}

static void disable_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    mask_evtchn(dynirq_to_evtchn[dynirq]);
}

static void ack_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    mask_evtchn(dynirq_to_evtchn[dynirq]);
    clear_evtchn(dynirq_to_evtchn[dynirq]);
}

static void end_dynirq(unsigned int irq)
{
    int dynirq = irq - DYNIRQ_BASE;
    if ( !(irq_desc[irq].status & IRQ_DISABLED) )
        unmask_evtchn(dynirq_to_evtchn[dynirq]);
}

static struct hw_interrupt_type dynirq_type = {
    "Dynamic-irq",
    startup_dynirq,
    shutdown_dynirq,
    enable_dynirq,
    disable_dynirq,
    ack_dynirq,
    end_dynirq,
    NULL
};

static void error_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    printk(KERN_ALERT "unexpected VIRQ_ERROR trap to vector %d\n", irq);
}

static struct irqaction error_action = {
    error_interrupt, 
    SA_INTERRUPT, 
    0, 
    "error", 
    NULL, 
    NULL
};

void __init init_IRQ(void)
{
    int i;

    for ( i = 0; i < NR_VIRQS; i++ )
        virq_to_dynirq[i] = -1;

    for ( i = 0; i < 1024; i++ )
        evtchn_to_dynirq[i] = -1;

    for ( i = 0; i < NR_DYNIRQS; i++ )
    {
        dynirq_to_evtchn[i] = -1;
        dynirq_bindcount[i] = 0;
    }

    spin_lock_init(&dynirq_lock);

    for ( i = 0; i < NR_DYNIRQS; i++ )
    {
        irq_desc[i + DYNIRQ_BASE].status  = IRQ_DISABLED;
        irq_desc[i + DYNIRQ_BASE].action  = 0;
        irq_desc[i + DYNIRQ_BASE].depth   = 1;
        irq_desc[i + DYNIRQ_BASE].handler = &dynirq_type;
    }

    (void)setup_irq(bind_virq_to_irq(VIRQ_ERROR), &error_action);
    
#ifdef CONFIG_PCI
    /* Also initialise the physical IRQ handlers. */
    physirq_init();
#endif
}
