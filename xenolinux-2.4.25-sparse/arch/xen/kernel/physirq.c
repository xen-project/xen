/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: physirq.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Mar 2004
 * 
 * Description: guests may receive virtual interrupts directly 
 *              corresponding to physical interrupts. these virtual
 *              interrupts require special handling provided 
 *              by the virq irq type.
 */

#ifdef CONFIG_PCI

#include <linux/config.h>
#include <asm/atomic.h>
#include <asm/irq.h>
#include <asm/hypervisor.h>
#include <asm/system.h>

#include <linux/irq.h>
#include <linux/sched.h>

#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/hypervisor-ifs/physdev.h>

static void physirq_interrupt(int irq, void *unused, struct pt_regs *ptregs);

static int setup_event_handler = 0;

static unsigned int startup_physirq_event(unsigned int irq)
{
    physdev_op_t op;
    int err;

    printk("startup_physirq_event %d\n", irq);

    /*
     * install a interrupt handler for physirq event when called first time
     * we actually are never executing the handler as _EVENT_PHYSIRQ is 
     * handled specially in hypervisor.c But we need to enable the event etc.
     */
    if ( !setup_event_handler )
    {
        printk("startup_physirq_event %d: setup event handler\n", irq);
        /* set up a event handler to demux virtualised physical interrupts */
        err = request_irq(IRQ_FROM_XEN_VIRQ(VIRQ_PHYSIRQ), physirq_interrupt, 
                          SA_SAMPLE_RANDOM, "physirq", NULL);
        if ( err )
        {
            printk(KERN_WARNING "Could not allocate physirq interrupt\n");
            return err;
        }
        setup_event_handler = 1;
    }

    /*
     * request the irq from hypervisor
     */
    op.cmd = PHYSDEVOP_REQUEST_IRQ;
    op.u.request_irq.irq   = irq;
    if ( (err = HYPERVISOR_physdev_op(&op)) != 0 )
    {
        printk(KERN_ALERT "could not get IRQ %d from Xen\n", irq);
        return err;
    }
    return 0;
}
/*
 * This is a dummy interrupt handler.
 * It should never be called. events for physical interrupts are handled
 * differently in hypervisor.c
 */
static void physirq_interrupt(int irq, void *unused, struct pt_regs *ptregs)
{
    printk("XXX This should never be called!");
}


/*
 * IRQ is not needed anymore.
 */
static void shutdown_physirq_event(unsigned int irq)
{
    physdev_op_t op;
    int err;

    printk("shutdown_phys_irq called.");

    /*
     * tell hypervisor
     */
    op.cmd = PHYSDEVOP_FREE_IRQ;
    op.u.free_irq.irq   = irq;
    if ( (err = HYPERVISOR_physdev_op(&op)) != 0 )
    {
        printk(KERN_ALERT "could not free IRQ %d\n", irq);
        return;
    }
    return;
}


static void enable_physirq_event(unsigned int irq)
{
    /* XXX just enable all phys interrupts for now */
    enable_irq(IRQ_FROM_XEN_VIRQ(VIRQ_PHYSIRQ));
}

static void disable_physirq_event(unsigned int irq)
{
    /* XXX just disable all phys interrupts for now */
    disable_irq(IRQ_FROM_XEN_VIRQ(VIRQ_PHYSIRQ));
}

static void ack_physirq_event(unsigned int irq)
{
    /* clear bit */
    if ( irq <= 0 || irq >= 32 )
    {
        printk("wrong irq %d\n", irq);
    }

    clear_bit(irq, &HYPERVISOR_shared_info->physirq_pend);
}

static void end_physirq_event(unsigned int irq)
{
    int err;
    physdev_op_t op;

    /* call hypervisor */
    op.cmd = PHYSDEVOP_FINISHED_IRQ;
    op.u.finished_irq.irq   = irq;
    if ( (err = HYPERVISOR_physdev_op(&op)) != 0 )
    {
        printk(KERN_ALERT "could not finish IRQ %d\n", irq);
        return;
    }
    return;
}

static struct hw_interrupt_type physirq_irq_type = {
    "physical-irq",
    startup_physirq_event,
    shutdown_physirq_event,
    enable_physirq_event,
    disable_physirq_event,
    ack_physirq_event,
    end_physirq_event,
    NULL
};



void __init physirq_init(void)
{
    int i;

    printk("Initialise irq handlers [%d-%d] for physical interrupts.\n",
           PHYS_IRQ_BASE, PHYS_IRQ_BASE+NR_PHYS_IRQS-1);

    for ( i = 0; i < NR_PHYS_IRQS; i++ )
    {
        irq_desc[i + PHYS_IRQ_BASE].status  = IRQ_DISABLED;
        irq_desc[i + PHYS_IRQ_BASE].action  = 0;
        irq_desc[i + PHYS_IRQ_BASE].depth   = 1;
        irq_desc[i + PHYS_IRQ_BASE].handler = &physirq_irq_type;
    }
}

#endif
