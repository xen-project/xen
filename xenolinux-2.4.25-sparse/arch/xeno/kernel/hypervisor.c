/******************************************************************************
 * hypervisor.c
 * 
 * Communication to/from hypervisor.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <linux/config.h>
#include <asm/atomic.h>
#include <linux/irq.h>
#include <asm/hypervisor.h>
#include <asm/system.h>
#include <asm/ptrace.h>

multicall_entry_t multicall_list[8];
int nr_multicall_ents = 0;

static unsigned long event_mask = 0;

void do_hypervisor_callback(struct pt_regs *regs)
{
    unsigned long events, flags;
    shared_info_t *shared = HYPERVISOR_shared_info;

    do {
        /* Specialised local_irq_save(). */
        flags = test_and_clear_bit(EVENTS_MASTER_ENABLE_BIT, 
                                   &shared->events_mask);
        barrier();

        events  = xchg(&shared->events, 0);
        events &= event_mask;

        __asm__ __volatile__ (
            "   push %1                            ;"
            "   sub  $4,%%esp                      ;"
            "   jmp  2f                            ;"
            "1: btrl %%eax,%0                      ;" /* clear bit     */
            "   mov  %%eax,(%%esp)                 ;"
            "   call do_IRQ                        ;" /* do_IRQ(event) */
            "2: bsfl %0,%%eax                      ;" /* %eax == bit # */
            "   jnz  1b                            ;"
            "   add  $8,%%esp                      ;"
            /* we use %ebx because it is callee-saved */
            : : "b" (events), "r" (regs)
            /* clobbered by callback function calls */
            : "eax", "ecx", "edx", "memory" ); 

        /* Specialised local_irq_restore(). */
        if ( flags ) set_bit(EVENTS_MASTER_ENABLE_BIT, &shared->events_mask);
        barrier();
    }
    while ( shared->events );
}



/*
 * Define interface to generic handling in irq.c
 */

static void shutdown_hypervisor_event(unsigned int irq)
{
    clear_bit(irq, &event_mask);
    clear_bit(irq, &HYPERVISOR_shared_info->events_mask);
}

static void enable_hypervisor_event(unsigned int irq)
{
    set_bit(irq, &event_mask);
    set_bit(irq, &HYPERVISOR_shared_info->events_mask);
    if ( test_bit(EVENTS_MASTER_ENABLE_BIT, 
                  &HYPERVISOR_shared_info->events_mask) )
        do_hypervisor_callback(NULL);
}

static void disable_hypervisor_event(unsigned int irq)
{
    clear_bit(irq, &event_mask);
    clear_bit(irq, &HYPERVISOR_shared_info->events_mask);
}

static void ack_hypervisor_event(unsigned int irq)
{
    if ( !(event_mask & (1<<irq)) )
    {
        printk("Unexpected hypervisor event %d\n", irq);
        atomic_inc(&irq_err_count);
    }
    set_bit(irq, &HYPERVISOR_shared_info->events_mask);
}

static unsigned int startup_hypervisor_event(unsigned int irq)
{
    enable_hypervisor_event(irq);
    return 0;
}

static void end_hypervisor_event(unsigned int irq)
{
}

static struct hw_interrupt_type hypervisor_irq_type = {
    "Hypervisor-event",
    startup_hypervisor_event,
    shutdown_hypervisor_event,
    enable_hypervisor_event,
    disable_hypervisor_event,
    ack_hypervisor_event,
    end_hypervisor_event,
    NULL
};

void __init init_IRQ(void)
{
    int i;

    for ( i = 0; i < NR_IRQS; i++ )
    {
        irq_desc[i].status  = IRQ_DISABLED;
        irq_desc[i].action  = 0;
        irq_desc[i].depth   = 1;
        irq_desc[i].handler = &hypervisor_irq_type;
    }
}
