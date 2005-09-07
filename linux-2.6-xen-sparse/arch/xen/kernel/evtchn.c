/******************************************************************************
 * evtchn.c
 * 
 * Communication via Xen event channels.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/version.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm-xen/synch_bitops.h>
#include <asm-xen/xen-public/event_channel.h>
#include <asm-xen/xen-public/physdev.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/evtchn.h>

/*
 * This lock protects updates to the following mapping and reference-count
 * arrays. The lock does not need to be acquired to read the mapping tables.
 */
static spinlock_t irq_mapping_update_lock;

/* IRQ <-> event-channel mappings. */
static int evtchn_to_irq[NR_EVENT_CHANNELS];
static int irq_to_evtchn[NR_IRQS];

/* IRQ <-> VIRQ mapping. */
DEFINE_PER_CPU(int, virq_to_irq[NR_VIRQS]);

/* evtchn <-> IPI mapping. */
#ifndef NR_IPIS
#define NR_IPIS 1 
#endif
DEFINE_PER_CPU(int, ipi_to_evtchn[NR_IPIS]);

/* Reference counts for bindings to IRQs. */
static int irq_bindcount[NR_IRQS];

/* Bitmap indicating which PIRQs require Xen to be notified on unmask. */
static unsigned long pirq_needs_unmask_notify[NR_PIRQS/sizeof(unsigned long)];

#ifdef CONFIG_SMP

static u8  cpu_evtchn[NR_EVENT_CHANNELS];
static u32 cpu_evtchn_mask[NR_CPUS][NR_EVENT_CHANNELS/32];

#define active_evtchns(cpu,sh,idx)              \
    ((sh)->evtchn_pending[idx] &                \
     cpu_evtchn_mask[cpu][idx] &                \
     ~(sh)->evtchn_mask[idx])

void bind_evtchn_to_cpu(unsigned int chn, unsigned int cpu)
{
    clear_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu_evtchn[chn]]);
    set_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu]);
    cpu_evtchn[chn] = cpu;
}

#else

#define active_evtchns(cpu,sh,idx)              \
    ((sh)->evtchn_pending[idx] &                \
     ~(sh)->evtchn_mask[idx])

void bind_evtchn_to_cpu(unsigned int chn, unsigned int cpu)
{
}
#endif

/* Upcall to generic IRQ layer. */
#ifdef CONFIG_X86
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
extern fastcall unsigned int do_IRQ(struct pt_regs *regs);
#else
extern asmlinkage unsigned int do_IRQ(struct pt_regs *regs);
#endif
#if defined (__i386__)
#define IRQ_REG orig_eax
#elif defined (__x86_64__)
#define IRQ_REG orig_rax
#endif
#define do_IRQ(irq, regs) do {                  \
    (regs)->IRQ_REG = (irq);                    \
    do_IRQ((regs));                             \
} while (0)
#endif

#define VALID_EVTCHN(_chn) ((_chn) >= 0)

/*
 * Force a proper event-channel callback from Xen after clearing the
 * callback mask. We do this in a very simple manner, by making a call
 * down into Xen. The pending flag will be checked by Xen on return.
 */
void force_evtchn_callback(void)
{
    (void)HYPERVISOR_xen_version(0);
}
EXPORT_SYMBOL(force_evtchn_callback);

/* NB. Interrupts are disabled on entry. */
asmlinkage void evtchn_do_upcall(struct pt_regs *regs)
{
    u32     l1, l2;
    unsigned int   l1i, l2i, port;
    int            irq, cpu = smp_processor_id();
    shared_info_t *s = HYPERVISOR_shared_info;
    vcpu_info_t   *vcpu_info = &s->vcpu_data[cpu];

    vcpu_info->evtchn_upcall_pending = 0;

    /* NB. No need for a barrier here -- XCHG is a barrier on x86. */
    l1 = xchg(&vcpu_info->evtchn_pending_sel, 0);
    while ( l1 != 0 )
    {
        l1i = __ffs(l1);
        l1 &= ~(1 << l1i);
        
        while ( (l2 = active_evtchns(cpu, s, l1i)) != 0 )
        {
            l2i = __ffs(l2);
            l2 &= ~(1 << l2i);
            
            port = (l1i << 5) + l2i;
            if ( (irq = evtchn_to_irq[port]) != -1 ) {
                do_IRQ(irq, regs);
	    } else
                evtchn_device_upcall(port);
        }
    }
}
EXPORT_SYMBOL(evtchn_do_upcall);

static int find_unbound_irq(void)
{
    int irq;

    for ( irq = 0; irq < NR_IRQS; irq++ )
        if ( irq_bindcount[irq] == 0 )
            break;

    if ( irq == NR_IRQS )
        panic("No available IRQ to bind to: increase NR_IRQS!\n");

    return irq;
}

int bind_virq_to_irq(int virq)
{
    evtchn_op_t op;
    int evtchn, irq;
    int cpu = smp_processor_id();

    spin_lock(&irq_mapping_update_lock);

    if ( (irq = per_cpu(virq_to_irq, cpu)[virq]) == -1 )
    {
        op.cmd              = EVTCHNOP_bind_virq;
        op.u.bind_virq.virq = virq;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IRQ %d\n", virq);
        evtchn = op.u.bind_virq.port;

        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        per_cpu(virq_to_irq, cpu)[virq] = irq;

        bind_evtchn_to_cpu(evtchn, cpu);
    }

    irq_bindcount[irq]++;

    spin_unlock(&irq_mapping_update_lock);
    
    return irq;
}
EXPORT_SYMBOL(bind_virq_to_irq);

void unbind_virq_from_irq(int virq)
{
    evtchn_op_t op;
    int cpu    = smp_processor_id();
    int irq    = per_cpu(virq_to_irq, cpu)[virq];
    int evtchn = irq_to_evtchn[irq];

    spin_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
        op.cmd          = EVTCHNOP_close;
        op.u.close.dom  = DOMID_SELF;
        op.u.close.port = evtchn;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to unbind virtual IRQ %d\n", virq);

        /*
         * This is a slight hack. Interdomain ports can be allocated directly 
         * by userspace, and at that point they get bound by Xen to vcpu 0. We 
         * therefore need to make sure that if we get an event on an event 
         * channel we don't know about vcpu 0 handles it. Binding channels to 
         * vcpu 0 when closing them achieves this.
         */
        bind_evtchn_to_cpu(evtchn, 0);
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
        per_cpu(virq_to_irq, cpu)[virq]     = -1;
    }

    spin_unlock(&irq_mapping_update_lock);
}
EXPORT_SYMBOL(unbind_virq_from_irq);

int bind_ipi_to_irq(int ipi)
{
    evtchn_op_t op;
    int evtchn, irq;
    int cpu = smp_processor_id();

    spin_lock(&irq_mapping_update_lock);

    if ( (evtchn = per_cpu(ipi_to_evtchn, cpu)[ipi]) == 0 )
    {
        op.cmd = EVTCHNOP_bind_ipi;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IPI %d on cpu %d\n", ipi, cpu);
        evtchn = op.u.bind_ipi.port;

        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        per_cpu(ipi_to_evtchn, cpu)[ipi] = evtchn;

        bind_evtchn_to_cpu(evtchn, cpu);
    } 
    else
    {
        irq = evtchn_to_irq[evtchn];
    }

    irq_bindcount[irq]++;

    spin_unlock(&irq_mapping_update_lock);

    return irq;
}
EXPORT_SYMBOL(bind_ipi_to_irq);

void unbind_ipi_from_irq(int ipi)
{
    evtchn_op_t op;
    int cpu    = smp_processor_id();
    int evtchn = per_cpu(ipi_to_evtchn, cpu)[ipi];
    int irq    = evtchn_to_irq[evtchn];

    spin_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
        op.cmd          = EVTCHNOP_close;
        op.u.close.dom  = DOMID_SELF;
        op.u.close.port = evtchn;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to unbind virtual IPI %d on cpu %d\n", ipi, cpu);

        /* See comments in unbind_virq_from_irq */
        bind_evtchn_to_cpu(evtchn, 0);
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
        per_cpu(ipi_to_evtchn, cpu)[ipi] = 0;
    }

    spin_unlock(&irq_mapping_update_lock);
}
EXPORT_SYMBOL(unbind_ipi_from_irq);

int bind_evtchn_to_irq(unsigned int evtchn)
{
    int irq;

    spin_lock(&irq_mapping_update_lock);

    if ( (irq = evtchn_to_irq[evtchn]) == -1 )
    {
        irq = find_unbound_irq();
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;
    }

    irq_bindcount[irq]++;

    spin_unlock(&irq_mapping_update_lock);
    
    return irq;
}
EXPORT_SYMBOL(bind_evtchn_to_irq);

void unbind_evtchn_from_irq(unsigned int evtchn)
{
    int irq = evtchn_to_irq[evtchn];

    spin_lock(&irq_mapping_update_lock);

    if ( --irq_bindcount[irq] == 0 )
    {
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
    }

    spin_unlock(&irq_mapping_update_lock);
}
EXPORT_SYMBOL(unbind_evtchn_from_irq);

int bind_evtchn_to_irqhandler(
    unsigned int evtchn,
    irqreturn_t (*handler)(int, void *, struct pt_regs *),
    unsigned long irqflags,
    const char *devname,
    void *dev_id)
{
    unsigned int irq;
    int retval;

    irq = bind_evtchn_to_irq(evtchn);
    retval = request_irq(irq, handler, irqflags, devname, dev_id);
    if ( retval != 0 )
        unbind_evtchn_from_irq(evtchn);

    return retval;
}
EXPORT_SYMBOL(bind_evtchn_to_irqhandler);

void unbind_evtchn_from_irqhandler(unsigned int evtchn, void *dev_id)
{
    unsigned int irq = evtchn_to_irq[evtchn];
    free_irq(irq, dev_id);
    unbind_evtchn_from_irq(evtchn);
}
EXPORT_SYMBOL(unbind_evtchn_from_irqhandler);

#ifdef CONFIG_SMP
static void do_nothing_function(void *ign)
{
}
#endif

/* Rebind an evtchn so that it gets delivered to a specific cpu */
static void rebind_irq_to_cpu(unsigned irq, unsigned tcpu)
{
    evtchn_op_t op;
    int evtchn;

    spin_lock(&irq_mapping_update_lock);
    evtchn = irq_to_evtchn[irq];
    if (!VALID_EVTCHN(evtchn)) {
        spin_unlock(&irq_mapping_update_lock);
        return;
    }

    /* Tell Xen to send future instances of this interrupt to other vcpu. */
    op.cmd = EVTCHNOP_bind_vcpu;
    op.u.bind_vcpu.port = evtchn;
    op.u.bind_vcpu.vcpu = tcpu;

    /*
     * If this fails, it usually just indicates that we're dealing with a virq 
     * or IPI channel, which don't actually need to be rebound. Ignore it, 
     * but don't do the xenlinux-level rebind in that case.
     */
    if (HYPERVISOR_event_channel_op(&op) >= 0)
        bind_evtchn_to_cpu(evtchn, tcpu);

    spin_unlock(&irq_mapping_update_lock);

    /*
     * Now send the new target processor a NOP IPI. When this returns, it 
     * will check for any pending interrupts, and so service any that got 
     * delivered to the wrong processor by mistake.
     * 
     * XXX: The only time this is called with interrupts disabled is from the 
     * hotplug/hotunplug path. In that case, all cpus are stopped with 
     * interrupts disabled, and the missed interrupts will be picked up when 
     * they start again. This is kind of a hack.
     */
    if (!irqs_disabled())
        smp_call_function(do_nothing_function, NULL, 0, 0);
}


static void set_affinity_irq(unsigned irq, cpumask_t dest)
{
    unsigned tcpu = first_cpu(dest);
    rebind_irq_to_cpu(irq, tcpu);
}

/*
 * Interface to generic handling in irq.c
 */

static unsigned int startup_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    if ( !VALID_EVTCHN(evtchn) )
        return 0;
    unmask_evtchn(evtchn);
    return 0;
}

static void shutdown_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    if ( !VALID_EVTCHN(evtchn) )
        return;
    mask_evtchn(evtchn);
}

static void enable_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    unmask_evtchn(evtchn);
}

static void disable_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    mask_evtchn(evtchn);
}

static void ack_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    mask_evtchn(evtchn);
    clear_evtchn(evtchn);
}

static void end_dynirq(unsigned int irq)
{
    int evtchn = irq_to_evtchn[irq];

    if ( !(irq_desc[irq].status & IRQ_DISABLED) )
        unmask_evtchn(evtchn);
}

static struct hw_interrupt_type dynirq_type = {
    "Dynamic-irq",
    startup_dynirq,
    shutdown_dynirq,
    enable_dynirq,
    disable_dynirq,
    ack_dynirq,
    end_dynirq,
    set_affinity_irq
};

static inline void pirq_unmask_notify(int pirq)
{
    physdev_op_t op;
    if ( unlikely(test_bit(pirq, &pirq_needs_unmask_notify[0])) )
    {
        op.cmd = PHYSDEVOP_IRQ_UNMASK_NOTIFY;
        (void)HYPERVISOR_physdev_op(&op);
    }
}

static inline void pirq_query_unmask(int pirq)
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

    bind_evtchn_to_cpu(evtchn, 0);
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

    bind_evtchn_to_cpu(evtchn, 0);
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
    set_affinity_irq
};

void hw_resend_irq(struct hw_interrupt_type *h, unsigned int i)
{
    int evtchn = irq_to_evtchn[i];
    shared_info_t *s = HYPERVISOR_shared_info;
    if ( !VALID_EVTCHN(evtchn) )
        return;
    BUG_ON(!synch_test_bit(evtchn, &s->evtchn_mask[0]));
    synch_set_bit(evtchn, &s->evtchn_pending[0]);
}

void irq_suspend(void)
{
    int pirq, virq, irq, evtchn;
    int cpu = smp_processor_id(); /* XXX */

    /* Unbind VIRQs from event channels. */
    for ( virq = 0; virq < NR_VIRQS; virq++ )
    {
        if ( (irq = per_cpu(virq_to_irq, cpu)[virq]) == -1 )
            continue;
        evtchn = irq_to_evtchn[irq];

        /* Mark the event channel as unused in our table. */
        evtchn_to_irq[evtchn] = -1;
        irq_to_evtchn[irq]    = -1;
    }

    /* Check that no PIRQs are still bound. */
    for ( pirq = 0; pirq < NR_PIRQS; pirq++ )
        if ( (evtchn = irq_to_evtchn[pirq_to_irq(pirq)]) != -1 )
            panic("Suspend attempted while PIRQ %d bound to evtchn %d.\n",
                  pirq, evtchn);
}

void irq_resume(void)
{
    evtchn_op_t op;
    int         virq, irq, evtchn;
    int cpu = smp_processor_id(); /* XXX */

    for ( evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++ )
        mask_evtchn(evtchn); /* New event-channel space is not 'live' yet. */

    for ( virq = 0; virq < NR_VIRQS; virq++ )
    {
        if ( (irq = per_cpu(virq_to_irq, cpu)[virq]) == -1 )
            continue;

        /* Get a new binding from Xen. */
        op.cmd              = EVTCHNOP_bind_virq;
        op.u.bind_virq.virq = virq;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("Failed to bind virtual IRQ %d\n", virq);
        evtchn = op.u.bind_virq.port;
        
        /* Record the new mapping. */
        bind_evtchn_to_cpu(evtchn, 0);
        evtchn_to_irq[evtchn] = irq;
        irq_to_evtchn[irq]    = evtchn;

        /* Ready for use. */
        unmask_evtchn(evtchn);
    }
}

void __init init_IRQ(void)
{
    int i;
    int cpu;

    irq_ctx_init(0);

    spin_lock_init(&irq_mapping_update_lock);

#ifdef CONFIG_SMP
    /* By default all event channels notify CPU#0. */
    memset(cpu_evtchn_mask[0], ~0, sizeof(cpu_evtchn_mask[0]));
#endif

    for ( cpu = 0; cpu < NR_CPUS; cpu++ ) {
        /* No VIRQ -> IRQ mappings. */
        for ( i = 0; i < NR_VIRQS; i++ )
            per_cpu(virq_to_irq, cpu)[i] = -1;
    }

    /* No event-channel -> IRQ mappings. */
    for ( i = 0; i < NR_EVENT_CHANNELS; i++ )
    {
        evtchn_to_irq[i] = -1;
        mask_evtchn(i); /* No event channels are 'live' right now. */
    }

    /* No IRQ -> event-channel mappings. */
    for ( i = 0; i < NR_IRQS; i++ )
        irq_to_evtchn[i] = -1;

    for ( i = 0; i < NR_DYNIRQS; i++ )
    {
        /* Dynamic IRQ space is currently unbound. Zero the refcnts. */
        irq_bindcount[dynirq_to_irq(i)] = 0;

        irq_desc[dynirq_to_irq(i)].status  = IRQ_DISABLED;
        irq_desc[dynirq_to_irq(i)].action  = 0;
        irq_desc[dynirq_to_irq(i)].depth   = 1;
        irq_desc[dynirq_to_irq(i)].handler = &dynirq_type;
    }

    for ( i = 0; i < NR_PIRQS; i++ )
    {
        /* Phys IRQ space is statically bound (1:1 mapping). Nail refcnts. */
        irq_bindcount[pirq_to_irq(i)] = 1;

        irq_desc[pirq_to_irq(i)].status  = IRQ_DISABLED;
        irq_desc[pirq_to_irq(i)].action  = 0;
        irq_desc[pirq_to_irq(i)].depth   = 1;
        irq_desc[pirq_to_irq(i)].handler = &pirq_type;
    }
}
