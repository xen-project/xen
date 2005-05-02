/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */
#ifndef _XEN_INTR_H_
#define _XEN_INTR_H_

/*
* The flat IRQ space is divided into two regions:
*  1. A one-to-one mapping of real physical IRQs. This space is only used
*     if we have physical device-access privilege. This region is at the 
*     start of the IRQ space so that existing device drivers do not need
*     to be modified to translate physical IRQ numbers into our IRQ space.
*  3. A dynamic mapping of inter-domain and Xen-sourced virtual IRQs. These
*     are bound using the provided bind/unbind functions.
*/

#define PIRQ_BASE   0
#define NR_PIRQS  128

#define DYNIRQ_BASE (PIRQ_BASE + NR_PIRQS)
#define NR_DYNIRQS  128

#define NR_IRQS   (NR_PIRQS + NR_DYNIRQS)

#define pirq_to_irq(_x)   ((_x) + PIRQ_BASE)
#define irq_to_pirq(_x)   ((_x) - PIRQ_BASE)

#define dynirq_to_irq(_x) ((_x) + DYNIRQ_BASE)
#define irq_to_dynirq(_x) ((_x) - DYNIRQ_BASE)

/* Dynamic binding of event channels and VIRQ sources to Linux IRQ space. */
extern int  bind_virq_to_irq(int virq);
extern void unbind_virq_from_irq(int virq);
extern int  bind_evtchn_to_irq(int evtchn);
extern void unbind_evtchn_from_irq(int evtchn);
extern int bind_ipi_on_cpu_to_irq(int cpu, int ipi);
extern void unbind_ipi_on_cpu_from_irq(int cpu, int ipi);
extern void ap_evtchn_init(int cpu);

static __inline__ int irq_cannonicalize(int irq)
{
    return (irq == 2) ? 9 : irq;
}

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);

extern void irq_suspend(void);
extern void irq_resume(void);

extern void idle_block(void);


#endif /* _XEN_INTR_H_ */
