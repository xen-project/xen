/*
 * linux/arch/ia64/kernel/irq.c
 *
 * Copyright (C) 1998-2001 Hewlett-Packard Co
 *	Stephane Eranian <eranian@hpl.hp.com>
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *
 *  6/10/99: Updated to bring in sync with x86 version to facilitate
 *	     support for SMP and different interrupt controllers.
 *
 * 09/15/00 Goutham Rao <goutham.rao@intel.com> Implemented pci_irq_to_vector
 *                      PCI to vector allocation routine.
 * 04/14/2004 Ashok Raj <ashok.raj@intel.com>
 *						Added CPU Hotplug handling for IPF.
 */

#include <linux/module.h>

#include <linux/jiffies.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/kernel_stat.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/random.h>	/* for rand_initialize_irq() */
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/threads.h>
#include <linux/bitops.h>
#ifdef CONFIG_XEN
#include <linux/cpu.h>
#endif

#include <asm/delay.h>
#include <asm/intrinsics.h>
#include <asm/io.h>
#include <asm/hw_irq.h>
#include <asm/machvec.h>
#include <asm/pgtable.h>
#include <asm/system.h>

#ifdef CONFIG_PERFMON
# include <asm/perfmon.h>
#endif

#define IRQ_DEBUG	0

/* These can be overridden in platform_irq_init */
int ia64_first_device_vector = IA64_DEF_FIRST_DEVICE_VECTOR;
int ia64_last_device_vector = IA64_DEF_LAST_DEVICE_VECTOR;

/* default base addr of IPI table */
void __iomem *ipi_base_addr = ((void __iomem *)
			       (__IA64_UNCACHED_OFFSET | IA64_IPI_DEFAULT_BASE_ADDR));

/*
 * Legacy IRQ to IA-64 vector translation table.
 */
__u8 isa_irq_to_vector_map[16] = {
	/* 8259 IRQ translation, first 16 entries */
	0x2f, 0x20, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
	0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21
};
EXPORT_SYMBOL(isa_irq_to_vector_map);

static unsigned long ia64_vector_mask[BITS_TO_LONGS(IA64_MAX_DEVICE_VECTORS)];

int
assign_irq_vector (int irq)
{
	int pos, vector;

#ifdef CONFIG_XEN
	if (is_running_on_xen()) {
		extern int xen_assign_irq_vector(int);
		return xen_assign_irq_vector(irq);
	}
#endif
 again:
	pos = find_first_zero_bit(ia64_vector_mask, IA64_NUM_DEVICE_VECTORS);
	vector = IA64_FIRST_DEVICE_VECTOR + pos;
	if (vector > IA64_LAST_DEVICE_VECTOR)
		return -ENOSPC;
	if (test_and_set_bit(pos, ia64_vector_mask))
		goto again;
	return vector;
}

void
free_irq_vector (int vector)
{
	int pos;

	if (vector < IA64_FIRST_DEVICE_VECTOR || vector > IA64_LAST_DEVICE_VECTOR)
		return;

#ifdef CONFIG_XEN
	if (is_running_on_xen()) {
		extern void xen_free_irq_vector(int);
		xen_free_irq_vector(vector);
		return;
	}
#endif
	pos = vector - IA64_FIRST_DEVICE_VECTOR;
	if (!test_and_clear_bit(pos, ia64_vector_mask))
		printk(KERN_WARNING "%s: double free!\n", __FUNCTION__);
}

int
reserve_irq_vector (int vector)
{
	int pos;

	if (vector < IA64_FIRST_DEVICE_VECTOR ||
	    vector > IA64_LAST_DEVICE_VECTOR)
		return -EINVAL;

	pos = vector - IA64_FIRST_DEVICE_VECTOR;
	return test_and_set_bit(pos, ia64_vector_mask);
}

#ifdef CONFIG_SMP
#	define IS_RESCHEDULE(vec)	(vec == IA64_IPI_RESCHEDULE)
#else
#	define IS_RESCHEDULE(vec)	(0)
#endif
/*
 * That's where the IVT branches when we get an external
 * interrupt. This branches to the correct hardware IRQ handler via
 * function ptr.
 */
void
ia64_handle_irq (ia64_vector vector, struct pt_regs *regs)
{
	unsigned long saved_tpr;

#if IRQ_DEBUG
	{
		unsigned long bsp, sp;

		/*
		 * Note: if the interrupt happened while executing in
		 * the context switch routine (ia64_switch_to), we may
		 * get a spurious stack overflow here.  This is
		 * because the register and the memory stack are not
		 * switched atomically.
		 */
		bsp = ia64_getreg(_IA64_REG_AR_BSP);
		sp = ia64_getreg(_IA64_REG_SP);

		if ((sp - bsp) < 1024) {
			static unsigned char count;
			static long last_time;

			if (jiffies - last_time > 5*HZ)
				count = 0;
			if (++count < 5) {
				last_time = jiffies;
				printk("ia64_handle_irq: DANGER: less than "
				       "1KB of free stack space!!\n"
				       "(bsp=0x%lx, sp=%lx)\n", bsp, sp);
			}
		}
	}
#endif /* IRQ_DEBUG */

	/*
	 * Always set TPR to limit maximum interrupt nesting depth to
	 * 16 (without this, it would be ~240, which could easily lead
	 * to kernel stack overflows).
	 */
	irq_enter();
	saved_tpr = ia64_getreg(_IA64_REG_CR_TPR);
	ia64_srlz_d();
	while (vector != IA64_SPURIOUS_INT_VECTOR) {
		if (!IS_RESCHEDULE(vector)) {
			ia64_setreg(_IA64_REG_CR_TPR, vector);
			ia64_srlz_d();

			__do_IRQ(local_vector_to_irq(vector), regs);

			/*
			 * Disable interrupts and send EOI:
			 */
			local_irq_disable();
			ia64_setreg(_IA64_REG_CR_TPR, saved_tpr);
		}
		ia64_eoi();
		vector = ia64_get_ivr();
	}
	/*
	 * This must be done *after* the ia64_eoi().  For example, the keyboard softirq
	 * handler needs to be able to wait for further keyboard interrupts, which can't
	 * come through until ia64_eoi() has been done.
	 */
	irq_exit();
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * This function emulates a interrupt processing when a cpu is about to be
 * brought down.
 */
void ia64_process_pending_intr(void)
{
	ia64_vector vector;
	unsigned long saved_tpr;
	extern unsigned int vectors_in_migration[NR_IRQS];

	vector = ia64_get_ivr();

	 irq_enter();
	 saved_tpr = ia64_getreg(_IA64_REG_CR_TPR);
	 ia64_srlz_d();

	 /*
	  * Perform normal interrupt style processing
	  */
	while (vector != IA64_SPURIOUS_INT_VECTOR) {
		if (!IS_RESCHEDULE(vector)) {
			ia64_setreg(_IA64_REG_CR_TPR, vector);
			ia64_srlz_d();

			/*
			 * Now try calling normal ia64_handle_irq as it would have got called
			 * from a real intr handler. Try passing null for pt_regs, hopefully
			 * it will work. I hope it works!.
			 * Probably could shared code.
			 */
			vectors_in_migration[local_vector_to_irq(vector)]=0;
			__do_IRQ(local_vector_to_irq(vector), NULL);

			/*
			 * Disable interrupts and send EOI
			 */
			local_irq_disable();
			ia64_setreg(_IA64_REG_CR_TPR, saved_tpr);
		}
		ia64_eoi();
		vector = ia64_get_ivr();
	}
	irq_exit();
}
#endif


#ifdef CONFIG_SMP
extern irqreturn_t handle_IPI (int irq, void *dev_id, struct pt_regs *regs);

static struct irqaction ipi_irqaction = {
	.handler =	handle_IPI,
	.flags =	IRQF_DISABLED,
	.name =		"IPI"
};
#endif

#ifdef CONFIG_XEN
#include <xen/evtchn.h>
#include <xen/interface/callback.h>

static DEFINE_PER_CPU(int, timer_irq) = -1;
static DEFINE_PER_CPU(int, ipi_irq) = -1;
static DEFINE_PER_CPU(int, resched_irq) = -1;
static DEFINE_PER_CPU(int, cmc_irq) = -1;
static DEFINE_PER_CPU(int, cmcp_irq) = -1;
static DEFINE_PER_CPU(int, cpep_irq) = -1;
static char timer_name[NR_CPUS][15];
static char ipi_name[NR_CPUS][15];
static char resched_name[NR_CPUS][15];
static char cmc_name[NR_CPUS][15];
static char cmcp_name[NR_CPUS][15];
static char cpep_name[NR_CPUS][15];

struct saved_irq {
	unsigned int irq;
	struct irqaction *action;
};
/* 16 should be far optimistic value, since only several percpu irqs
 * are registered early.
 */
#define MAX_LATE_IRQ	16
static struct saved_irq saved_percpu_irqs[MAX_LATE_IRQ];
static unsigned short late_irq_cnt = 0;
static unsigned short saved_irq_cnt = 0;
static int xen_slab_ready = 0;

#ifdef CONFIG_SMP
/* Dummy stub. Though we may check RESCHEDULE_VECTOR before __do_IRQ,
 * it ends up to issue several memory accesses upon percpu data and
 * thus adds unnecessary traffic to other paths.
 */
static irqreturn_t
handle_reschedule(int irq, void *dev_id, struct pt_regs *regs)
{

	return IRQ_HANDLED;
}

static struct irqaction resched_irqaction = {
	.handler =	handle_reschedule,
	.flags =	SA_INTERRUPT,
	.name =		"RESCHED"
};
#endif

/*
 * This is xen version percpu irq registration, which needs bind
 * to xen specific evtchn sub-system. One trick here is that xen
 * evtchn binding interface depends on kmalloc because related
 * port needs to be freed at device/cpu down. So we cache the
 * registration on BSP before slab is ready and then deal them
 * at later point. For rest instances happening after slab ready,
 * we hook them to xen evtchn immediately.
 *
 * FIXME: MCA is not supported by far, and thus "nomca" boot param is
 * required.
 */
static void
xen_register_percpu_irq (unsigned int vec, struct irqaction *action, int save)
{
	unsigned int cpu = smp_processor_id();
	irq_desc_t *desc;
	int irq = 0;

	if (xen_slab_ready) {
		switch (vec) {
		case IA64_TIMER_VECTOR:
			sprintf(timer_name[cpu], "%s%d", action->name, cpu);
			irq = bind_virq_to_irqhandler(VIRQ_ITC, cpu,
				action->handler, action->flags,
				timer_name[cpu], action->dev_id);
			per_cpu(timer_irq,cpu) = irq;
			break;
		case IA64_IPI_RESCHEDULE:
			sprintf(resched_name[cpu], "%s%d", action->name, cpu);
			irq = bind_ipi_to_irqhandler(RESCHEDULE_VECTOR, cpu,
				action->handler, action->flags,
				resched_name[cpu], action->dev_id);
			per_cpu(resched_irq,cpu) = irq;
			break;
		case IA64_IPI_VECTOR:
			sprintf(ipi_name[cpu], "%s%d", action->name, cpu);
			irq = bind_ipi_to_irqhandler(IPI_VECTOR, cpu,
				action->handler, action->flags,
				ipi_name[cpu], action->dev_id);
			per_cpu(ipi_irq,cpu) = irq;
			break;
		case IA64_CMC_VECTOR:
			sprintf(cmc_name[cpu], "%s%d", action->name, cpu);
			irq = bind_virq_to_irqhandler(VIRQ_MCA_CMC, cpu,
			                              action->handler,
			                              action->flags,
			                              cmc_name[cpu],
			                              action->dev_id);
			per_cpu(cmc_irq,cpu) = irq;
			break;
		case IA64_CMCP_VECTOR:
			sprintf(cmcp_name[cpu], "%s%d", action->name, cpu);
			irq = bind_ipi_to_irqhandler(CMCP_VECTOR, cpu,
			                             action->handler,
			                             action->flags,
			                             cmcp_name[cpu],
			                             action->dev_id);
			per_cpu(cmcp_irq,cpu) = irq;
			break;
		case IA64_CPEP_VECTOR:
			sprintf(cpep_name[cpu], "%s%d", action->name, cpu);
			irq = bind_ipi_to_irqhandler(CPEP_VECTOR, cpu,
			                             action->handler,
			                             action->flags,
			                             cpep_name[cpu],
			                             action->dev_id);
			per_cpu(cpep_irq,cpu) = irq;
			break;
		case IA64_CPE_VECTOR:
		case IA64_MCA_RENDEZ_VECTOR:
		case IA64_PERFMON_VECTOR:
		case IA64_MCA_WAKEUP_VECTOR:
		case IA64_SPURIOUS_INT_VECTOR:
			/* No need to complain, these aren't supported. */
			break;
		default:
			printk(KERN_WARNING "Percpu irq %d is unsupported "
			       "by xen!\n", vec);
			break;
		}
		BUG_ON(irq < 0);

		if (irq > 0) {
			/*
			 * Mark percpu.  Without this, migrate_irqs() will
			 * mark the interrupt for migrations and trigger it
			 * on cpu hotplug.
			 */
			desc = irq_desc + irq;
			desc->status |= IRQ_PER_CPU;
		}
	} 

	/* For BSP, we cache registered percpu irqs, and then re-walk
	 * them when initializing APs
	 */
	if (!cpu && save) {
		BUG_ON(saved_irq_cnt == MAX_LATE_IRQ);
		saved_percpu_irqs[saved_irq_cnt].irq = vec;
		saved_percpu_irqs[saved_irq_cnt].action = action;
		saved_irq_cnt++;
		if (!xen_slab_ready)
			late_irq_cnt++;
	}
}

static void
xen_bind_early_percpu_irq (void)
{
	int i;

	xen_slab_ready = 1;
	/* There's no race when accessing this cached array, since only
	 * BSP will face with such step shortly
	 */
	for (i = 0; i < late_irq_cnt; i++)
		xen_register_percpu_irq(saved_percpu_irqs[i].irq,
		                        saved_percpu_irqs[i].action, 0);
}

/* FIXME: There's no obvious point to check whether slab is ready. So
 * a hack is used here by utilizing a late time hook.
 */
extern void (*late_time_init)(void);
extern char xen_event_callback;
extern void xen_init_IRQ(void);

#ifdef CONFIG_HOTPLUG_CPU
static int __devinit
unbind_evtchn_callback(struct notifier_block *nfb,
                       unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;

	if (action == CPU_DEAD) {
		/* Unregister evtchn.  */
		if (per_cpu(cpep_irq,cpu) >= 0) {
			unbind_from_irqhandler(per_cpu(cpep_irq, cpu), NULL);
			per_cpu(cpep_irq, cpu) = -1;
		}
		if (per_cpu(cmcp_irq,cpu) >= 0) {
			unbind_from_irqhandler(per_cpu(cmcp_irq, cpu), NULL);
			per_cpu(cmcp_irq, cpu) = -1;
		}
		if (per_cpu(cmc_irq,cpu) >= 0) {
			unbind_from_irqhandler(per_cpu(cmc_irq, cpu), NULL);
			per_cpu(cmc_irq, cpu) = -1;
		}
		if (per_cpu(ipi_irq,cpu) >= 0) {
			unbind_from_irqhandler (per_cpu(ipi_irq, cpu), NULL);
			per_cpu(ipi_irq, cpu) = -1;
		}
		if (per_cpu(resched_irq,cpu) >= 0) {
			unbind_from_irqhandler (per_cpu(resched_irq, cpu),
						NULL);
			per_cpu(resched_irq, cpu) = -1;
		}
		if (per_cpu(timer_irq,cpu) >= 0) {
			unbind_from_irqhandler (per_cpu(timer_irq, cpu), NULL);
			per_cpu(timer_irq, cpu) = -1;
		}
	}
	return NOTIFY_OK;
}

static struct notifier_block unbind_evtchn_notifier = {
	.notifier_call = unbind_evtchn_callback,
	.priority = 0
};
#endif

DECLARE_PER_CPU(int, ipi_to_irq[NR_IPIS]);
void xen_smp_intr_init(void)
{
#ifdef CONFIG_SMP
	unsigned int cpu = smp_processor_id();
	unsigned int i = 0;
	struct callback_register event = {
		.type = CALLBACKTYPE_event,
		.address = (unsigned long)&xen_event_callback,
	};

	if (cpu == 0) {
		/* Initialization was already done for boot cpu.  */
#ifdef CONFIG_HOTPLUG_CPU
		/* Register the notifier only once.  */
		register_cpu_notifier(&unbind_evtchn_notifier);
#endif
		return;
	}

	/* This should be piggyback when setup vcpu guest context */
	BUG_ON(HYPERVISOR_callback_op(CALLBACKOP_register, &event));

	for (i = 0; i < saved_irq_cnt; i++)
		xen_register_percpu_irq(saved_percpu_irqs[i].irq,
		                        saved_percpu_irqs[i].action, 0);
#endif /* CONFIG_SMP */
}
#endif /* CONFIG_XEN */

void
register_percpu_irq (ia64_vector vec, struct irqaction *action)
{
	irq_desc_t *desc;
	unsigned int irq;

#ifdef CONFIG_XEN
	if (is_running_on_xen())
		return xen_register_percpu_irq(vec, action, 1);
#endif

	for (irq = 0; irq < NR_IRQS; ++irq)
		if (irq_to_vector(irq) == vec) {
			desc = irq_desc + irq;
			desc->status |= IRQ_PER_CPU;
			desc->chip = &irq_type_ia64_lsapic;
			if (action)
				setup_irq(irq, action);
		}
}

void __init
init_IRQ (void)
{
#ifdef CONFIG_XEN
	/* Maybe put into platform_irq_init later */
	if (is_running_on_xen()) {
		struct callback_register event = {
			.type = CALLBACKTYPE_event,
			.address = (unsigned long)&xen_event_callback,
		};
		xen_init_IRQ();
		BUG_ON(HYPERVISOR_callback_op(CALLBACKOP_register, &event));
		late_time_init = xen_bind_early_percpu_irq;
#ifdef CONFIG_SMP
		register_percpu_irq(IA64_IPI_RESCHEDULE, &resched_irqaction);
#endif /* CONFIG_SMP */
	}
#endif /* CONFIG_XEN */
	register_percpu_irq(IA64_SPURIOUS_INT_VECTOR, NULL);
#ifdef CONFIG_SMP
	register_percpu_irq(IA64_IPI_VECTOR, &ipi_irqaction);
#endif
#ifdef CONFIG_PERFMON
	pfm_init_percpu();
#endif
	platform_irq_init();
}

void
ia64_send_ipi (int cpu, int vector, int delivery_mode, int redirect)
{
	void __iomem *ipi_addr;
	unsigned long ipi_data;
	unsigned long phys_cpu_id;

#ifdef CONFIG_XEN
        if (is_running_on_xen()) {
		int irq = -1;

#ifdef CONFIG_SMP
		/* TODO: we need to call vcpu_up here */
		if (unlikely(vector == ap_wakeup_vector)) {
			extern void xen_send_ipi (int cpu, int vec);
			xen_send_ipi (cpu, vector);
			//vcpu_prepare_and_up(cpu);
			return;
		}
#endif

		switch(vector) {
		case IA64_IPI_VECTOR:
			irq = per_cpu(ipi_to_irq, cpu)[IPI_VECTOR];
			break;
		case IA64_IPI_RESCHEDULE:
			irq = per_cpu(ipi_to_irq, cpu)[RESCHEDULE_VECTOR];
			break;
		case IA64_CMCP_VECTOR:
			irq = per_cpu(ipi_to_irq, cpu)[CMCP_VECTOR];
			break;
		case IA64_CPEP_VECTOR:
			irq = per_cpu(ipi_to_irq, cpu)[CPEP_VECTOR];
			break;
		default:
			printk(KERN_WARNING "Unsupported IPI type 0x%x\n",
			       vector);
			irq = 0;
			break;
		}		
	
		BUG_ON(irq < 0);
		notify_remote_via_irq(irq);
		return;
        }
#endif /* CONFIG_XEN */

#ifdef CONFIG_SMP
	phys_cpu_id = cpu_physical_id(cpu);
#else
	phys_cpu_id = (ia64_getreg(_IA64_REG_CR_LID) >> 16) & 0xffff;
#endif

	/*
	 * cpu number is in 8bit ID and 8bit EID
	 */

	ipi_data = (delivery_mode << 8) | (vector & 0xff);
	ipi_addr = ipi_base_addr + ((phys_cpu_id << 4) | ((redirect & 1) << 3));

	writeq(ipi_data, ipi_addr);
}
