/*
 * Copyright 2004 James Cleverdon, IBM.
 * Subject to the GNU Public License, v.2
 *
 * Xen APIC subarch code.  Maximum 8 CPUs, logical delivery.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 *
 * Hacked to pieces for Xen by Chris Wright.
 */
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/init.h>
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
#include <asm/smp.h>
#include <asm/ipi.h>
#else
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/genapic.h>
#endif
#include <xen/evtchn.h>

DECLARE_PER_CPU(int, ipi_to_irq[NR_IPIS]);

static inline void __send_IPI_one(unsigned int cpu, int vector)
{
	int irq = per_cpu(ipi_to_irq, cpu)[vector];
	BUG_ON(irq < 0);
	notify_remote_via_irq(irq);
}

void xen_send_IPI_shortcut(unsigned int shortcut, int vector, unsigned int dest)
{
	int cpu;

	switch (shortcut) {
	case APIC_DEST_SELF:
		__send_IPI_one(smp_processor_id(), vector);
		break;
	case APIC_DEST_ALLBUT:
		for (cpu = 0; cpu < NR_CPUS; ++cpu) {
			if (cpu == smp_processor_id())
				continue;
			if (cpu_isset(cpu, cpu_online_map)) {
				__send_IPI_one(cpu, vector);
			}
		}
		break;
	case APIC_DEST_ALLINC:
		for (cpu = 0; cpu < NR_CPUS; ++cpu) {
			if (cpu_isset(cpu, cpu_online_map)) {
				__send_IPI_one(cpu, vector);
			}
		}
		break;
	default:
		printk("XXXXXX __send_IPI_shortcut %08x vector %d\n", shortcut,
		       vector);
		break;
	}
}

static cpumask_t xen_target_cpus(void)
{
	return cpu_online_map;
}

/*
 * Set up the logical destination ID.
 * Do nothing, not called now.
 */
static void xen_init_apic_ldr(void)
{
	Dprintk("%s\n", __FUNCTION__);
	return;
}

static void xen_send_IPI_allbutself(int vector)
{
	/*
	 * if there are no other CPUs in the system then
	 * we get an APIC send error if we try to broadcast.
	 * thus we have to avoid sending IPIs in this case.
	 */
	Dprintk("%s\n", __FUNCTION__);
	if (num_online_cpus() > 1)
		xen_send_IPI_shortcut(APIC_DEST_ALLBUT, vector, APIC_DEST_LOGICAL);
}

static void xen_send_IPI_all(int vector)
{
	Dprintk("%s\n", __FUNCTION__);
	xen_send_IPI_shortcut(APIC_DEST_ALLINC, vector, APIC_DEST_LOGICAL);
}

static void xen_send_IPI_mask(cpumask_t cpumask, int vector)
{
	unsigned long mask = cpus_addr(cpumask)[0];
	unsigned int cpu;
	unsigned long flags;

	Dprintk("%s\n", __FUNCTION__);
	local_irq_save(flags);
	WARN_ON(mask & ~cpus_addr(cpu_online_map)[0]);

	for (cpu = 0; cpu < NR_CPUS; ++cpu) {
		if (cpu_isset(cpu, cpumask)) {
			__send_IPI_one(cpu, vector);
		}
	}
	local_irq_restore(flags);
}

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
static int xen_apic_id_registered(void)
{
	/* better be set */
	Dprintk("%s\n", __FUNCTION__);
	return physid_isset(smp_processor_id(), phys_cpu_present_map);
}
#endif

static unsigned int xen_cpu_mask_to_apicid(cpumask_t cpumask)
{
	Dprintk("%s\n", __FUNCTION__);
	return cpus_addr(cpumask)[0] & APIC_ALL_CPUS;
}

static unsigned int phys_pkg_id(int index_msb)
{
	u32 ebx;

	Dprintk("%s\n", __FUNCTION__);
	ebx = cpuid_ebx(1);
	return ((ebx >> 24) & 0xFF) >> index_msb;
}

struct genapic apic_xen =  {
	.name = "xen",
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
	.int_delivery_mode = dest_LowestPrio,
#endif
	.int_dest_mode = (APIC_DEST_LOGICAL != 0),
	.int_delivery_dest = APIC_DEST_LOGICAL | APIC_DM_LOWEST,
	.target_cpus = xen_target_cpus,
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
	.apic_id_registered = xen_apic_id_registered,
#endif
	.init_apic_ldr = xen_init_apic_ldr,
	.send_IPI_all = xen_send_IPI_all,
	.send_IPI_allbutself = xen_send_IPI_allbutself,
	.send_IPI_mask = xen_send_IPI_mask,
	.cpu_mask_to_apicid = xen_cpu_mask_to_apicid,
	.phys_pkg_id = phys_pkg_id,
};
