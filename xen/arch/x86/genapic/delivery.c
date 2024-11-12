#include <xen/irq.h>
#include <xen/sched.h>

#include <asm/apic.h>
#include <asm/current.h>
#include <asm/genapic.h>
#include <asm/hardirq.h>
#include <asm/smp.h>

/*
 * LOGICAL FLAT DELIVERY MODE (multicast via bitmask to <= 8 logical APIC IDs).
 */

void cf_check init_apic_ldr_flat(void)
{
	unsigned long val;

	apic_write(APIC_DFR, APIC_DFR_FLAT);
	val = apic_read(APIC_LDR) & ~APIC_LDR_MASK;
	val |= SET_xAPIC_LOGICAL_ID(1UL << smp_processor_id());
	apic_write(APIC_LDR, val);
}

/*
 * PHYSICAL DELIVERY MODE (unicast to physical APIC IDs).
 */

void cf_check init_apic_ldr_phys(void)
{
	/* We only deliver in phys mode - no setup needed. */
}

const cpumask_t *cf_check vector_allocation_cpumask_phys(int cpu)
{
	return cpumask_of(cpu);
}

unsigned int cf_check cpu_mask_to_apicid_phys(const cpumask_t *cpumask)
{
	/* As we are using single CPU as destination, pick only one CPU here */
	return cpu_physical_id(cpumask_any(cpumask));
}
