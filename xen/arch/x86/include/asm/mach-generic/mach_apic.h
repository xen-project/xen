#ifndef __ASM_MACH_APIC_H
#define __ASM_MACH_APIC_H

#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/genapic.h>
#include <asm/smp.h>

/* The following are dependent on APIC delivery mode (logical vs. physical). */
#define INT_DELIVERY_MODE (genapic.int_delivery_mode)
#define INT_DEST_MODE (genapic.int_dest_mode)
#define TARGET_CPUS ((const typeof(cpu_online_map) *)&cpu_online_map)
#define init_apic_ldr() alternative_vcall(genapic.init_apic_ldr)
#define cpu_mask_to_apicid(mask) ({ \
	/* \
	 * There are a number of places where the address of a local variable \
	 * gets passed here. The use of ?: in alternative_call<N>() triggers an \
	 * "address of ... is always true" warning in such a case with at least \
	 * gcc 7 and 8. Hence the seemingly pointless local variable here. \
	 */ \
	const cpumask_t *m_ = (mask); \
	alternative_call(genapic.cpu_mask_to_apicid, m_); \
})
#define vector_allocation_cpumask(cpu) \
	alternative_call(genapic.vector_allocation_cpumask, cpu)

static inline void enable_apic_mode(void)
{
	/* Not needed for modern ES7000 which boot in Virtual Wire mode. */
	/*es7000_sw_apic();*/
}

#define apicid_to_node(apicid) ((int)apicid_to_node[(u32)apicid])

extern u32 bios_cpu_apicid[];

static inline int multi_timer_check(int apic, int irq)
{
	return 0;
}

#endif /* __ASM_MACH_APIC_H */
