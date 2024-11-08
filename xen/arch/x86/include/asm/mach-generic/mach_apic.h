#ifndef __ASM_MACH_APIC_H
#define __ASM_MACH_APIC_H

#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/genapic.h>
#include <asm/smp.h>

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
