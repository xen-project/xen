#ifndef __ASM_SMPBOOT_H
#define __ASM_SMPBOOT_H

static inline unsigned long apicid_to_phys_cpu_present(int apicid)
{
	return 1UL << apicid;
}

extern volatile int logical_apicid_2_cpu[];
extern volatile int cpu_2_logical_apicid[];
extern volatile int physical_apicid_2_cpu[];
extern volatile int cpu_2_physical_apicid[];

#define boot_apicid_to_cpu(apicid) physical_apicid_2_cpu[apicid]

#endif
