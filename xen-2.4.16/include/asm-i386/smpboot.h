#ifndef __ASM_SMPBOOT_H
#define __ASM_SMPBOOT_H

#define TRAMPOLINE_LOW phys_to_virt(0x467)
#define TRAMPOLINE_HIGH phys_to_virt(0x469)

#define boot_cpu_apicid boot_cpu_physical_apicid

/* How to map from the cpu_present_map. */
#define cpu_present_to_apicid(apicid) (apicid)

/*
 * Mappings between logical cpu number and logical / physical apicid
 * The first four macros are trivial, but it keeps the abstraction consistent
 */
extern volatile int logical_apicid_2_cpu[];
extern volatile int cpu_2_logical_apicid[];
extern volatile int physical_apicid_2_cpu[];
extern volatile int cpu_2_physical_apicid[];

#define logical_apicid_to_cpu(apicid) logical_apicid_2_cpu[apicid]
#define cpu_to_logical_apicid(cpu) cpu_2_logical_apicid[cpu]
#define physical_apicid_to_cpu(apicid) physical_apicid_2_cpu[apicid]
#define cpu_to_physical_apicid(cpu) cpu_2_physical_apicid[cpu]
#define boot_apicid_to_cpu(apicid) physical_apicid_2_cpu[apicid]
#define cpu_to_boot_apicid(cpu) cpu_2_physical_apicid[cpu]

#endif
