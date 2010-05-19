#ifndef __ASM_MACH_WAKECPU_H
#define __ASM_MACH_WAKECPU_H

/* 
 * This file copes with machines that wakeup secondary CPUs by the
 * INIT, INIT, STARTUP sequence.
 */

#define WAKE_SECONDARY_VIA_INIT

#define TRAMPOLINE_LOW maddr_to_virt(0x467)
#define TRAMPOLINE_HIGH maddr_to_virt(0x469)

#define boot_cpu_apicid boot_cpu_physical_apicid

#if APIC_DEBUG
 #define inquire_remote_apic(apicid) __inquire_remote_apic(apicid)
#else
 #define inquire_remote_apic(apicid) {}
#endif

#endif /* __ASM_MACH_WAKECPU_H */
