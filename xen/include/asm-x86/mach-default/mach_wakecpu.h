#ifndef __ASM_MACH_WAKECPU_H
#define __ASM_MACH_WAKECPU_H

/* 
 * This file copes with machines that wakeup secondary CPUs by the
 * INIT, INIT, STARTUP sequence.
 */

#define TRAMPOLINE_LOW maddr_to_virt(0x467)
#define TRAMPOLINE_HIGH maddr_to_virt(0x469)

#endif /* __ASM_MACH_WAKECPU_H */
