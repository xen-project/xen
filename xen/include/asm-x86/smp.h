#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <asm/fixmap.h>
#include <asm/mpspec.h>
#include <asm/io_apic.h>
#include <asm/apic.h>
#endif

#ifdef CONFIG_SMP
#ifndef __ASSEMBLY__

/*
 * Private routines/data
 */
 
extern void smp_alloc_memory(void);
extern unsigned long phys_cpu_present_map;
extern unsigned long cpu_online_map;
extern volatile unsigned long smp_invalidate_needed;
extern int pic_mode;
extern int smp_num_siblings;
extern int cpu_sibling_map[];

/*
 * On x86 all CPUs are mapped 1:1 to the APIC space.
 * This simplifies scheduling and IPI sending and
 * compresses data structures.
 */
static inline int cpu_logical_map(int cpu)
{
	return cpu;
}
static inline int cpu_number_map(int cpu)
{
	return cpu;
}

/*
 * Some lowlevel functions might want to know about
 * the real APIC ID <-> CPU # mapping.
 */
#define MAX_APICID 256
extern volatile int cpu_to_physical_apicid[NR_CPUS];
extern volatile int physical_apicid_to_cpu[MAX_APICID];
extern volatile int cpu_to_logical_apicid[NR_CPUS];
extern volatile int logical_apicid_to_cpu[MAX_APICID];

/*
 * General functions that each host system must provide.
 */
 
/*extern void smp_boot_cpus(void);*/
extern void smp_store_cpu_info(int id);		/* Store per CPU info (like the initial udelay numbers */

/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup. We map APIC_BASE very early in page_setup(),
 * so this is correct in the x86 case.
 */

#define smp_processor_id() (current->processor)

static __inline int hard_smp_processor_id(void)
{
	/* we don't want to mark this access volatile - bad code generation */
	return GET_APIC_ID(*(unsigned *)(APIC_BASE+APIC_ID));
}

static __inline int logical_smp_processor_id(void)
{
	/* we don't want to mark this access volatile - bad code generation */
	return GET_APIC_LOGICAL_ID(*(unsigned *)(APIC_BASE+APIC_LDR));
}

#endif /* !__ASSEMBLY__ */

#define NO_PROC_ID		0xFF		/* No processor magic marker */

/*
 *	This magic constant controls our willingness to transfer
 *	a process across CPUs. Such a transfer incurs misses on the L1
 *	cache, and on a P6 or P5 with multiple L2 caches L2 hits. My
 *	gut feeling is this will vary by board in value. For a board
 *	with separate L2 cache it probably depends also on the RSS, and
 *	for a board with shared L2 cache it ought to decay fast as other
 *	processes are run.
 */
 
#define PROC_CHANGE_PENALTY	15		/* Schedule penalty */

#endif
#endif
