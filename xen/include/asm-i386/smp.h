#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#include <xeno/config.h>
#include <asm/ptrace.h>

#ifdef CONFIG_SMP
#define TARGET_CPUS cpu_online_map
#else
#define TARGET_CPUS 0x01
#endif

#ifdef CONFIG_SMP
/*
 * Private routines/data
 */
 
extern void smp_alloc_memory(void);
extern unsigned long phys_cpu_present_map;
extern unsigned long cpu_online_map;
extern volatile unsigned long smp_invalidate_needed;
extern int pic_mode;
extern void smp_flush_tlb(void);
extern void smp_message_irq(int cpl, void *dev_id, struct pt_regs *regs);
extern void smp_invalidate_rcv(void);		/* Process an NMI */
extern void (*mtrr_hook) (void);
extern void zap_low_mappings (void);

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
 
extern void smp_boot_cpus(void);
extern void smp_store_cpu_info(int id);		/* Store per CPU info (like the initial udelay numbers */

/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup. We map APIC_BASE very early in page_setup(),
 * so this is correct in the x86 case.
 */

#define smp_processor_id() (current->processor)

#include <asm/fixmap.h>
#include <asm/apic.h>

static __inline int hard_smp_processor_id(void)
{
	/* we don't want to mark this access volatile - bad code generation */
	return GET_APIC_ID(*(unsigned long *)(APIC_BASE+APIC_ID));
}

static __inline int logical_smp_processor_id(void)
{
	/* we don't want to mark this access volatile - bad code generation */
	return GET_APIC_LOGICAL_ID(*(unsigned long *)(APIC_BASE+APIC_LDR));
}

#endif
#endif
