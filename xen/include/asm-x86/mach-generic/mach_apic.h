#ifndef __ASM_MACH_APIC_H
#define __ASM_MACH_APIC_H

#include <asm/genapic.h>

#define esr_disable (genapic->ESR_DISABLE)
#define NO_BALANCE_IRQ (genapic->no_balance_irq)
#define INT_DELIVERY_MODE (genapic->int_delivery_mode)
#define INT_DEST_MODE (genapic->int_dest_mode)
#undef APIC_DEST_LOGICAL
#define APIC_DEST_LOGICAL (genapic->apic_destination_logical)
#define TARGET_CPUS	  (genapic->target_cpus())
#define apic_id_registered (genapic->apic_id_registered)
#define init_apic_ldr (genapic->init_apic_ldr)
#define ioapic_phys_id_map (genapic->ioapic_phys_id_map)
#define clustered_apic_check (genapic->clustered_apic_check) 
#define apicid_to_node (genapic->apicid_to_node)
#define cpu_to_logical_apicid (genapic->cpu_to_logical_apicid) 
#define cpu_present_to_apicid (genapic->cpu_present_to_apicid)
#define apicid_to_cpu_present (genapic->apicid_to_cpu_present)
#define check_apicid_present (genapic->check_apicid_present)
#define check_phys_apicid_present (genapic->check_phys_apicid_present)
#define check_apicid_used (genapic->check_apicid_used)
#define cpu_mask_to_apicid (genapic->cpu_mask_to_apicid)
#define enable_apic_mode (genapic->enable_apic_mode)
#define phys_pkg_id (genapic->phys_pkg_id)

static inline int mpc_apic_id(struct mpc_config_processor *m, 
			struct mpc_config_translation *translation_record)
{
	printk("Processor #%d %d:%d APIC version %d\n",
			m->mpc_apicid,
			(m->mpc_cpufeature & CPU_FAMILY_MASK) >> 8,
			(m->mpc_cpufeature & CPU_MODEL_MASK) >> 4,
			m->mpc_apicver);
	return (m->mpc_apicid);
}

static inline void setup_portio_remap(void)
{
}

static inline int multi_timer_check(int apic, int irq)
{
	return 0;
}

extern void generic_bigsmp_probe(void);

#endif /* __ASM_MACH_APIC_H */
