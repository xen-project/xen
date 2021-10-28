#ifndef _ASM_GENAPIC_H
#define _ASM_GENAPIC_H 1

/*
 * Generic APIC driver interface.
 *
 * An straight forward mapping of the APIC related parts of the
 * x86 subarchitecture interface to a dynamic object.
 *
 * This is used by the "generic" x86 subarchitecture.
 *
 * Copyright 2003 Andi Kleen, SuSE Labs.
 */

struct mpc_config_translation;
struct mpc_config_bus;
struct mp_config_table;
struct mpc_config_processor;

struct genapic { 
	const char *name;
	int (*probe)(void);

	/* Interrupt delivery parameters ('physical' vs. 'logical flat'). */
	int int_delivery_mode;
	int int_dest_mode;
	void (*init_apic_ldr)(void);
	const cpumask_t *(*vector_allocation_cpumask)(int cpu);
	unsigned int (*cpu_mask_to_apicid)(const cpumask_t *cpumask);
	void (*send_IPI_mask)(const cpumask_t *mask, int vector);
    void (*send_IPI_self)(uint8_t vector);
};

#define APIC_INIT(aname, aprobe) \
	.name = aname, \
	.probe = aprobe

extern struct genapic genapic;
extern const struct genapic apic_default;
extern const struct genapic apic_bigsmp;

void cf_check send_IPI_self_legacy(uint8_t vector);

void cf_check init_apic_ldr_flat(void);
unsigned int cf_check cpu_mask_to_apicid_flat(const cpumask_t *cpumask);
void cf_check send_IPI_mask_flat(const cpumask_t *mask, int vector);
const cpumask_t *cf_check vector_allocation_cpumask_flat(int cpu);
#define GENAPIC_FLAT \
	.int_delivery_mode = dest_LowestPrio, \
	.int_dest_mode = 1 /* logical delivery */, \
	.init_apic_ldr = init_apic_ldr_flat, \
	.vector_allocation_cpumask = vector_allocation_cpumask_flat, \
	.cpu_mask_to_apicid = cpu_mask_to_apicid_flat, \
	.send_IPI_mask = send_IPI_mask_flat, \
	.send_IPI_self = send_IPI_self_legacy

void cf_check init_apic_ldr_phys(void);
unsigned int cf_check cpu_mask_to_apicid_phys(const cpumask_t *cpumask);
void cf_check send_IPI_mask_phys(const cpumask_t *mask, int vector);
const cpumask_t *cf_check vector_allocation_cpumask_phys(int cpu);
#define GENAPIC_PHYS \
	.int_delivery_mode = dest_Fixed, \
	.int_dest_mode = 0 /* physical delivery */, \
	.init_apic_ldr = init_apic_ldr_phys, \
	.vector_allocation_cpumask = vector_allocation_cpumask_phys, \
	.cpu_mask_to_apicid = cpu_mask_to_apicid_phys, \
	.send_IPI_mask = send_IPI_mask_phys, \
	.send_IPI_self = send_IPI_self_legacy

#endif
