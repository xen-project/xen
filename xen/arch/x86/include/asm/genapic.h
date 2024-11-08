#ifndef _ASM_GENAPIC_H
#define _ASM_GENAPIC_H 1

#include <xen/cpumask.h>

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

extern struct genapic genapic;
extern const struct genapic apic_default;
extern const struct genapic apic_bigsmp;

void cf_check send_IPI_self_legacy(uint8_t vector);

void cf_check init_apic_ldr_flat(void);
void cf_check send_IPI_mask_flat(const cpumask_t *cpumask, int vector);

void cf_check init_apic_ldr_phys(void);
unsigned int cf_check cpu_mask_to_apicid_phys(const cpumask_t *cpumask);
void cf_check send_IPI_mask_phys(const cpumask_t *mask, int vector);
const cpumask_t *cf_check vector_allocation_cpumask_phys(int cpu);

void generic_apic_probe(void);
void generic_bigsmp_probe(void);

#endif
