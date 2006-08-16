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
	char *name;
	int (*probe)(void);

	/* When one of the next two hooks returns 1 the genapic
	   is switched to this. Essentially they are additional probe 
	   functions. */
	int (*mps_oem_check)(struct mp_config_table *mpc, char *oem, 
			      char *productid);
	int (*acpi_madt_oem_check)(char *oem_id, char *oem_table_id);

	/* Interrupt delivery parameters ('physical' vs. 'logical flat'). */
	int int_delivery_mode;
	int int_dest_mode;
	void (*init_apic_ldr)(void);
	void (*clustered_apic_check)(void);
	cpumask_t (*target_cpus)(void);
	unsigned int (*cpu_mask_to_apicid)(cpumask_t cpumask);
	void (*send_IPI_mask)(cpumask_t mask, int vector);
};

#define APICFUNC(x) .x = x

#define APIC_INIT(aname, aprobe) \
	.name = aname, \
	.probe = aprobe, \
	APICFUNC(mps_oem_check), \
	APICFUNC(acpi_madt_oem_check)

extern struct genapic *genapic;

void init_apic_ldr_flat(void);
void clustered_apic_check_flat(void);
cpumask_t target_cpus_flat(void);
unsigned int cpu_mask_to_apicid_flat(cpumask_t cpumask);
void send_IPI_mask_flat(cpumask_t mask, int vector);
#define GENAPIC_FLAT \
	.int_delivery_mode = dest_LowestPrio, \
	.int_dest_mode = 1 /* logical delivery */, \
	.init_apic_ldr = init_apic_ldr_flat, \
	.clustered_apic_check = clustered_apic_check_flat, \
	.target_cpus = target_cpus_flat, \
	.cpu_mask_to_apicid = cpu_mask_to_apicid_flat, \
	.send_IPI_mask = send_IPI_mask_flat

void init_apic_ldr_phys(void);
void clustered_apic_check_phys(void);
cpumask_t target_cpus_phys(void);
unsigned int cpu_mask_to_apicid_phys(cpumask_t cpumask);
void send_IPI_mask_phys(cpumask_t mask, int vector);
#define GENAPIC_PHYS \
	.int_delivery_mode = dest_Fixed, \
	.int_dest_mode = 0 /* physical delivery */, \
	.init_apic_ldr = init_apic_ldr_phys, \
	.clustered_apic_check = clustered_apic_check_phys, \
	.target_cpus = target_cpus_phys, \
	.cpu_mask_to_apicid = cpu_mask_to_apicid_phys, \
	.send_IPI_mask = send_IPI_mask_phys

#endif
