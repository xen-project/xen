/**
 * @file nmi_int.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon <levon@movementarian.org>
 *
 * Modified for Xen: by Aravind Menon & Jose Renato Santos
 *   These modifications are:
 *   Copyright (C) 2005 Hewlett-Packard Co.
 */

#include <xen/event.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/nmi.h>
#include <public/xen.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/regs.h>
#include <asm/current.h>
#include <xen/delay.h>
#include <xen/string.h>
 
#include "op_counter.h"
#include "op_x86_model.h"
 
static struct op_x86_model_spec const * model;
static struct op_msrs cpu_msrs[NR_CPUS];
static unsigned long saved_lvtpc[NR_CPUS];

#define VIRQ_BITMASK_SIZE (MAX_OPROF_DOMAINS/32 + 1)
extern int active_domains[MAX_OPROF_DOMAINS];
extern unsigned int adomains;
extern struct domain *adomain_ptrs[MAX_OPROF_DOMAINS];
extern unsigned long virq_ovf_pending[VIRQ_BITMASK_SIZE];
extern int is_active(struct domain *d);
extern int active_id(struct domain *d);
extern int is_profiled(struct domain *d);



static int nmi_callback(struct cpu_user_regs *regs, int cpu)
{
	int xen_mode, ovf;

	ovf = model->check_ctrs(cpu, &cpu_msrs[cpu], regs);
	xen_mode = ring_0(regs);
	if ( ovf && is_active(current->domain) && !xen_mode )
		send_guest_vcpu_virq(current, VIRQ_XENOPROF);

	return 1;
}
 
 
static void nmi_cpu_save_registers(struct op_msrs *msrs)
{
	unsigned int const nr_ctrs = model->num_counters;
	unsigned int const nr_ctrls = model->num_controls;
	struct op_msr *counters = msrs->counters;
	struct op_msr *controls = msrs->controls;
	unsigned int i;

	for (i = 0; i < nr_ctrs; ++i) {
		rdmsr(counters[i].addr,
			counters[i].saved.low,
			counters[i].saved.high);
	}
 
	for (i = 0; i < nr_ctrls; ++i) {
		rdmsr(controls[i].addr,
			controls[i].saved.low,
			controls[i].saved.high);
	}
}


static void nmi_save_registers(void * dummy)
{
	int cpu = smp_processor_id();
	struct op_msrs * msrs = &cpu_msrs[cpu];
	model->fill_in_addresses(msrs);
	nmi_cpu_save_registers(msrs);
}


static void free_msrs(void)
{
	int i;
	for (i = 0; i < NR_CPUS; ++i) {
		xfree(cpu_msrs[i].counters);
		cpu_msrs[i].counters = NULL;
		xfree(cpu_msrs[i].controls);
		cpu_msrs[i].controls = NULL;
	}
}


static int allocate_msrs(void)
{
	int success = 1;
	size_t controls_size = sizeof(struct op_msr) * model->num_controls;
	size_t counters_size = sizeof(struct op_msr) * model->num_counters;

	int i;
	for (i = 0; i < NR_CPUS; ++i) {
		if (!test_bit(i, &cpu_online_map))
			continue;

		cpu_msrs[i].counters = xmalloc_bytes(counters_size);
		if (!cpu_msrs[i].counters) {
			success = 0;
			break;
		}
		cpu_msrs[i].controls = xmalloc_bytes(controls_size);
		if (!cpu_msrs[i].controls) {
			success = 0;
			break;
		}
	}

	if (!success)
		free_msrs();

	return success;
}


static void nmi_cpu_setup(void * dummy)
{
	int cpu = smp_processor_id();
	struct op_msrs * msrs = &cpu_msrs[cpu];
	model->setup_ctrs(msrs);
}


int nmi_setup_events(void)
{
	on_each_cpu(nmi_cpu_setup, NULL, 0, 1);
	return 0;
}

int nmi_reserve_counters(void)
{
	if (!allocate_msrs())
		return -ENOMEM;

	/* We walk a thin line between law and rape here.
	 * We need to be careful to install our NMI handler
	 * without actually triggering any NMIs as this will
	 * break the core code horrifically.
	 */
	if (reserve_lapic_nmi() < 0) {
		free_msrs();
		return -EBUSY;
	}
	/* We need to serialize save and setup for HT because the subset
	 * of msrs are distinct for save and setup operations
	 */
	on_each_cpu(nmi_save_registers, NULL, 0, 1);
 	return 0;
}

int nmi_enable_virq(void)
{
	set_nmi_callback(nmi_callback);
	return 0;
}


void nmi_disable_virq(void)
{
	unset_nmi_callback();
} 


static void nmi_restore_registers(struct op_msrs * msrs)
{
	unsigned int const nr_ctrs = model->num_counters;
	unsigned int const nr_ctrls = model->num_controls;
	struct op_msr * counters = msrs->counters;
	struct op_msr * controls = msrs->controls;
	unsigned int i;

	for (i = 0; i < nr_ctrls; ++i) {
		wrmsr(controls[i].addr,
			controls[i].saved.low,
			controls[i].saved.high);
	}
 
	for (i = 0; i < nr_ctrs; ++i) {
		wrmsr(counters[i].addr,
			counters[i].saved.low,
			counters[i].saved.high);
	}
}
 

static void nmi_cpu_shutdown(void * dummy)
{
	int cpu = smp_processor_id();
	struct op_msrs * msrs = &cpu_msrs[cpu];
	nmi_restore_registers(msrs);
}

 
void nmi_release_counters(void)
{
	on_each_cpu(nmi_cpu_shutdown, NULL, 0, 1);
	release_lapic_nmi();
	free_msrs();
}

 
static void nmi_cpu_start(void * dummy)
{
	int cpu = smp_processor_id();
	struct op_msrs const * msrs = &cpu_msrs[cpu];
	saved_lvtpc[cpu] = apic_read(APIC_LVTPC);
	apic_write(APIC_LVTPC, APIC_DM_NMI);
	model->start(msrs);
}
 

int nmi_start(void)
{
	on_each_cpu(nmi_cpu_start, NULL, 0, 1);
	return 0;
}
 
 
static void nmi_cpu_stop(void * dummy)
{
	unsigned int v;
	int cpu = smp_processor_id();
	struct op_msrs const * msrs = &cpu_msrs[cpu];
	model->stop(msrs);

	/* restoring APIC_LVTPC can trigger an apic error because the delivery
	 * mode and vector nr combination can be illegal. That's by design: on
	 * power on apic lvt contain a zero vector nr which are legal only for
	 * NMI delivery mode. So inhibit apic err before restoring lvtpc
	 */
	if ( !(apic_read(APIC_LVTPC) & APIC_DM_NMI)
	     || (apic_read(APIC_LVTPC) & APIC_LVT_MASKED) )
	{
		printk("nmi_stop: APIC not good %ul\n", apic_read(APIC_LVTPC));
		mdelay(5000);
	}
	v = apic_read(APIC_LVTERR);
	apic_write(APIC_LVTERR, v | APIC_LVT_MASKED);
	apic_write(APIC_LVTPC, saved_lvtpc[cpu]);
	apic_write(APIC_LVTERR, v);
}
 
 
void nmi_stop(void)
{
	on_each_cpu(nmi_cpu_stop, NULL, 0, 1);
}


struct op_counter_config counter_config[OP_MAX_COUNTER];

static int __init p4_init(char * cpu_type)
{ 
	__u8 cpu_model = current_cpu_data.x86_model;

	if ((cpu_model > 6) || (cpu_model == 5)) {
		printk("xenoprof: Initialization failed. "
		       "Intel processor model %d for pentium 4 family is not "
		       "supported\n", cpu_model);
		return 0;
	}

#ifndef CONFIG_SMP
	strlcpy (cpu_type, "i386/p4", XENOPROF_CPU_TYPE_SIZE);
	model = &op_p4_spec;
	return 1;
#else
	switch (smp_num_siblings) {
		case 1:
			strlcpy (cpu_type, "i386/p4", 
				 XENOPROF_CPU_TYPE_SIZE);
			model = &op_p4_spec;
			return 1;

		case 2:
			strlcpy (cpu_type, "i386/p4-ht", 
				 XENOPROF_CPU_TYPE_SIZE);
			model = &op_p4_ht2_spec;
			return 1;
	}
#endif
	printk("Xenoprof ERROR: P4 HyperThreading detected with > 2 threads\n");

	return 0;
}


static int __init ppro_init(char *cpu_type)
{
	__u8 cpu_model = current_cpu_data.x86_model;

	if (cpu_model > 15) {
		printk("xenoprof: Initialization failed. "
		       "Intel processor model %d for P6 class family is not "
		       "supported\n", cpu_model);
		return 0;
	}
	else if (cpu_model == 15)
		strlcpy (cpu_type, "i386/core_2", XENOPROF_CPU_TYPE_SIZE);
	else if (cpu_model == 14)
		strlcpy (cpu_type, "i386/core", XENOPROF_CPU_TYPE_SIZE);
	else if (cpu_model == 9)
		strlcpy (cpu_type, "i386/p6_mobile", XENOPROF_CPU_TYPE_SIZE);
	else if (cpu_model > 5)
		strlcpy (cpu_type, "i386/piii", XENOPROF_CPU_TYPE_SIZE);
	else if (cpu_model > 2)
		strlcpy (cpu_type, "i386/pii", XENOPROF_CPU_TYPE_SIZE);
	else
		strlcpy (cpu_type, "i386/ppro", XENOPROF_CPU_TYPE_SIZE);

	model = &op_ppro_spec;
	return 1;
}

int nmi_init(int *num_events, int *is_primary, char *cpu_type)
{
	__u8 vendor = current_cpu_data.x86_vendor;
	__u8 family = current_cpu_data.x86;
	int prim = 0;
 
	if (!cpu_has_apic) {
		printk("xenoprof: Initialization failed. No apic.\n");
		return -ENODEV;
	}

	if (xenoprof_primary_profiler == NULL) {
		/* For now, only dom0 can be the primary profiler */
		if (current->domain->domain_id == 0) {
			xenoprof_primary_profiler = current->domain;
			prim = 1;
		}
	}
 
	switch (vendor) {
		case X86_VENDOR_AMD:
			/* Needs to be at least an Athlon (or hammer in 32bit mode) */

			switch (family) {
			default:
				printk("xenoprof: Initialization failed. "
				       "AMD processor family %d is not "
				       "supported\n", family);
				return -ENODEV;
			case 6:
				model = &op_athlon_spec;
				strlcpy (cpu_type, "i386/athlon", 
					 XENOPROF_CPU_TYPE_SIZE);
				break;
			case 0xf:
				model = &op_athlon_spec;
				/* Actually it could be i386/hammer too, but give
				   user space an consistent name. */
				strlcpy (cpu_type, "x86-64/hammer", 
					 XENOPROF_CPU_TYPE_SIZE);
				break;
			}
			break;
 
		case X86_VENDOR_INTEL:
			switch (family) {
				/* Pentium IV */
				case 0xf:
					if (!p4_init(cpu_type))
						return -ENODEV;
					break;

				/* A P6-class processor */
				case 6:
					if (!ppro_init(cpu_type))
						return -ENODEV;
					break;

				default:
				printk("xenoprof: Initialization failed. "
				       "Intel processor family %d is not "
				       "supported\n", family);
					return -ENODEV;
			}
			break;

		default:
			printk("xenoprof: Initialization failed. "
			       "Unsupported processor. Unknown vendor %d\n",
				vendor);
			return -ENODEV;
	}

	*num_events = model->num_counters;
	*is_primary = prim;

	return 0;
}

