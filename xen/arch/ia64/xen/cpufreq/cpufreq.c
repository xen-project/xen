/*
 * arch/ia64/kernel/cpufreq/acpi-cpufreq.c
 * This file provides the ACPI based P-state support. This
 * module works with generic cpufreq infrastructure. Most of
 * the code is based on i386 version
 * (arch/i386/kernel/cpu/cpufreq/acpi-cpufreq.c)
 *
 * Copyright (C) 2005 Intel Corp
 *      Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *
 * Sep 2008 - Liu Jinsong <jinsong.liu@intel.com>
 *      porting IPF acpi-cpufreq.c from Linux 2.6.23 to Xen hypervisor
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/xmalloc.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <asm/config.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <asm/pal.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

static struct acpi_cpufreq_data *drv_data[NR_CPUS];

static struct cpufreq_driver acpi_cpufreq_driver;

static int
processor_get_pstate (u32 *value)
{
	u64 pstate_index = 0;
	s64 retval;

	retval = ia64_pal_get_pstate(&pstate_index,
			PAL_GET_PSTATE_TYPE_INSTANT);
	*value = (u32) pstate_index;

	if (retval)
		printk("Failed to get current freq\n");

	return (int)retval;
}

static unsigned int
extract_clock (unsigned value)
{
	unsigned long i;
	unsigned int cpu;
	struct processor_performance *perf;

	cpu = smp_processor_id();
	perf = &processor_pminfo[cpu]->perf;

	for (i = 0; i < perf->state_count; i++) {
		if (value == perf->states[i].status)
			return perf->states[i].core_frequency;
	}
	return perf->states[i-1].core_frequency;
}

static void
processor_get_freq (void *data)
{
	unsigned int *freq = data;
	int ret = 0;
	u32 value = 0;
	unsigned int clock_freq;

	ret = processor_get_pstate(&value);
	if (ret) {
		*freq = 0;
		return;
	}

	clock_freq = extract_clock(value);
	*freq = (clock_freq*1000);
	return;
}

static unsigned int
acpi_cpufreq_get (unsigned int cpu)
{
	unsigned int freq;

	if (!cpu_online(cpu))
		return 0;

	if (cpu == smp_processor_id())
		processor_get_freq((void*)&freq);
	else
		smp_call_function_single(cpu, processor_get_freq, &freq, 1);

	return freq;
}

static void
processor_set_pstate (void *data)
{
	u32 *value = data;
	s64 retval;

	retval = ia64_pal_set_pstate((u64)*value);

	if (retval)
		*value = 1;
	else
		*value = 0;
}

static int
processor_set_freq (struct acpi_cpufreq_data *data,
		struct cpufreq_policy *policy, int state)
{
	u32 value = 0;
	unsigned int cpu = policy->cpu;

	if (!cpu_online(cpu))
		return -ENODEV;

	if (state == data->acpi_data->state) {
		if (unlikely(policy->resume)) {
			printk(KERN_INFO
			       "Called after resume, resetting to P%d\n",
			       state);
			policy->resume = 0;
		} else {
			printk(KERN_DEBUG"Already at target state (P%d)\n",
			       state);
			return 0;
		}
	}

	value = (u32) data->acpi_data->states[state].control;

	if (cpu == smp_processor_id())
		processor_set_pstate((void *)&value);
	else
		smp_call_function_single(cpu, processor_set_pstate, &value, 1);

	if (value) {
		printk(KERN_WARNING "Transition failed\n");
		return -ENODEV;
	}

	cpufreq_statistic_update(cpu, data->acpi_data->state, state);

	data->acpi_data->state = state;
	policy->cur = data->freq_table[state].frequency;

	return 0;
}

static int
acpi_cpufreq_target (struct cpufreq_policy *policy,
		unsigned int target_freq, unsigned int relation)
{
	struct acpi_cpufreq_data *data = drv_data[policy->cpu];
	unsigned int next_state = 0;
	unsigned int result = 0;

	result = cpufreq_frequency_table_target(policy,
			data->freq_table, target_freq, relation, &next_state);
	if (result)
		return (result);

	result = processor_set_freq(data, policy, next_state);

	return (result);
}

static int
acpi_cpufreq_verify (struct cpufreq_policy *policy)
{
	struct acpi_cpufreq_data *data = drv_data[policy->cpu];
	struct processor_performance *perf =
		&processor_pminfo[policy->cpu]->perf;

	if (!policy || !data)
		return -EINVAL;

	cpufreq_verify_within_limits(policy, 0,
			perf->states[perf->platform_limit].core_frequency * 1000);

	return cpufreq_frequency_table_verify(policy, data->freq_table);
}

static int
acpi_cpufreq_cpu_init (struct cpufreq_policy *policy)
{
	unsigned int i;
	unsigned int cpu = policy->cpu;
	unsigned int result = 0;
	struct acpi_cpufreq_data *data;

	data = xmalloc(struct acpi_cpufreq_data);
	if (!data)
		return -ENOMEM;
	memset(data, 0, sizeof(struct acpi_cpufreq_data));

	drv_data[cpu] = data;

	data->acpi_data = &processor_pminfo[cpu]->perf;

	data->freq_table = xmalloc_array(struct cpufreq_frequency_table,
			(data->acpi_data->state_count + 1));
	if (!data->freq_table) {
		result = -ENOMEM;
		goto err_unreg;
	}

	/* detect transition latency */
	policy->cpuinfo.transition_latency = 0;
	for (i=0; i<data->acpi_data->state_count; i++) {
		if ((data->acpi_data->states[i].transition_latency * 1000) >
				policy->cpuinfo.transition_latency) {
			policy->cpuinfo.transition_latency =
				data->acpi_data->states[i].transition_latency * 1000;
		}
	}

	policy->governor = cpufreq_opt_governor ? : CPUFREQ_DEFAULT_GOVERNOR;

	policy->cur = acpi_cpufreq_get(policy->cpu);
	printk(KERN_INFO "Current freq of CPU %u is %u\n", cpu, policy->cur);

	/* table init */
	for (i = 0; i <= data->acpi_data->state_count; i++) {
		data->freq_table[i].index = i;
		if (i < data->acpi_data->state_count) {
			data->freq_table[i].frequency =
				data->acpi_data->states[i].core_frequency * 1000;
		} else {
			data->freq_table[i].frequency = CPUFREQ_TABLE_END;
		}
	}

	result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
	if (result)
		goto err_freqfree;

	data->acpi_data->state = 0;
	policy->resume = 1;

	return result;

err_freqfree:
	xfree(data->freq_table);
err_unreg:
	xfree(data);
	drv_data[cpu] = NULL;

	return result;
}

static int
acpi_cpufreq_cpu_exit (struct cpufreq_policy *policy)
{
	struct acpi_cpufreq_data *data = drv_data[policy->cpu];

	if (data) {
		drv_data[policy->cpu] = NULL;
		xfree(data->freq_table);
		xfree(data);
	}

	return 0;
}

static struct cpufreq_driver acpi_cpufreq_driver = {
	.name       = "acpi-cpufreq",
	.verify     = acpi_cpufreq_verify,
	.target     = acpi_cpufreq_target,
	.get        = acpi_cpufreq_get,
	.init       = acpi_cpufreq_cpu_init,
	.exit       = acpi_cpufreq_cpu_exit,
};

static int __init cpufreq_driver_init(void)
{
	int ret = 0;

	if (cpufreq_controller == FREQCTL_xen)
		ret = cpufreq_register_driver(&acpi_cpufreq_driver);

	return ret;
}

__initcall(cpufreq_driver_init);

int cpufreq_cpu_init(unsigned int cpuid)
{
	return cpufreq_add_cpu(cpuid);
}
