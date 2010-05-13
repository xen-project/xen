/*
 *  powernow - AMD Architectural P-state Driver ($Revision: 1.4 $)
 *
 *  Copyright (C) 2008 Mark Langsdorf <mark.langsdorf@amd.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/timer.h>
#include <xen/xmalloc.h>
#include <asm/bug.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/config.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <asm/cpufeature.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

#define CPUID_6_ECX_APERFMPERF_CAPABILITY       (0x1)
#define CPUID_FREQ_VOLT_CAPABILITIES    0x80000007
#define CPB_CAPABLE             0x00000200
#define USE_HW_PSTATE           0x00000080
#define HW_PSTATE_MASK          0x00000007
#define HW_PSTATE_VALID_MASK    0x80000000
#define HW_PSTATE_MAX_MASK      0x000000f0
#define HW_PSTATE_MAX_SHIFT     4
#define MSR_PSTATE_DEF_BASE     0xc0010064 /* base of Pstate MSRs */
#define MSR_PSTATE_STATUS       0xc0010063 /* Pstate Status MSR */
#define MSR_PSTATE_CTRL         0xc0010062 /* Pstate control MSR */
#define MSR_PSTATE_CUR_LIMIT    0xc0010061 /* pstate current limit MSR */
#define MSR_HWCR_CPBDIS_MASK    0x02000000

struct powernow_cpufreq_data {
    struct processor_performance *acpi_data;
    struct cpufreq_frequency_table *freq_table;
    unsigned int max_freq;
    unsigned int resume;
    unsigned int cpu_feature;
};

static struct powernow_cpufreq_data *drv_data[NR_CPUS];

static struct cpufreq_driver powernow_cpufreq_driver;

struct drv_cmd {
    unsigned int type;
    cpumask_t mask;
    u32 val;
    int turbo;
};

static void transition_pstate(void *drvcmd)
{
    struct drv_cmd *cmd;
    cmd = (struct drv_cmd *) drvcmd;

    if (cmd->turbo != CPUFREQ_TURBO_UNSUPPORTED) {
        u32 lo, hi;
        rdmsr(MSR_K8_HWCR, lo, hi);
        if (cmd->turbo == CPUFREQ_TURBO_ENABLED)
            lo &= ~MSR_HWCR_CPBDIS_MASK;
        else
            lo |= MSR_HWCR_CPBDIS_MASK; 
        wrmsr(MSR_K8_HWCR, lo, hi);
    }
    wrmsr(MSR_PSTATE_CTRL, cmd->val, 0);
}

static int powernow_cpufreq_target(struct cpufreq_policy *policy,
                               unsigned int target_freq, unsigned int relation)
{
    struct powernow_cpufreq_data *data = drv_data[policy->cpu];
    struct processor_performance *perf;
    struct cpufreq_freqs freqs;
    cpumask_t online_policy_cpus;
    struct drv_cmd cmd;
    unsigned int next_state = 0; /* Index into freq_table */
    unsigned int next_perf_state = 0; /* Index into perf table */
    int result = 0;
    int j = 0;

    if (unlikely(data == NULL ||
        data->acpi_data == NULL || data->freq_table == NULL)) {
        return -ENODEV;
    }

    perf = data->acpi_data;
    result = cpufreq_frequency_table_target(policy,
                                            data->freq_table,
                                            target_freq,
                                            relation, &next_state);
    if (unlikely(result))
        return -ENODEV;

    online_policy_cpus = policy->cpus;

    next_perf_state = data->freq_table[next_state].index;
    if (perf->state == next_perf_state) {
        if (unlikely(data->resume)) 
            data->resume = 0;
        else
            return 0;
    }

    cpus_clear(cmd.mask);

    if (policy->shared_type != CPUFREQ_SHARED_TYPE_ANY)
        cmd.mask = online_policy_cpus;
    else
        cpu_set(policy->cpu, cmd.mask);

    freqs.old = perf->states[perf->state].core_frequency * 1000;
    freqs.new = data->freq_table[next_state].frequency;

    cmd.val = next_perf_state;
    cmd.turbo = policy->turbo;

    on_selected_cpus(&cmd.mask, transition_pstate, &cmd, 1);

    for_each_cpu_mask(j, online_policy_cpus)
        cpufreq_statistic_update(j, perf->state, next_perf_state);

    perf->state = next_perf_state;
    policy->cur = freqs.new;

    return result;
}

static int powernow_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct powernow_cpufreq_data *data;
    struct processor_performance *perf;

    if (!policy || !(data = drv_data[policy->cpu]) ||
        !processor_pminfo[policy->cpu])
        return -EINVAL;

    perf = &processor_pminfo[policy->cpu]->perf;

    cpufreq_verify_within_limits(policy, 0, 
        perf->states[perf->platform_limit].core_frequency * 1000);

    return cpufreq_frequency_table_verify(policy, data->freq_table);
}

static void feature_detect(void *info)
{
    struct cpufreq_policy *policy = info;
    unsigned int ecx, edx;

    ecx = cpuid_ecx(6);
    if (ecx & CPUID_6_ECX_APERFMPERF_CAPABILITY) {
        policy->aperf_mperf = 1;
        powernow_cpufreq_driver.getavg = get_measured_perf;
    }

    edx = cpuid_edx(CPUID_FREQ_VOLT_CAPABILITIES);
    if ((edx & CPB_CAPABLE) == CPB_CAPABLE) {
        policy->turbo = CPUFREQ_TURBO_ENABLED;
        if (cpufreq_verbose)
            printk(XENLOG_INFO
                   "CPU%u: Core Boost/Turbo detected and enabled\n",
                   smp_processor_id());
    }
}

static int powernow_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int i;
    unsigned int valid_states = 0;
    unsigned int cpu = policy->cpu;
    struct powernow_cpufreq_data *data;
    unsigned int result = 0;
    struct processor_performance *perf;
    u32 max_hw_pstate, hi = 0, lo = 0;
    struct cpuinfo_x86 *c = &cpu_data[policy->cpu];

    data = xmalloc(struct powernow_cpufreq_data);
    if (!data)
        return -ENOMEM;
    memset(data, 0, sizeof(struct powernow_cpufreq_data));

    drv_data[cpu] = data;

    data->acpi_data = &processor_pminfo[cpu]->perf;

    perf = data->acpi_data;
    policy->shared_type = perf->shared_type;

    /*
     * Will let policy->cpus know about dependency only when software
     * coordination is required.
     */
    if (policy->shared_type == CPUFREQ_SHARED_TYPE_ALL ||
        policy->shared_type == CPUFREQ_SHARED_TYPE_ANY) {
        policy->cpus = perf->shared_cpu_map;
    } else {
        policy->cpus = cpumask_of_cpu(cpu);    
    }

    /* capability check */
    if (perf->state_count <= 1) {
        printk("No P-States\n");
        result = -ENODEV;
        goto err_unreg;
    }
    rdmsr(MSR_PSTATE_CUR_LIMIT, hi, lo);
    max_hw_pstate = (hi & HW_PSTATE_MAX_MASK) >> HW_PSTATE_MAX_SHIFT;

    if (perf->control_register.space_id != perf->status_register.space_id) {
        result = -ENODEV;
        goto err_unreg;
    }

    data->freq_table = xmalloc_array(struct cpufreq_frequency_table, 
                                    (perf->state_count+1));
    if (!data->freq_table) {
        result = -ENOMEM;
        goto err_unreg;
    }

    /* detect transition latency */
    policy->cpuinfo.transition_latency = 0;
    for (i=0; i<perf->state_count; i++) {
        if ((perf->states[i].transition_latency * 1000) >
            policy->cpuinfo.transition_latency)
            policy->cpuinfo.transition_latency =
                perf->states[i].transition_latency * 1000;
    }

    policy->governor = cpufreq_opt_governor ? : CPUFREQ_DEFAULT_GOVERNOR;

    data->max_freq = perf->states[0].core_frequency * 1000;
    /* table init */
    for (i = 0; i < perf->state_count && i <= max_hw_pstate; i++) {
        if (i > 0 && perf->states[i].core_frequency >=
            data->freq_table[valid_states-1].frequency / 1000)
            continue;

        data->freq_table[valid_states].index = perf->states[i].control & HW_PSTATE_MASK;
        data->freq_table[valid_states].frequency =
            perf->states[i].core_frequency * 1000;
        valid_states++;
    }
    data->freq_table[valid_states].frequency = CPUFREQ_TABLE_END;
    perf->state = 0;

    result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
    if (result)
        goto err_freqfree;

    if (c->cpuid_level >= 6)
        on_selected_cpus(cpumask_of(cpu), feature_detect, policy, 1);
      
    /*
     * the first call to ->target() should result in us actually
     * writing something to the appropriate registers.
     */
    data->resume = 1;

    policy->cur = data->freq_table[i].frequency;
    return result;

err_freqfree:
    xfree(data->freq_table);
err_unreg:
    xfree(data);
    drv_data[cpu] = NULL;

    return result;
}

static int powernow_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    struct powernow_cpufreq_data *data = drv_data[policy->cpu];

    if (data) {
        drv_data[policy->cpu] = NULL;
        xfree(data->freq_table);
        xfree(data);
    }

    return 0;
}

static struct cpufreq_driver powernow_cpufreq_driver = {
    .verify = powernow_cpufreq_verify,
    .target = powernow_cpufreq_target,
    .init   = powernow_cpufreq_cpu_init,
    .exit   = powernow_cpufreq_cpu_exit
};

unsigned int powernow_register_driver()
{
    unsigned int i, ret = 0;

    for_each_online_cpu(i) {
        struct cpuinfo_x86 *c = &cpu_data[i];
        if (c->x86_vendor != X86_VENDOR_AMD)
            ret = -ENODEV;
        else
        {
            u32 eax, ebx, ecx, edx;
            cpuid(CPUID_FREQ_VOLT_CAPABILITIES, &eax, &ebx, &ecx, &edx);
            if ((edx & USE_HW_PSTATE) != USE_HW_PSTATE)
                ret = -ENODEV;
        }
        if (ret)
            return ret;
    }

    ret = cpufreq_register_driver(&powernow_cpufreq_driver);
    return ret;
}
