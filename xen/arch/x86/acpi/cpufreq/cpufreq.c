/*
 *  cpufreq.c - ACPI Processor P-States Driver ($Revision: 1.4 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2002 - 2004 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2006        Denis Sadykov <denis.m.sadykov@intel.com>
 *
 *  Feb 2008 - Liu Jinsong <jinsong.liu@intel.com>
 *      porting acpi-cpufreq.c from Linux 2.6.23 to Xen hypervisor
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
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/xmalloc.h>
#include <asm/bug.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

enum {
    UNDEFINED_CAPABLE = 0,
    SYSTEM_INTEL_MSR_CAPABLE,
    SYSTEM_IO_CAPABLE,
};

#define INTEL_MSR_RANGE         (0xffffull)

struct acpi_cpufreq_data *cpufreq_drv_data[NR_CPUS];

static bool __read_mostly acpi_pstate_strict;
boolean_param("acpi_pstate_strict", acpi_pstate_strict);

static int check_est_cpu(unsigned int cpuid)
{
    struct cpuinfo_x86 *cpu = &cpu_data[cpuid];

    if (cpu->x86_vendor != X86_VENDOR_INTEL ||
        !cpu_has(cpu, X86_FEATURE_EIST))
        return 0;

    return 1;
}

static unsigned extract_io(u32 value, struct acpi_cpufreq_data *data)
{
    struct processor_performance *perf;
    int i;

    perf = data->acpi_data;

    for (i=0; i<perf->state_count; i++) {
        if (value == perf->states[i].status)
            return data->freq_table[i].frequency;
    }
    return 0;
}

static unsigned extract_msr(u32 msr, struct acpi_cpufreq_data *data)
{
    int i;
    struct processor_performance *perf;

    msr &= INTEL_MSR_RANGE;
    perf = data->acpi_data;

    for (i=0; data->freq_table[i].frequency != CPUFREQ_TABLE_END; i++) {
        if (msr == perf->states[data->freq_table[i].index].status)
            return data->freq_table[i].frequency;
    }
    return data->freq_table[0].frequency;
}

static unsigned extract_freq(u32 val, struct acpi_cpufreq_data *data)
{
    switch (data->arch_cpu_flags) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        return extract_msr(val, data);
    case SYSTEM_IO_CAPABLE:
        return extract_io(val, data);
    default:
        return 0;
    }
}

struct msr_addr {
    u32 reg;
};

struct io_addr {
    u16 port;
    u8 bit_width;
};

typedef union {
    struct msr_addr msr;
    struct io_addr io;
} drv_addr_union;

struct drv_cmd {
    unsigned int type;
    const cpumask_t *mask;
    drv_addr_union addr;
    u32 val;
};

static void do_drv_read(void *drvcmd)
{
    struct drv_cmd *cmd;

    cmd = (struct drv_cmd *)drvcmd;

    switch (cmd->type) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        rdmsrl(cmd->addr.msr.reg, cmd->val);
        break;
    case SYSTEM_IO_CAPABLE:
        acpi_os_read_port((acpi_io_address)cmd->addr.io.port,
            &cmd->val, (u32)cmd->addr.io.bit_width);
        break;
    default:
        break;
    }
}

static void do_drv_write(void *drvcmd)
{
    struct drv_cmd *cmd;
    uint64_t msr_content;

    cmd = (struct drv_cmd *)drvcmd;

    switch (cmd->type) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        rdmsrl(cmd->addr.msr.reg, msr_content);
        msr_content = (msr_content & ~INTEL_MSR_RANGE)
            | (cmd->val & INTEL_MSR_RANGE);
        wrmsrl(cmd->addr.msr.reg, msr_content);
        break;
    case SYSTEM_IO_CAPABLE:
        acpi_os_write_port((acpi_io_address)cmd->addr.io.port,
            cmd->val, (u32)cmd->addr.io.bit_width);
        break;
    default:
        break;
    }
}

static void drv_read(struct drv_cmd *cmd)
{
    cmd->val = 0;

    ASSERT(cpumask_weight(cmd->mask) == 1);

    /* to reduce IPI for the sake of performance */
    if (likely(cpumask_test_cpu(smp_processor_id(), cmd->mask)))
        do_drv_read((void *)cmd);
    else
        on_selected_cpus(cmd->mask, do_drv_read, cmd, 1);
}

static void drv_write(struct drv_cmd *cmd)
{
    if (cpumask_equal(cmd->mask, cpumask_of(smp_processor_id())))
        do_drv_write((void *)cmd);
    else
        on_selected_cpus(cmd->mask, do_drv_write, cmd, 1);
}

static u32 get_cur_val(const cpumask_t *mask)
{
    struct cpufreq_policy *policy;
    struct processor_performance *perf;
    struct drv_cmd cmd;
    unsigned int cpu = smp_processor_id();

    if (unlikely(cpumask_empty(mask)))
        return 0;

    if (!cpumask_test_cpu(cpu, mask))
        cpu = cpumask_first(mask);
    if (cpu >= nr_cpu_ids || !cpu_online(cpu))
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if (!policy || !cpufreq_drv_data[policy->cpu])
        return 0;    

    switch (cpufreq_drv_data[policy->cpu]->arch_cpu_flags) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        cmd.type = SYSTEM_INTEL_MSR_CAPABLE;
        cmd.addr.msr.reg = MSR_IA32_PERF_STATUS;
        break;
    case SYSTEM_IO_CAPABLE:
        cmd.type = SYSTEM_IO_CAPABLE;
        perf = cpufreq_drv_data[policy->cpu]->acpi_data;
        cmd.addr.io.port = perf->control_register.address;
        cmd.addr.io.bit_width = perf->control_register.bit_width;
        break;
    default:
        return 0;
    }

    cmd.mask = cpumask_of(cpu);

    drv_read(&cmd);
    return cmd.val;
}

struct perf_pair {
    union {
        struct {
            uint32_t lo;
            uint32_t hi;
        } split;
        uint64_t whole;
    } aperf, mperf;
};
static DEFINE_PER_CPU(struct perf_pair, gov_perf_pair);
static DEFINE_PER_CPU(struct perf_pair, usr_perf_pair);

static void read_measured_perf_ctrs(void *_readin)
{
    struct perf_pair *readin = _readin;

    rdmsrl(MSR_IA32_APERF, readin->aperf.whole);
    rdmsrl(MSR_IA32_MPERF, readin->mperf.whole);
}

/*
 * Return the measured active (C0) frequency on this CPU since last call
 * to this function.
 * Input: cpu number
 * Return: Average CPU frequency in terms of max frequency (zero on error)
 *
 * We use IA32_MPERF and IA32_APERF MSRs to get the measured performance
 * over a period of time, while CPU is in C0 state.
 * IA32_MPERF counts at the rate of max advertised frequency
 * IA32_APERF counts at the rate of actual CPU frequency
 * Only IA32_APERF/IA32_MPERF ratio is architecturally defined and
 * no meaning should be associated with absolute values of these MSRs.
 */
unsigned int get_measured_perf(unsigned int cpu, unsigned int flag)
{
    struct cpufreq_policy *policy;    
    struct perf_pair readin, cur, *saved;
    unsigned int perf_percent;
    unsigned int retval;

    if (!cpu_online(cpu))
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if (!policy || !policy->aperf_mperf)
        return 0;

    switch (flag)
    {
    case GOV_GETAVG:
    {
        saved = &per_cpu(gov_perf_pair, cpu);
        break;
    }
    case USR_GETAVG:
    {
        saved = &per_cpu(usr_perf_pair, cpu);
        break;
    }
    default:
        return 0;
    }

    if (cpu == smp_processor_id()) {
        read_measured_perf_ctrs((void *)&readin);
    } else {
        on_selected_cpus(cpumask_of(cpu), read_measured_perf_ctrs,
                        &readin, 1);
    }

    cur.aperf.whole = readin.aperf.whole - saved->aperf.whole;
    cur.mperf.whole = readin.mperf.whole - saved->mperf.whole;
    saved->aperf.whole = readin.aperf.whole;
    saved->mperf.whole = readin.mperf.whole;

    if (unlikely(((unsigned long)(-1) / 100) < cur.aperf.whole)) {
        int shift_count = 7;
        cur.aperf.whole >>= shift_count;
        cur.mperf.whole >>= shift_count;
    }

    if (cur.aperf.whole && cur.mperf.whole)
        perf_percent = (cur.aperf.whole * 100) / cur.mperf.whole;
    else
        perf_percent = 0;

    retval = policy->cpuinfo.max_freq * perf_percent / 100;

    return retval;
}

static unsigned int get_cur_freq_on_cpu(unsigned int cpu)
{
    struct cpufreq_policy *policy;
    struct acpi_cpufreq_data *data;
    unsigned int freq;

    if (!cpu_online(cpu))
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if (!policy)
        return 0;

    data = cpufreq_drv_data[policy->cpu];
    if (unlikely(data == NULL ||
        data->acpi_data == NULL || data->freq_table == NULL))
        return 0;

    freq = extract_freq(get_cur_val(cpumask_of(cpu)), data);
    return freq;
}

static void feature_detect(void *info)
{
    struct cpufreq_policy *policy = info;
    unsigned int eax;

    if ( cpu_has_aperfmperf )
    {
        policy->aperf_mperf = 1;
        cpufreq_driver.getavg = get_measured_perf;
    }

    eax = cpuid_eax(6);
    if (eax & 0x2) {
        policy->turbo = CPUFREQ_TURBO_ENABLED;
        if (cpufreq_verbose)
            printk(XENLOG_INFO "CPU%u: Turbo Mode detected and enabled\n",
                   smp_processor_id());
    }
}

static unsigned int check_freqs(const cpumask_t *mask, unsigned int freq,
                                struct acpi_cpufreq_data *data)
{
    unsigned int cur_freq;
    unsigned int i;

    for (i=0; i<100; i++) {
        cur_freq = extract_freq(get_cur_val(mask), data);
        if (cur_freq == freq)
            return 1;
        udelay(10);
    }
    return 0;
}

static int acpi_cpufreq_target(struct cpufreq_policy *policy,
                               unsigned int target_freq, unsigned int relation)
{
    struct acpi_cpufreq_data *data = cpufreq_drv_data[policy->cpu];
    struct processor_performance *perf;
    struct cpufreq_freqs freqs;
    cpumask_t online_policy_cpus;
    struct drv_cmd cmd;
    unsigned int next_state = 0; /* Index into freq_table */
    unsigned int next_perf_state = 0; /* Index into perf table */
    unsigned int j;
    int result = 0;

    if (unlikely(data == NULL ||
        data->acpi_data == NULL || data->freq_table == NULL)) {
        return -ENODEV;
    }

    if (policy->turbo == CPUFREQ_TURBO_DISABLED)
        if (target_freq > policy->cpuinfo.second_max_freq)
            target_freq = policy->cpuinfo.second_max_freq;

    perf = data->acpi_data;
    result = cpufreq_frequency_table_target(policy,
                                            data->freq_table,
                                            target_freq,
                                            relation, &next_state);
    if (unlikely(result))
        return -ENODEV;

    cpumask_and(&online_policy_cpus, &cpu_online_map, policy->cpus);

    next_perf_state = data->freq_table[next_state].index;
    if (perf->state == next_perf_state) {
        if (unlikely(policy->resume))
            policy->resume = 0;
        else
            return 0;
    }

    switch (data->arch_cpu_flags) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        cmd.type = SYSTEM_INTEL_MSR_CAPABLE;
        cmd.addr.msr.reg = MSR_IA32_PERF_CTL;
        cmd.val = (u32) perf->states[next_perf_state].control;
        break;
    case SYSTEM_IO_CAPABLE:
        cmd.type = SYSTEM_IO_CAPABLE;
        cmd.addr.io.port = perf->control_register.address;
        cmd.addr.io.bit_width = perf->control_register.bit_width;
        cmd.val = (u32) perf->states[next_perf_state].control;
        break;
    default:
        return -ENODEV;
    }

    if (policy->shared_type != CPUFREQ_SHARED_TYPE_ANY)
        cmd.mask = &online_policy_cpus;
    else
        cmd.mask = cpumask_of(policy->cpu);

    freqs.old = perf->states[perf->state].core_frequency * 1000;
    freqs.new = data->freq_table[next_state].frequency;

    drv_write(&cmd);

    if (acpi_pstate_strict && !check_freqs(cmd.mask, freqs.new, data)) {
        printk(KERN_WARNING "Fail transfer to new freq %d\n", freqs.new);
        return -EAGAIN;
    }

    for_each_cpu(j, &online_policy_cpus)
        cpufreq_statistic_update(j, perf->state, next_perf_state);

    perf->state = next_perf_state;
    policy->cur = freqs.new;

    return result;
}

static int acpi_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct acpi_cpufreq_data *data;
    struct processor_performance *perf;

    if (!policy || !(data = cpufreq_drv_data[policy->cpu]) ||
        !processor_pminfo[policy->cpu])
        return -EINVAL;

    perf = &processor_pminfo[policy->cpu]->perf;

    cpufreq_verify_within_limits(policy, 0, 
        perf->states[perf->platform_limit].core_frequency * 1000);

    return cpufreq_frequency_table_verify(policy, data->freq_table);
}

static unsigned long
acpi_cpufreq_guess_freq(struct acpi_cpufreq_data *data, unsigned int cpu)
{
    struct processor_performance *perf = data->acpi_data;

    if (cpu_khz) {
        /* search the closest match to cpu_khz */
        unsigned int i;
        unsigned long freq;
        unsigned long freqn = perf->states[0].core_frequency * 1000;

        for (i=0; i<(perf->state_count-1); i++) {
            freq = freqn;
            freqn = perf->states[i+1].core_frequency * 1000;
            if ((2 * cpu_khz) > (freqn + freq)) {
                perf->state = i;
                return freq;
            }
        }
        perf->state = perf->state_count-1;
        return freqn;
    } else {
        /* assume CPU is at P0... */
        perf->state = 0;
        return perf->states[0].core_frequency * 1000;
    }
}

static int 
acpi_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int i;
    unsigned int valid_states = 0;
    unsigned int cpu = policy->cpu;
    struct acpi_cpufreq_data *data;
    unsigned int result = 0;
    struct cpuinfo_x86 *c = &cpu_data[policy->cpu];
    struct processor_performance *perf;

    data = xzalloc(struct acpi_cpufreq_data);
    if (!data)
        return -ENOMEM;

    cpufreq_drv_data[cpu] = data;

    data->acpi_data = &processor_pminfo[cpu]->perf;

    perf = data->acpi_data;
    policy->shared_type = perf->shared_type;

    switch (perf->control_register.space_id) {
    case ACPI_ADR_SPACE_SYSTEM_IO:
        if (cpufreq_verbose)
            printk("xen_pminfo: @acpi_cpufreq_cpu_init,"
                   "SYSTEM IO addr space\n");
        data->arch_cpu_flags = SYSTEM_IO_CAPABLE;
        break;
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
        if (cpufreq_verbose)
            printk("xen_pminfo: @acpi_cpufreq_cpu_init,"
                   "HARDWARE addr space\n");
        if (!check_est_cpu(cpu)) {
            result = -ENODEV;
            goto err_unreg;
        }
        data->arch_cpu_flags = SYSTEM_INTEL_MSR_CAPABLE;
        break;
    default:
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

    /* table init */
    for (i=0; i<perf->state_count; i++) {
        if (i>0 && perf->states[i].core_frequency >=
            data->freq_table[valid_states-1].frequency / 1000)
            continue;

        data->freq_table[valid_states].index = i;
        data->freq_table[valid_states].frequency =
            perf->states[i].core_frequency * 1000;
        valid_states++;
    }
    data->freq_table[valid_states].frequency = CPUFREQ_TABLE_END;
    perf->state = 0;

    result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
    if (result)
        goto err_freqfree;

    switch (perf->control_register.space_id) {
    case ACPI_ADR_SPACE_SYSTEM_IO:
        /* Current speed is unknown and not detectable by IO port */
        policy->cur = acpi_cpufreq_guess_freq(data, policy->cpu);
        break;
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
        cpufreq_driver.get = get_cur_freq_on_cpu;
        policy->cur = get_cur_freq_on_cpu(cpu);
        break;
    default:
        break;
    }

    /* Check for APERF/MPERF support in hardware
     * also check for boost support */
    if (c->x86_vendor == X86_VENDOR_INTEL && c->cpuid_level >= 6)
        on_selected_cpus(cpumask_of(cpu), feature_detect, policy, 1);

    /*
     * the first call to ->target() should result in us actually
     * writing something to the appropriate registers.
     */
    policy->resume = 1;

    return result;

err_freqfree:
    xfree(data->freq_table);
err_unreg:
    xfree(data);
    cpufreq_drv_data[cpu] = NULL;

    return result;
}

static int acpi_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    struct acpi_cpufreq_data *data = cpufreq_drv_data[policy->cpu];

    if (data) {
        cpufreq_drv_data[policy->cpu] = NULL;
        xfree(data->freq_table);
        xfree(data);
    }

    return 0;
}

static const struct cpufreq_driver __initconstrel acpi_cpufreq_driver = {
    .name   = "acpi-cpufreq",
    .verify = acpi_cpufreq_verify,
    .target = acpi_cpufreq_target,
    .init   = acpi_cpufreq_cpu_init,
    .exit   = acpi_cpufreq_cpu_exit,
};

static int __init cpufreq_driver_init(void)
{
    int ret = 0;

    if ((cpufreq_controller == FREQCTL_xen) &&
        (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL))
        ret = cpufreq_register_driver(&acpi_cpufreq_driver);
    else if ((cpufreq_controller == FREQCTL_xen) &&
        (boot_cpu_data.x86_vendor &
         (X86_VENDOR_AMD | X86_VENDOR_HYGON)))
        ret = powernow_register_driver();

    return ret;
}
presmp_initcall(cpufreq_driver_init);

int cpufreq_cpu_init(unsigned int cpuid)
{
    int ret;

    /* Currently we only handle Intel, AMD and Hygon processor */
    if ( boot_cpu_data.x86_vendor &
         (X86_VENDOR_INTEL | X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        ret = cpufreq_add_cpu(cpuid);
    else
        ret = -EFAULT;
    return ret;
}
