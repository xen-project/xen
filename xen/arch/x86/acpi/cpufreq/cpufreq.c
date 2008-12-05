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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/sched.h>
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

enum {
    UNDEFINED_CAPABLE = 0,
    SYSTEM_INTEL_MSR_CAPABLE,
    SYSTEM_IO_CAPABLE,
};

#define INTEL_MSR_RANGE         (0xffff)
#define CPUID_6_ECX_APERFMPERF_CAPABILITY       (0x1)

static struct acpi_cpufreq_data *drv_data[NR_CPUS];

static struct cpufreq_driver acpi_cpufreq_driver;

static int check_est_cpu(unsigned int cpuid)
{
    struct cpuinfo_x86 *cpu = &cpu_data[cpuid];

    if (cpu->x86_vendor != X86_VENDOR_INTEL ||
        !cpu_has(cpu, X86_FEATURE_EST))
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
    switch (data->cpu_feature) {
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
    cpumask_t mask;
    drv_addr_union addr;
    u32 val;
};

static void do_drv_read(struct drv_cmd *cmd)
{
    u32 h;

    switch (cmd->type) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        rdmsr(cmd->addr.msr.reg, cmd->val, h);
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
    u32 lo, hi;

    cmd = (struct drv_cmd *)drvcmd;

    switch (cmd->type) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        rdmsr(cmd->addr.msr.reg, lo, hi);
        lo = (lo & ~INTEL_MSR_RANGE) | (cmd->val & INTEL_MSR_RANGE);
        wrmsr(cmd->addr.msr.reg, lo, hi);
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

    do_drv_read(cmd);
}

static void drv_write(struct drv_cmd *cmd)
{
    on_selected_cpus( cmd->mask, do_drv_write, (void *)cmd, 0, 0);
}

static u32 get_cur_val(cpumask_t mask)
{
    struct processor_performance *perf;
    struct drv_cmd cmd;

    if (unlikely(cpus_empty(mask)))
        return 0;

    switch (drv_data[first_cpu(mask)]->cpu_feature) {
    case SYSTEM_INTEL_MSR_CAPABLE:
        cmd.type = SYSTEM_INTEL_MSR_CAPABLE;
        cmd.addr.msr.reg = MSR_IA32_PERF_STATUS;
        break;
    case SYSTEM_IO_CAPABLE:
        cmd.type = SYSTEM_IO_CAPABLE;
        perf = drv_data[first_cpu(mask)]->acpi_data;
        cmd.addr.io.port = perf->control_register.address;
        cmd.addr.io.bit_width = perf->control_register.bit_width;
        break;
    default:
        return 0;
    }

    cmd.mask = mask;

    drv_read(&cmd);
    return cmd.val;
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
static void  __get_measured_perf(void *perf_percent)
{
    unsigned int *ratio = perf_percent;
    union {
        struct {
            uint32_t lo;
            uint32_t hi;
        } split;
        uint64_t whole;
    } aperf_cur, mperf_cur;

    rdmsr(MSR_IA32_APERF, aperf_cur.split.lo, aperf_cur.split.hi);
    rdmsr(MSR_IA32_MPERF, mperf_cur.split.lo, mperf_cur.split.hi);

    wrmsr(MSR_IA32_APERF, 0,0);
    wrmsr(MSR_IA32_MPERF, 0,0);

    if (unlikely(((unsigned long)(-1) / 100) < aperf_cur.whole)) {
        int shift_count = 7;
        aperf_cur.whole >>= shift_count;
        mperf_cur.whole >>= shift_count;
    }

    if (aperf_cur.whole && mperf_cur.whole)
        *ratio = (aperf_cur.whole * 100) / mperf_cur.whole;
    else
        *ratio = 0;
}

static unsigned int get_measured_perf(unsigned int cpu)
{
    unsigned int retval, perf_percent;
    cpumask_t cpumask;

    if (!cpu_online(cpu))
        return 0;

    cpumask = cpumask_of_cpu(cpu);
    on_selected_cpus(cpumask, __get_measured_perf, (void *)&perf_percent,0,1);

    retval = drv_data[cpu]->max_freq * perf_percent / 100;
    return retval;
}

static unsigned int get_cur_freq_on_cpu(unsigned int cpu)
{
    struct acpi_cpufreq_data *data = drv_data[cpu];
    unsigned int freq;

    if (unlikely(data == NULL ||
        data->acpi_data == NULL || data->freq_table == NULL)) {
        return 0;
    }

    freq = extract_freq(get_cur_val(cpumask_of_cpu(cpu)), data);
    return freq;
}

static unsigned int check_freqs(cpumask_t mask, unsigned int freq,
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
    struct acpi_cpufreq_data *data = drv_data[policy->cpu];
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

    perf = data->acpi_data;
    result = cpufreq_frequency_table_target(policy,
                                            data->freq_table,
                                            target_freq,
                                            relation, &next_state);
    if (unlikely(result))
        return -ENODEV;

    cpus_and(online_policy_cpus, cpu_online_map, policy->cpus);

    next_perf_state = data->freq_table[next_state].index;
    if (perf->state == next_perf_state) {
        if (unlikely(policy->resume))
            policy->resume = 0;
        else
            return 0;
    }

    switch (data->cpu_feature) {
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

    cpus_clear(cmd.mask);

    if (policy->shared_type != CPUFREQ_SHARED_TYPE_ANY)
        cmd.mask = online_policy_cpus;
    else
        cpu_set(policy->cpu, cmd.mask);

    freqs.old = perf->states[perf->state].core_frequency * 1000;
    freqs.new = data->freq_table[next_state].frequency;

    drv_write(&cmd);

    if (!check_freqs(cmd.mask, freqs.new, data))
        return -EAGAIN;

    for_each_cpu_mask(j, online_policy_cpus)
        cpufreq_statistic_update(j, perf->state, next_perf_state);

    perf->state = next_perf_state;
    policy->cur = freqs.new;

    return result;
}

static int acpi_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct acpi_cpufreq_data *data;
    struct processor_performance *perf;

    if (!policy || !(data = drv_data[policy->cpu]) ||
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

    data = xmalloc(struct acpi_cpufreq_data);
    if (!data)
        return -ENOMEM;
    memset(data, 0, sizeof(struct acpi_cpufreq_data));

    drv_data[cpu] = data;

    data->acpi_data = &processor_pminfo[cpu]->perf;

    perf = data->acpi_data;
    policy->shared_type = perf->shared_type;

    switch (perf->control_register.space_id) {
    case ACPI_ADR_SPACE_SYSTEM_IO:
        printk("xen_pminfo: @acpi_cpufreq_cpu_init,"
            "SYSTEM IO addr space\n");
        data->cpu_feature = SYSTEM_IO_CAPABLE;
        break;
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
        printk("xen_pminfo: @acpi_cpufreq_cpu_init," 
            "HARDWARE addr space\n");
        if (!check_est_cpu(cpu)) {
            result = -ENODEV;
            goto err_unreg;
        }
        data->cpu_feature = SYSTEM_INTEL_MSR_CAPABLE;
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
    policy->governor = CPUFREQ_DEFAULT_GOVERNOR;

    data->max_freq = perf->states[0].core_frequency * 1000;
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
        acpi_cpufreq_driver.get = get_cur_freq_on_cpu;
        policy->cur = get_cur_freq_on_cpu(cpu);
        break;
    default:
        break;
    }

    /* Check for APERF/MPERF support in hardware */
    if (c->x86_vendor == X86_VENDOR_INTEL && c->cpuid_level >= 6) {
        unsigned int ecx;
        ecx = cpuid_ecx(6);
        if (ecx & CPUID_6_ECX_APERFMPERF_CAPABILITY)
            acpi_cpufreq_driver.getavg = get_measured_perf;
    }

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
    drv_data[cpu] = NULL;

    return result;
}

static int acpi_cpufreq_cpu_exit(struct cpufreq_policy *policy)
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

    return ret;
}
__initcall(cpufreq_driver_init);

int cpufreq_cpu_init(unsigned int cpuid)
{
    static int cpu_count=0;
    int ret;

    cpu_count++; 

    /* Currently we only handle Intel and AMD processor */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        ret = cpufreq_add_cpu(cpuid);
    else if ( (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) &&
            (cpu_count == num_online_cpus()) )
        ret = powernow_cpufreq_init();
    else
        ret = -EFAULT;
    return ret;
}
