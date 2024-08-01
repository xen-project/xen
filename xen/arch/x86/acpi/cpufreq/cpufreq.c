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
#include <xen/param.h>
#include <xen/sched.h>
#include <acpi/cpufreq/cpufreq.h>

struct acpi_cpufreq_data *cpufreq_drv_data[NR_CPUS];

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

static void cf_check read_measured_perf_ctrs(void *_readin)
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

    if (!cpu_online(cpu))
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if ( !policy || !cpu_has_aperfmperf )
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

    return policy->cpuinfo.perf_freq * perf_percent / 100;
}

static int __init cf_check cpufreq_driver_init(void)
{
    int ret = 0;

    if ( cpufreq_controller == FREQCTL_xen )
    {
        switch ( boot_cpu_data.x86_vendor )
        {
        case X86_VENDOR_INTEL:
            ret = -ENOENT;

            for ( unsigned int i = 0; i < cpufreq_xen_cnt; i++ )
            {
                switch ( cpufreq_xen_opts[i] )
                {
                case CPUFREQ_xen:
                    ret = IS_ENABLED(CONFIG_INTEL) ?
                          acpi_cpufreq_register() : -ENODEV;
                    break;
                case CPUFREQ_hwp:
                    ret = IS_ENABLED(CONFIG_INTEL) ?
                          hwp_register_driver() : -ENODEV;
                    break;
                case CPUFREQ_none:
                    ret = 0;
                    break;
                }

                if ( ret != -ENODEV )
                    break;
            }
            break;

        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            ret = IS_ENABLED(CONFIG_AMD) ? powernow_register_driver() : -ENODEV;
            break;
        }
    }

    return ret;
}
presmp_initcall(cpufreq_driver_init);

static int __init cf_check cpufreq_driver_late_init(void)
{
    /*
     * While acpi_cpufreq_driver wants to unconditionally have all hooks
     * populated for __initconst_cf_clobber to have as much of an effect as
     * possible, zap the .get hook here (but not in cpufreq_driver_init()),
     * until acpi_cpufreq_cpu_init() knows whether it's wanted / needed.
     */
    cpufreq_driver.get = NULL;
    return 0;
}
__initcall(cpufreq_driver_late_init);

int cpufreq_cpu_init(unsigned int cpu)
{
    /* Currently we only handle Intel, AMD and Hygon processor */
    if ( boot_cpu_data.x86_vendor &
         (X86_VENDOR_INTEL | X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        return cpufreq_add_cpu(cpu);

    return -EOPNOTSUPP;
}
