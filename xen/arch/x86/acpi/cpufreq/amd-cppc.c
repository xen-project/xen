/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * amd-cppc.c - AMD Processor CPPC Frequency Driver
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Author: Penny Zheng <penny.zheng@amd.com>
 *
 * AMD CPPC cpufreq driver introduces a new CPU performance scaling design
 * for AMD processors using the ACPI Collaborative Performance and Power
 * Control (CPPC) feature which provides finer grained frequency control range.
 */

#include <xen/domain.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/xvmalloc.h>
#include <acpi/cpufreq/cpufreq.h>
#include <asm/amd.h>
#include <asm/msr.h>

#define amd_cppc_err(cpu, fmt, args...)                             \
    printk(XENLOG_ERR "AMD-CPPC: CPU%u error: " fmt, cpu, ## args)
#define amd_cppc_warn(cpu, fmt, args...)                            \
    printk(XENLOG_WARNING "AMD-CPPC: CPU%u warning: " fmt, cpu, ## args)
#define amd_cppc_verbose(cpu, fmt, args...)                         \
({                                                                  \
    if ( cpufreq_verbose )                                          \
        printk(XENLOG_DEBUG "AMD-CPPC: CPU%u " fmt, cpu, ## args);  \
})

/*
 * Field highest_perf, nominal_perf, lowest_nonlinear_perf, and lowest_perf
 * contain the values read from CPPC capability MSR. They represent the limits
 * of managed performance range as well as the dynamic capability, which may
 * change during processor operation
 * Field highest_perf represents highest performance, which is the absolute
 * maximum performance an individual processor may reach, assuming ideal
 * conditions. This performance level may not be sustainable for long
 * durations and may only be achievable if other platform components
 * are in a specific state; for example, it may require other processors be
 * in an idle state. This would be equivalent to the highest frequencies
 * supported by the processor.
 * Field nominal_perf represents maximum sustained performance level of the
 * processor, assuming ideal operating conditions. All cores/processors are
 * expected to be able to sustain their nominal performance state
 * simultaneously.
 * Field lowest_nonlinear_perf represents Lowest Nonlinear Performance, which
 * is the lowest performance level at which nonlinear power savings are
 * achieved. Above this threshold, lower performance levels should be
 * generally more energy efficient than higher performance levels. So in
 * traditional terms, this represents the P-state range of performance levels.
 * Field lowest_perf represents the absolute lowest performance level of the
 * platform. Selecting it may cause an efficiency penalty but should reduce
 * the instantaneous power consumption of the processor. So in traditional
 * terms, this represents the T-state range of performance levels.
 *
 * Field max_perf, min_perf, des_perf store the values for CPPC request MSR.
 * Software passes performance goals through these fields.
 * Field max_perf conveys the maximum performance level at which the platform
 * may run. And it may be set to any performance value in the range
 * [lowest_perf, highest_perf], inclusive.
 * Field min_perf conveys the minimum performance level at which the platform
 * may run. And it may be set to any performance value in the range
 * [lowest_perf, highest_perf], inclusive but must be less than or equal to
 * max_perf.
 * Field des_perf conveys performance level Xen governor is requesting. And it
 * may be set to any performance value in the range [min_perf, max_perf],
 * inclusive. In active mode, des_perf must be zero.
 * Field epp represents energy performance preference, which only has meaning
 * when active mode is enabled. The EPP is used in the CCLK DPM controller
 * to drive the frequency that a core is going to operate during short periods
 * of activity, called minimum active frequency, It could contatin a range of
 * values from 0 to 0xff. An EPP of zero sets the min active frequency to
 * maximum frequency, while an EPP of 0xff sets the min active frequency to
 * approxiately Idle frequency.
 */
struct amd_cppc_drv_data
{
    const struct xen_processor_cppc *cppc_data;
    union {
        uint64_t raw;
        struct {
            unsigned int lowest_perf:8;
            unsigned int lowest_nonlinear_perf:8;
            unsigned int nominal_perf:8;
            unsigned int highest_perf:8;
            unsigned int :32;
        };
    } caps;
    union {
        uint64_t raw;
        struct {
            unsigned int max_perf:8;
            unsigned int min_perf:8;
            unsigned int des_perf:8;
            unsigned int epp:8;
            unsigned int :32;
        };
    } req;

    int err;
};

static DEFINE_PER_CPU_READ_MOSTLY(struct amd_cppc_drv_data *,
                                  amd_cppc_drv_data);
/*
 * Core max frequency read from PstateDef as anchor point
 * for freq-to-perf transition
 */
static DEFINE_PER_CPU_READ_MOSTLY(unsigned int, pxfreq_mhz);
static DEFINE_PER_CPU_READ_MOSTLY(uint8_t, epp_init);
#ifndef NDEBUG
static bool __ro_after_init opt_active_mode;
#else
static bool __initdata opt_active_mode;
#endif


static bool __init amd_cppc_handle_option(const char *s, const char *end)
{
    int ret;

    ret = parse_boolean("verbose", s, end);
    if ( ret >= 0 )
    {
        cpufreq_verbose = ret;
        return true;
    }

    ret = parse_boolean("active", s, end);
    if ( ret >= 0 )
    {
        opt_active_mode = ret;
        return true;
    }

    return false;
}

int __init amd_cppc_cmdline_parse(const char *s, const char *e)
{
    do {
        const char *end = strpbrk(s, ",;");

        if ( !amd_cppc_handle_option(s, end) )
        {
            printk(XENLOG_WARNING
                   "cpufreq/amd-cppc: option '%.*s' not recognized\n",
                   (int)((end ?: e) - s), s);

            return -EINVAL;
        }

        s = end ? end + 1 : NULL;
    } while ( s && s < e );

    return 0;
}

/*
 * If CPPC lowest_freq and nominal_freq registers are exposed then we can
 * use them to convert perf to freq and vice versa. The conversion is
 * extrapolated as an linear function passing by the 2 points:
 *  - (Low perf, Low freq)
 *  - (Nominal perf, Nominal freq)
 * Parameter freq is always in kHz.
 */
static int amd_cppc_khz_to_perf(const struct amd_cppc_drv_data *data,
                                unsigned int freq, uint8_t *perf)
{
    const struct xen_processor_cppc *cppc_data = data->cppc_data;
    unsigned int mul, div;
    int offset = 0, res;

    if ( cppc_data->cpc.lowest_mhz &&
         data->caps.nominal_perf > data->caps.lowest_perf &&
         cppc_data->cpc.nominal_mhz > cppc_data->cpc.lowest_mhz )
    {
        mul = data->caps.nominal_perf - data->caps.lowest_perf;
        div = cppc_data->cpc.nominal_mhz - cppc_data->cpc.lowest_mhz;

        /*
         * We don't need to convert to kHz for computing offset and can
         * directly use nominal_mhz and lowest_mhz as the division
         * will remove the frequency unit.
         */
        offset = data->caps.nominal_perf -
                 (mul * cppc_data->cpc.nominal_mhz) / div;
    }
    else
    {
        /* Read Processor Max Speed(MHz) as anchor point */
        mul = data->caps.highest_perf;
        div = this_cpu(pxfreq_mhz);
        if ( !div )
            return -EOPNOTSUPP;
    }

    res = offset + (mul * freq) / (div * 1000);
    if ( res > UINT8_MAX )
    {
        printk_once(XENLOG_WARNING
                    "Perf value exceeds maximum value 255: %d\n", res);
        *perf = UINT8_MAX;
        return 0;
    }
    if ( res <= 0 )
    {
        printk_once(XENLOG_WARNING
                    "Perf value smaller than minimum value: %d\n", res);
        return -ERANGE;
    }
    *perf = res;

    return 0;
}

/*
 * _CPC may define nominal frequecy and lowest frequency, if not, use
 * Processor Max Speed as anchor point to calculate.
 * Output freq stores cpc frequency in kHz
 */
static int amd_get_cpc_freq(const struct amd_cppc_drv_data *data,
                            unsigned int cpc_mhz, uint8_t perf,
                            unsigned int *freq)
{
    unsigned int mul, div, res;

    if ( cpc_mhz )
    {
        /* Switch to kHz */
        *freq = cpc_mhz * 1000;
        return 0;
    }

    /* Read Processor Max Speed(MHz) as anchor point */
    mul = this_cpu(pxfreq_mhz);
    if ( !mul )
        return -EOPNOTSUPP;
    div = data->caps.highest_perf;
    res = (mul * perf * 1000) / div;
    if ( unlikely(!res) )
        return -EOPNOTSUPP;

    return 0;
}

/* Output max_freq stores calculated maximum frequency in kHz */
static int amd_get_max_freq(const struct amd_cppc_drv_data *data,
                            unsigned int *max_freq)
{
    unsigned int nom_freq = 0;
    int res;

    res = amd_get_cpc_freq(data, data->cppc_data->cpc.nominal_mhz,
                           data->caps.nominal_perf, &nom_freq);
    if ( res )
        return res;

    *max_freq = (data->caps.highest_perf * nom_freq) / data->caps.nominal_perf;

    return 0;
}

static int cf_check amd_cppc_cpufreq_verify(struct cpufreq_policy *policy)
{
    cpufreq_verify_within_limits(policy, policy->cpuinfo.min_freq,
                                 policy->cpuinfo.max_freq);

    return 0;
}

static void cf_check amd_cppc_write_request_msrs(void *info)
{
    const struct amd_cppc_drv_data *data = info;

    wrmsrl(MSR_AMD_CPPC_REQ, data->req.raw);
}

static void amd_cppc_write_request(unsigned int cpu, uint8_t min_perf,
                                   uint8_t des_perf, uint8_t max_perf,
                                   uint8_t epp)
{
    struct amd_cppc_drv_data *data = per_cpu(amd_cppc_drv_data, cpu);
    uint64_t prev = data->req.raw;

    data->req.min_perf = min_perf;
    data->req.max_perf = max_perf;
    ASSERT(!opt_active_mode || !des_perf);
    data->req.des_perf = des_perf;
    data->req.epp = epp;

    if ( prev == data->req.raw )
        return;

    on_selected_cpus(cpumask_of(cpu), amd_cppc_write_request_msrs, data, 1);
}

static int cf_check amd_cppc_cpufreq_target(struct cpufreq_policy *policy,
                                            unsigned int target_freq,
                                            unsigned int relation)
{
    unsigned int cpu = policy->cpu;
    const struct amd_cppc_drv_data *data = per_cpu(amd_cppc_drv_data, cpu);
    uint8_t des_perf;
    int res;

    if ( unlikely(!target_freq) )
        return 0;

    res = amd_cppc_khz_to_perf(data, target_freq, &des_perf);
    if ( res )
        return res;

    /*
     * Having a performance level lower than the lowest nonlinear
     * performance level, such as, lowest_perf <= perf <= lowest_nonliner_perf,
     * may actually cause an efficiency penalty, So when deciding the min_perf
     * value, we prefer lowest nonlinear performance over lowest performance.
     */
    amd_cppc_write_request(policy->cpu, data->caps.lowest_nonlinear_perf,
                           des_perf, data->caps.highest_perf,
                           /* Pre-defined BIOS value for passive mode */
                           per_cpu(epp_init, policy->cpu));
    return 0;
}

static void cf_check amd_cppc_init_msrs(void *info)
{
    struct cpufreq_policy *policy = info;
    struct amd_cppc_drv_data *data = this_cpu(amd_cppc_drv_data);
    uint64_t val;
    unsigned int min_freq = 0, nominal_freq = 0, max_freq;

    /* Package level MSR */
    rdmsrl(MSR_AMD_CPPC_ENABLE, val);
    /*
     * Only when Enable bit is on, the hardware will calculate the processor’s
     * performance capabilities and initialize the performance level fields in
     * the CPPC capability registers.
     */
    if ( !(val & AMD_CPPC_ENABLE) )
    {
        val |= AMD_CPPC_ENABLE;
        wrmsrl(MSR_AMD_CPPC_ENABLE, val);
    }

    rdmsrl(MSR_AMD_CPPC_CAP1, data->caps.raw);

    if ( data->caps.highest_perf == 0 || data->caps.lowest_perf == 0 ||
         data->caps.nominal_perf == 0 || data->caps.lowest_nonlinear_perf == 0 ||
         data->caps.lowest_perf > data->caps.lowest_nonlinear_perf ||
         data->caps.lowest_nonlinear_perf > data->caps.nominal_perf ||
         data->caps.nominal_perf > data->caps.highest_perf )
    {
        amd_cppc_err(policy->cpu,
                     "Out of range values: highest(%u), lowest(%u), nominal(%u), lowest_nonlinear(%u)\n",
                     data->caps.highest_perf, data->caps.lowest_perf,
                     data->caps.nominal_perf, data->caps.lowest_nonlinear_perf);
        goto err;
    }

    amd_process_freq(&cpu_data[policy->cpu],
                     NULL, NULL, &this_cpu(pxfreq_mhz));

    data->err = amd_get_cpc_freq(data, data->cppc_data->cpc.lowest_mhz,
                                 data->caps.lowest_perf, &min_freq);
    if ( data->err )
        return;

    data->err = amd_get_cpc_freq(data, data->cppc_data->cpc.nominal_mhz,
                                 data->caps.nominal_perf, &nominal_freq);
    if ( data->err )
        return;

    data->err = amd_get_max_freq(data, &max_freq);
    if ( data->err )
        return;

    if ( min_freq > nominal_freq || nominal_freq > max_freq )
    {
        amd_cppc_err(policy->cpu,
                     "min(%u), or max(%u), or nominal(%u) freq value is incorrect\n",
                     min_freq, max_freq, nominal_freq);
        goto err;
    }

    policy->min = min_freq;
    policy->max = max_freq;

    policy->cpuinfo.min_freq = min_freq;
    policy->cpuinfo.max_freq = max_freq;
    policy->cpuinfo.perf_freq = nominal_freq;
    /*
     * Set after policy->cpuinfo.perf_freq, as we are taking
     * APERF/MPERF average frequency as current frequency.
     */
    policy->cur = cpufreq_driver_getavg(policy->cpu, GOV_GETAVG);

    /* Store pre-defined BIOS value for passive mode */
    rdmsrl(MSR_AMD_CPPC_REQ, val);
    this_cpu(epp_init) = MASK_EXTR(val, AMD_CPPC_EPP_MASK);

    return;

 err:
    /*
     * No fallback shceme is available here, see more explanation at call
     * site in amd_cppc_cpufreq_cpu_init().
     */
    data->err = -EINVAL;
}

/*
 * AMD CPPC driver is different than legacy ACPI hardware P-State,
 * which has a finer grain frequency range between the highest and lowest
 * frequency. And boost frequency is actually the frequency which is mapped on
 * highest performance ratio. The legacy P0 frequency is actually mapped on
 * nominal performance ratio.
 */
static void amd_cppc_boost_init(struct cpufreq_policy *policy,
                                const struct amd_cppc_drv_data *data)
{
    if ( data->caps.highest_perf <= data->caps.nominal_perf )
        return;

    policy->turbo = CPUFREQ_TURBO_ENABLED;
}

static int cf_check amd_cppc_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    XVFREE(per_cpu(amd_cppc_drv_data, policy->cpu));

    return 0;
}

static int amd_cppc_cpufreq_init_perf(struct cpufreq_policy *policy)
{
    unsigned int cpu = policy->cpu;
    struct amd_cppc_drv_data *data;

    data = xvzalloc(struct amd_cppc_drv_data);
    if ( !data )
        return -ENOMEM;

    data->cppc_data = &processor_pminfo[cpu]->cppc_data;

    per_cpu(amd_cppc_drv_data, cpu) = data;

    on_selected_cpus(cpumask_of(cpu), amd_cppc_init_msrs, policy, 1);

    /*
     * The enable bit is sticky, as we need to enable it at the very first
     * begining, before CPPC capability values sanity check.
     * If error path is taken effective, not only amd-cppc cpufreq core fails
     * to initialize, but also we could not fall back to legacy P-states
     * driver, irrespective of the command line specifying a fallback option.
     */
    if ( data->err )
    {
        amd_cppc_err(cpu, "Could not initialize cpufreq core in CPPC mode\n");
        amd_cppc_cpufreq_cpu_exit(policy);
        return data->err;
    }

    policy->governor = cpufreq_opt_governor ? : CPUFREQ_DEFAULT_GOVERNOR;

    amd_cppc_boost_init(policy, data);

    return 0;
}

static int cf_check amd_cppc_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    int ret;

    ret = amd_cppc_cpufreq_init_perf(policy);
    if ( ret )
        return ret;

    amd_cppc_verbose(policy->cpu,
                     "CPU initialized with amd-cppc passive mode\n");

    return 0;
}

static int cf_check amd_cppc_epp_cpu_init(struct cpufreq_policy *policy)
{
    int ret;

    ret = amd_cppc_cpufreq_init_perf(policy);
    if ( ret )
        return ret;

    policy->policy = cpufreq_policy_from_governor(policy->governor);

    amd_cppc_verbose(policy->cpu,
                     "CPU initialized with amd-cppc active mode\n");

    return 0;
}

static void amd_cppc_prepare_policy(struct cpufreq_policy *policy,
                                    uint8_t *max_perf, uint8_t *min_perf,
                                    uint8_t *epp)
{
    const struct amd_cppc_drv_data *data = per_cpu(amd_cppc_drv_data,
                                                   policy->cpu);

    /*
     * On default, set min_perf with lowest_nonlinear_perf, and max_perf
     * with the highest, to ensure performance scaling in P-states range.
     */
    *max_perf = data->caps.highest_perf;
    *min_perf = data->caps.lowest_nonlinear_perf;

    /*
     * In policy CPUFREQ_POLICY_PERFORMANCE, increase min_perf to
     * highest_perf to achieve ultmost performance.
     * In policy CPUFREQ_POLICY_POWERSAVE, decrease max_perf to
     * lowest_nonlinear_perf to achieve ultmost power saving.
     * Set governor only to help print proper policy info to users.
     */
    switch ( policy->policy )
    {
    case CPUFREQ_POLICY_PERFORMANCE:
        /* Force the epp value to be zero for performance policy */
        *epp = CPPC_ENERGY_PERF_MAX_PERFORMANCE;
        *min_perf = *max_perf;
        policy->governor = &cpufreq_gov_performance;
        break;

    case CPUFREQ_POLICY_POWERSAVE:
        /* Force the epp value to be 0xff for powersave policy */
        *epp = CPPC_ENERGY_PERF_MAX_POWERSAVE;
        *max_perf = *min_perf;
        policy->governor = &cpufreq_gov_powersave;
        break;

    case CPUFREQ_POLICY_ONDEMAND:
        /*
         * Set epp with medium value to show no preference over performance
         * or powersave
         */
        *epp = CPPC_ENERGY_PERF_BALANCE;
        policy->governor = &cpufreq_gov_dbs;
        break;

    default:
        *epp = per_cpu(epp_init, policy->cpu);
        break;
    }
}

static int cf_check amd_cppc_epp_set_policy(struct cpufreq_policy *policy)
{
    uint8_t max_perf, min_perf, epp;

    amd_cppc_prepare_policy(policy, &max_perf, &min_perf, &epp);

    amd_cppc_write_request(policy->cpu, min_perf,
                           0 /* no des_perf in active mode */,
                           max_perf, epp);
    return 0;
}

static const struct cpufreq_driver __initconst_cf_clobber
amd_cppc_cpufreq_driver =
{
    .name   = XEN_AMD_CPPC_DRIVER_NAME,
    .verify = amd_cppc_cpufreq_verify,
    .target = amd_cppc_cpufreq_target,
    .init   = amd_cppc_cpufreq_cpu_init,
    .exit   = amd_cppc_cpufreq_cpu_exit,
};

static const struct cpufreq_driver __initconst_cf_clobber
amd_cppc_epp_driver =
{
    .name       = XEN_AMD_CPPC_EPP_DRIVER_NAME,
    .verify     = amd_cppc_cpufreq_verify,
    .setpolicy  = amd_cppc_epp_set_policy,
    .init       = amd_cppc_epp_cpu_init,
    .exit       = amd_cppc_cpufreq_cpu_exit,
};

int __init amd_cppc_register_driver(void)
{
    int ret;

    if ( !cpu_has_cppc )
        return -ENODEV;

    if ( opt_active_mode )
        ret = cpufreq_register_driver(&amd_cppc_epp_driver);
    else
        ret = cpufreq_register_driver(&amd_cppc_cpufreq_driver);

    return ret;
}
