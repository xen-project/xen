/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hwp.c cpufreq driver to run Intel Hardware P-States (HWP)
 *
 * Copyright (C) 2021 Jason Andryuk <jandryuk@gmail.com>
 */

#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/xmalloc.h>
#include <asm/msr.h>
#include <acpi/cpufreq/cpufreq.h>

static bool __ro_after_init hwp_in_use;

static bool __ro_after_init feature_hwp_notification;
static bool __ro_after_init feature_hwp_activity_window;

static bool __ro_after_init feature_hdc;

static bool __ro_after_init opt_cpufreq_hdc = true;

#define HWP_ENERGY_PERF_MAX_PERFORMANCE 0
#define HWP_ENERGY_PERF_BALANCE         0x80
#define HWP_ENERGY_PERF_MAX_POWERSAVE   0xff

union hwp_request
{
    struct
    {
        unsigned int min_perf:8;
        unsigned int max_perf:8;
        unsigned int desired:8;
        unsigned int energy_perf:8;
        unsigned int activity_window:10;
        bool package_control:1;
        unsigned int :16;
        bool activity_window_valid:1;
        bool energy_perf_valid:1;
        bool desired_valid:1;
        bool max_perf_valid:1;
        bool min_perf_valid:1;
    };
    uint64_t raw;
};

struct hwp_drv_data
{
    union
    {
        uint64_t hwp_caps;
        struct
        {
            unsigned int highest:8;
            unsigned int guaranteed:8;
            unsigned int most_efficient:8;
            unsigned int lowest:8;
            unsigned int :32;
        } hw;
    };
    union hwp_request curr_req;
    int ret;
    uint16_t activity_window;
    uint8_t minimum;
    uint8_t maximum;
    uint8_t desired;
    uint8_t energy_perf;
};
static DEFINE_PER_CPU_READ_MOSTLY(struct hwp_drv_data *, hwp_drv_data);

#define hwp_err(cpu, fmt, args...) \
    printk(XENLOG_ERR "HWP: CPU%u error: " fmt, cpu, ## args)
#define hwp_info(fmt, args...)    printk(XENLOG_INFO "HWP: " fmt, ## args)
#define hwp_verbose(fmt, args...)                         \
({                                                        \
    if ( cpufreq_verbose )                                \
        printk(XENLOG_DEBUG "HWP: " fmt, ## args);        \
})

static int cf_check hwp_governor(struct cpufreq_policy *policy,
                                 unsigned int event)
{
    int ret;

    if ( policy == NULL )
        return -EINVAL;

    switch ( event )
    {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_LIMITS:
        ret = 0;
        break;

    case CPUFREQ_GOV_STOP:
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static bool __init hwp_handle_option(const char *s, const char *end)
{
    int ret;

    ret = parse_boolean("verbose", s, end);
    if ( ret >= 0 )
    {
        cpufreq_verbose = ret;
        return true;
    }

    ret = parse_boolean("hdc", s, end);
    if ( ret >= 0 )
    {
        opt_cpufreq_hdc = ret;
        return true;
    }

    return false;
}

int __init hwp_cmdline_parse(const char *s, const char *e)
{
    do
    {
        const char *end = strpbrk(s, ",;");

        if ( !hwp_handle_option(s, end) )
        {
            printk(XENLOG_WARNING "cpufreq/hwp: option '%.*s' not recognized\n",
                   (int)((end ?: e) - s), s);

            return -EINVAL;
        }

        s = end ? ++end : end;
    } while ( s && s < e );

    return 0;
}

static struct cpufreq_governor cpufreq_gov_hwp =
{
    .name          = "hwp",
    .governor      = hwp_governor,
};

static int __init cf_check cpufreq_gov_hwp_init(void)
{
    if ( !cpufreq_governor_internal )
        return 0;

    return cpufreq_register_governor(&cpufreq_gov_hwp);
}
__initcall(cpufreq_gov_hwp_init);

bool hwp_active(void)
{
    return hwp_in_use;
}

static bool __init hwp_available(void)
{
    unsigned int eax;

    if ( boot_cpu_data.cpuid_level < CPUID_PM_LEAF )
    {
        hwp_verbose("cpuid_level (%#x) lacks HWP support\n",
                    boot_cpu_data.cpuid_level);

        return false;
    }

    if ( boot_cpu_data.cpuid_level < 0x16 )
    {
        hwp_info("HWP disabled: cpuid_level %#x < 0x16 lacks CPU freq info\n",
                 boot_cpu_data.cpuid_level);

        return false;
    }

    eax = cpuid_eax(CPUID_PM_LEAF);

    hwp_verbose("%d notify: %d act-window: %d energy-perf: %d pkg-level: %d peci: %d\n",
                !!(eax & CPUID6_EAX_HWP),
                !!(eax & CPUID6_EAX_HWP_NOTIFICATION),
                !!(eax & CPUID6_EAX_HWP_ACTIVITY_WINDOW),
                !!(eax & CPUID6_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE),
                !!(eax & CPUID6_EAX_HWP_PACKAGE_LEVEL_REQUEST),
                !!(eax & CPUID6_EAX_HWP_PECI));

    if ( !(eax & CPUID6_EAX_HWP) )
        return false;

    if ( !(eax & CPUID6_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE) )
    {
        hwp_verbose("disabled: No energy/performance preference available");

        return false;
    }

    feature_hwp_notification    = eax & CPUID6_EAX_HWP_NOTIFICATION;
    feature_hwp_activity_window = eax & CPUID6_EAX_HWP_ACTIVITY_WINDOW;
    feature_hdc                 = eax & CPUID6_EAX_HDC;

    hwp_verbose("Hardware Duty Cycling (HDC) %ssupported%s\n",
                feature_hdc ? "" : "not ",
                feature_hdc ? opt_cpufreq_hdc ? ", enabled" : ", disabled"
                            : "");

    hwp_verbose("HW_FEEDBACK %ssupported\n",
                (eax & CPUID6_EAX_HW_FEEDBACK) ? "" : "not ");

    hwp_in_use = true;

    hwp_info("Using HWP for cpufreq\n");

    return true;
}

static int cf_check hwp_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, policy->cpu);

    if ( !feature_hwp_activity_window && data->activity_window )
    {
        hwp_verbose("HWP activity window not supported\n");

        return -EINVAL;
    }

    return 0;
}

static void cf_check hwp_write_request(void *info)
{
    const struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = this_cpu(hwp_drv_data);
    union hwp_request hwp_req = data->curr_req;

    data->ret = 0;

    BUILD_BUG_ON(sizeof(hwp_req) != sizeof(hwp_req.raw));
    if ( wrmsr_safe(MSR_HWP_REQUEST, hwp_req.raw) )
    {
        hwp_verbose("CPU%u: error wrmsr_safe(MSR_HWP_REQUEST, %lx)\n",
                    policy->cpu, hwp_req.raw);
        rdmsr_safe(MSR_HWP_REQUEST, data->curr_req.raw);
        data->ret = -EINVAL;
    }
}

static int cf_check hwp_cpufreq_target(struct cpufreq_policy *policy,
                                       unsigned int target_freq,
                                       unsigned int relation)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);
    /* Zero everything to ensure reserved bits are zero... */
    union hwp_request hwp_req = { .raw = 0 };

    /* .. and update from there */
    hwp_req.min_perf = data->minimum;
    hwp_req.max_perf = data->maximum;
    hwp_req.desired = data->desired;
    hwp_req.energy_perf = data->energy_perf;
    if ( feature_hwp_activity_window )
        hwp_req.activity_window = data->activity_window;

    if ( hwp_req.raw == data->curr_req.raw )
        return 0;

    data->curr_req = hwp_req;

    on_selected_cpus(cpumask_of(cpu), hwp_write_request, policy, 1);

    return data->ret;
}

static bool hdc_set_pkg_hdc_ctl(unsigned int cpu, bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_PKG_HDC_CTL, msr) )
    {
        hwp_err(cpu, "rdmsr_safe(MSR_PKG_HDC_CTL)\n");
        return false;
    }

    if ( val )
        msr |= PKG_HDC_CTL_HDC_PKG_ENABLE;
    else
        msr &= ~PKG_HDC_CTL_HDC_PKG_ENABLE;

    if ( wrmsr_safe(MSR_PKG_HDC_CTL, msr) )
    {
        hwp_err(cpu, "wrmsr_safe(MSR_PKG_HDC_CTL): %016lx\n", msr);
        return false;
    }

    return true;
}

static bool hdc_set_pm_ctl1(unsigned int cpu, bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_PM_CTL1, msr) )
    {
        hwp_err(cpu, "rdmsr_safe(MSR_PM_CTL1)\n");
        return false;
    }

    if ( val )
        msr |= PM_CTL1_HDC_ALLOW_BLOCK;
    else
        msr &= ~PM_CTL1_HDC_ALLOW_BLOCK;

    if ( wrmsr_safe(MSR_PM_CTL1, msr) )
    {
        hwp_err(cpu, "wrmsr_safe(MSR_PM_CTL1): %016lx\n", msr);
        return false;
    }

    return true;
}

static void hwp_get_cpu_speeds(struct cpufreq_policy *policy)
{
    uint32_t base_khz, max_khz, bus_khz, edx;

    cpuid(0x16, &base_khz, &max_khz, &bus_khz, &edx);

    /*
     * Zero values are acceptable - they are not used for calculations
     * and only returned to userspace.
     */
    policy->cpuinfo.perf_freq = base_khz * 1000;
    policy->cpuinfo.min_freq = base_khz * 1000;
    policy->cpuinfo.max_freq = max_khz * 1000;
    policy->min = base_khz * 1000;
    policy->max = max_khz * 1000;
    policy->cur = 0;
}

static void cf_check hwp_init_msrs(void *info)
{
    struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = this_cpu(hwp_drv_data);
    uint64_t val;

    /*
     * Package level MSR, but we don't have a good idea of packages here, so
     * just do it everytime.
     */
    if ( rdmsr_safe(MSR_PM_ENABLE, val) )
    {
        hwp_err(policy->cpu, "rdmsr_safe(MSR_PM_ENABLE)\n");
        data->curr_req.raw = -1;
        return;
    }

    /* Ensure we don't generate interrupts */
    if ( feature_hwp_notification )
        wrmsr_safe(MSR_HWP_INTERRUPT, 0);

    if ( !(val & PM_ENABLE_HWP_ENABLE) )
    {
        val |= PM_ENABLE_HWP_ENABLE;
        if ( wrmsr_safe(MSR_PM_ENABLE, val) )
        {
            hwp_err(policy->cpu, "wrmsr_safe(MSR_PM_ENABLE, %lx)\n", val);
            data->curr_req.raw = -1;
            return;
        }
    }

    if ( rdmsr_safe(MSR_HWP_CAPABILITIES, data->hwp_caps) )
    {
        hwp_err(policy->cpu, "rdmsr_safe(MSR_HWP_CAPABILITIES)\n");
        goto error;
    }

    if ( rdmsr_safe(MSR_HWP_REQUEST, data->curr_req.raw) )
    {
        hwp_err(policy->cpu, "rdmsr_safe(MSR_HWP_REQUEST)\n");
        goto error;
    }

    /* Check for turbo support. */
    intel_feature_detect(policy);

    if ( feature_hdc &&
         (!hdc_set_pkg_hdc_ctl(policy->cpu, opt_cpufreq_hdc) ||
          !hdc_set_pm_ctl1(policy->cpu, opt_cpufreq_hdc)) )
    {
        hwp_err(policy->cpu, "Disabling HDC support\n");
        feature_hdc = false;
    }

    hwp_get_cpu_speeds(policy);

    return;

 error:
    data->curr_req.raw = -1;
    val &= ~PM_ENABLE_HWP_ENABLE;
    if ( wrmsr_safe(MSR_PM_ENABLE, val) )
        hwp_err(policy->cpu, "wrmsr_safe(MSR_PM_ENABLE, %lx)\n", val);
}

static int cf_check hwp_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    static bool __read_mostly first_run = true;
    static union hwp_request initial_req;
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data;

    data = xzalloc(struct hwp_drv_data);
    if ( !data )
        return -ENOMEM;

    policy->governor = &cpufreq_gov_hwp;

    per_cpu(hwp_drv_data, cpu) = data;

    on_selected_cpus(cpumask_of(cpu), hwp_init_msrs, policy, 1);

    if ( data->curr_req.raw == -1 )
    {
        hwp_err(cpu, "Could not initialize HWP properly\n");
        per_cpu(hwp_drv_data, cpu) = NULL;
        xfree(data);
        return -ENODEV;
    }

    data->minimum = data->curr_req.min_perf;
    data->maximum = data->curr_req.max_perf;
    data->desired = data->curr_req.desired;
    data->energy_perf = data->curr_req.energy_perf;
    data->activity_window = data->curr_req.activity_window;

    if ( first_run )
    {
        hwp_verbose("CPU%u: HWP_CAPABILITIES: %016lx\n", cpu, data->hwp_caps);
        initial_req = data->curr_req;
    }

    if ( first_run || data->curr_req.raw != initial_req.raw )
    {
        hwp_verbose("CPU%u: rdmsr HWP_REQUEST %016lx\n", cpu,
                    data->curr_req.raw);
        first_run = false;
    }

    return 0;
}

static int cf_check hwp_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, policy->cpu);

    per_cpu(hwp_drv_data, policy->cpu) = NULL;
    xfree(data);

    return 0;
}

/*
 * The SDM reads like turbo should be disabled with MSR_IA32_PERF_CTL and
 * PERF_CTL_TURBO_DISENGAGE, but that does not seem to actually work, at least
 * with testing on i7-10810U and i7-8550U.  MSR_MISC_ENABLE and
 * MISC_ENABLE_TURBO_DISENGAGE is what Linux uses and seems to work.
 */
static void cf_check hwp_set_misc_turbo(void *info)
{
    const struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, policy->cpu);
    uint64_t msr;

    data->ret = 0;

    if ( rdmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
    {
        hwp_verbose("CPU%u: error rdmsr_safe(MSR_IA32_MISC_ENABLE)\n",
                    policy->cpu);
        data->ret = -EACCES;

        return;
    }

    if ( policy->turbo == CPUFREQ_TURBO_ENABLED )
        msr &= ~MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;
    else
        msr |= MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;

    if ( wrmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
    {
        hwp_verbose("CPU%u: error wrmsr_safe(MSR_IA32_MISC_ENABLE): %016lx\n",
                    policy->cpu, msr);
        data->ret = -EACCES;
    }
}

static int cf_check hwp_cpufreq_update(unsigned int cpu, struct cpufreq_policy *policy)
{
    on_selected_cpus(cpumask_of(cpu), hwp_set_misc_turbo, policy, 1);

    return per_cpu(hwp_drv_data, cpu)->ret;
}

static const struct cpufreq_driver __initconst_cf_clobber
hwp_cpufreq_driver = {
    .name   = XEN_HWP_DRIVER_NAME,
    .verify = hwp_cpufreq_verify,
    .target = hwp_cpufreq_target,
    .init   = hwp_cpufreq_cpu_init,
    .exit   = hwp_cpufreq_cpu_exit,
    .update = hwp_cpufreq_update,
};

int get_hwp_para(unsigned int cpu,
                 struct xen_cppc_para *cppc_para)
{
    const struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);

    if ( data == NULL )
        return -ENODATA;

    cppc_para->features         =
        (feature_hwp_activity_window ? XEN_SYSCTL_CPPC_FEAT_ACT_WINDOW : 0);
    cppc_para->lowest           = data->hw.lowest;
    cppc_para->lowest_nonlinear = data->hw.most_efficient;
    cppc_para->nominal          = data->hw.guaranteed;
    cppc_para->highest          = data->hw.highest;
    cppc_para->minimum          = data->minimum;
    cppc_para->maximum          = data->maximum;
    cppc_para->desired          = data->desired;
    cppc_para->energy_perf      = data->energy_perf;
    cppc_para->activity_window  = data->activity_window;

    return 0;
}

int set_hwp_para(struct cpufreq_policy *policy,
                 struct xen_set_cppc_para *set_cppc)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);
    bool cleared_act_window = false;

    if ( data == NULL )
        return -ENOENT;

    /* Validate all parameters - Disallow reserved bits. */
    if ( set_cppc->minimum > 255 ||
         set_cppc->maximum > 255 ||
         set_cppc->desired > 255 ||
         set_cppc->energy_perf > 255 ||
         (set_cppc->set_params & ~XEN_SYSCTL_CPPC_SET_PARAM_MASK) ||
         (set_cppc->activity_window & ~XEN_SYSCTL_CPPC_ACT_WINDOW_MASK) )
        return -EINVAL;

    /* Only allow values if params bit is set. */
    if ( (!(set_cppc->set_params & XEN_SYSCTL_CPPC_SET_DESIRED) &&
          set_cppc->desired) ||
         (!(set_cppc->set_params & XEN_SYSCTL_CPPC_SET_MINIMUM) &&
          set_cppc->minimum) ||
         (!(set_cppc->set_params & XEN_SYSCTL_CPPC_SET_MAXIMUM) &&
          set_cppc->maximum) ||
         (!(set_cppc->set_params & XEN_SYSCTL_CPPC_SET_ENERGY_PERF) &&
          set_cppc->energy_perf) ||
         (!(set_cppc->set_params & XEN_SYSCTL_CPPC_SET_ACT_WINDOW) &&
          set_cppc->activity_window) )
        return -EINVAL;

    /* Clear out activity window if lacking HW supported. */
    if ( (set_cppc->set_params & XEN_SYSCTL_CPPC_SET_ACT_WINDOW) &&
         !feature_hwp_activity_window )
    {
        set_cppc->set_params &= ~XEN_SYSCTL_CPPC_SET_ACT_WINDOW;
        cleared_act_window = true;
    }

    /* Return if there is nothing to do. */
    if ( set_cppc->set_params == 0 )
        return 0;

    /* Apply presets */
    switch ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_PRESET_MASK )
    {
    case XEN_SYSCTL_CPPC_SET_PRESET_POWERSAVE:
        data->minimum = data->hw.lowest;
        data->maximum = data->hw.lowest;
        data->activity_window = 0;
        data->energy_perf = HWP_ENERGY_PERF_MAX_POWERSAVE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_CPPC_SET_PRESET_PERFORMANCE:
        data->minimum = data->hw.highest;
        data->maximum = data->hw.highest;
        data->activity_window = 0;
        data->energy_perf = HWP_ENERGY_PERF_MAX_PERFORMANCE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_CPPC_SET_PRESET_BALANCE:
        data->minimum = data->hw.lowest;
        data->maximum = data->hw.highest;
        data->activity_window = 0;
        data->energy_perf = HWP_ENERGY_PERF_BALANCE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_CPPC_SET_PRESET_NONE:
        break;

    default:
        return -EINVAL;
    }

    /* Further customize presets if needed */
    if ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_MINIMUM )
        data->minimum = set_cppc->minimum;

    if ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_MAXIMUM )
        data->maximum = set_cppc->maximum;

    if ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_ENERGY_PERF )
        data->energy_perf = set_cppc->energy_perf;

    if ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_DESIRED )
        data->desired = set_cppc->desired;

    if ( set_cppc->set_params & XEN_SYSCTL_CPPC_SET_ACT_WINDOW )
        data->activity_window = set_cppc->activity_window &
                                XEN_SYSCTL_CPPC_ACT_WINDOW_MASK;

    return hwp_cpufreq_target(policy, 0, 0);
}

int __init hwp_register_driver(void)
{
    int ret;

    if ( !hwp_available() )
        return -ENODEV;

    ret = cpufreq_register_driver(&hwp_cpufreq_driver);
    cpufreq_governor_internal = (ret == 0);

    return ret;
}
