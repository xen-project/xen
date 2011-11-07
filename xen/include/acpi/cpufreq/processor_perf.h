#ifndef __XEN_PROCESSOR_PM_H__
#define __XEN_PROCESSOR_PM_H__

#include <public/platform.h>
#include <public/sysctl.h>
#include <xen/acpi.h>

#define XEN_PX_INIT 0x80000000

int powernow_cpufreq_init(void);
unsigned int powernow_register_driver(void);
unsigned int get_measured_perf(unsigned int cpu, unsigned int flag);
void cpufreq_residency_update(unsigned int, uint8_t);
void cpufreq_statistic_update(unsigned int, uint8_t, uint8_t);
int  cpufreq_statistic_init(unsigned int);
void cpufreq_statistic_exit(unsigned int);
void cpufreq_statistic_reset(unsigned int);

int  cpufreq_limit_change(unsigned int);

int  cpufreq_add_cpu(unsigned int);
int  cpufreq_del_cpu(unsigned int);

struct processor_performance {
    uint32_t state;
    uint32_t platform_limit;
    struct xen_pct_register control_register;
    struct xen_pct_register status_register;
    uint32_t state_count;
    struct xen_processor_px *states;
    struct xen_psd_package domain_info;
    uint32_t shared_type;

    uint32_t init;
};

struct processor_pminfo {
    uint32_t acpi_id;
    uint32_t id;
    struct processor_performance    perf;
};

extern struct processor_pminfo *processor_pminfo[NR_CPUS];

struct px_stat {
    uint8_t total;        /* total Px states */
    uint8_t usable;       /* usable Px states */
    uint8_t last;         /* last Px state */
    uint8_t cur;          /* current Px state */
    uint64_t *trans_pt;   /* Px transition table */
    pm_px_val_t *pt;
};

struct pm_px {
    struct px_stat u;
    uint64_t prev_state_wall;
    uint64_t prev_idle_wall;
};

DECLARE_PER_CPU(struct pm_px *, cpufreq_statistic_data);

int cpufreq_cpu_init(unsigned int cpuid);
#endif /* __XEN_PROCESSOR_PM_H__ */
