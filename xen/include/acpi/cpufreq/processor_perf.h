#ifndef __XEN_PROCESSOR_PM_H__
#define __XEN_PROCESSOR_PM_H__

#include <public/platform.h>

int get_cpu_id(u8);
int acpi_cpufreq_init(void);

struct processor_performance {
    uint32_t state;
    uint32_t ppc;
    struct xen_pct_register control_register;
    struct xen_pct_register status_register;
    uint32_t state_count;
    struct xen_processor_px *states;
    struct xen_psd_package domain_info;
    cpumask_t shared_cpu_map;
    uint32_t shared_type;
};

struct processor_pminfo {
    uint32_t acpi_id;
    uint32_t id;
    uint32_t flag;
    struct processor_performance    perf;
};

extern struct processor_pminfo processor_pminfo[NR_CPUS];

#endif /* __XEN_PROCESSOR_PM_H__ */
