#ifndef __XEN_PMSTAT_H_
#define __XEN_PMSTAT_H_

#include <xen/types.h>
#include <public/platform.h> /* for struct xen_processor_power */
#include <public/sysctl.h>   /* for struct pm_cx_stat */

int set_px_pminfo(uint32_t acpi_id, struct xen_processor_performance *perf);
long set_cx_pminfo(uint32_t acpi_id, struct xen_processor_power *power);
int set_cppc_pminfo(unsigned int acpi_id,
                    const struct xen_processor_cppc *cppc_data);

#ifdef CONFIG_COMPAT
struct compat_processor_performance;
int compat_set_px_pminfo(uint32_t acpi_id, struct compat_processor_performance *perf);
struct compat_processor_power;
long compat_set_cx_pminfo(uint32_t acpi_id, struct compat_processor_power *power);
struct compat_processor_cppc;
int compat_set_cppc_pminfo(unsigned int acpi_id,
                           const struct compat_processor_cppc *cppc_data);
#endif

uint32_t pmstat_get_cx_nr(unsigned int cpu);
int pmstat_get_cx_stat(unsigned int cpu, struct pm_cx_stat *stat);
int pmstat_reset_cx_stat(unsigned int cpu);

int do_get_pm_info(struct xen_sysctl_get_pmstat *op);
int do_pm_op(struct xen_sysctl_pm_op *op);

#endif /* __XEN_PMSTAT_H_ */
