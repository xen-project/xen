
#include <xen/errno.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/processor_perf.h>
#include <public/platform.h>

int get_cpu_id(u8 acpi_id)
{
    return -1;
}

int xenpf_copy_px_states(struct processor_performance *pxpt,
                         struct xen_processor_performance *dom0_px_info)
{
    return -ENOSYS;
}

int cpufreq_cpu_init(unsigned int cpuid)
{
    return -ENOSYS;
}
