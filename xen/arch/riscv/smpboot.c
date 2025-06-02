#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/sections.h>

#include <asm/current.h>

cpumask_t __read_mostly cpu_online_map;
cpumask_t __ro_after_init cpu_possible_map;

void __init smp_prepare_boot_cpu(void)
{
    set_processor_id(0);

    cpumask_set_cpu(0, &cpu_possible_map);
    cpumask_set_cpu(0, &cpu_online_map);
}
