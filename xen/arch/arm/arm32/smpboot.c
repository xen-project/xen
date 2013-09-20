#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/smp.h>
#include <asm/platform.h>

int __init arch_smp_init(void)
{
    return platform_smp_init();
}

int __init arch_cpu_init(int cpu, struct dt_device_node *dn)
{
    /* TODO handle PSCI init */
    return 0;
}

int __init arch_cpu_up(int cpu)
{
    return platform_cpu_up(cpu);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
