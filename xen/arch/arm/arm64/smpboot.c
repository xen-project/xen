#include <xen/cpu.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/smp.h>

struct smp_enable_ops {
        int             (*prepare_cpu)(int);
};

static paddr_t cpu_release_addr[NR_CPUS];
static struct smp_enable_ops smp_enable_ops[NR_CPUS];

static int __init smp_spin_table_cpu_up(int cpu)
{
    paddr_t *release;

    if (!cpu_release_addr[cpu])
    {
        printk("CPU%d: No release addr\n", cpu);
        return -ENODEV;
    }

    release = __va(cpu_release_addr[cpu]);

    release[0] = __pa(init_secondary);
    flush_xen_data_tlb_range_va((vaddr_t)release, sizeof(*release));

    sev();
    return 0;
}

static void __init smp_spin_table_init(int cpu, struct dt_device_node *dn)
{
    if ( !dt_property_read_u64(dn, "cpu-release-addr", &cpu_release_addr[cpu]) )
    {
        printk("CPU%d has no cpu-release-addr\n", cpu);
        return;
    }

    smp_enable_ops[cpu].prepare_cpu = smp_spin_table_cpu_up;
}

int __init arch_smp_init(void)
{
    /* Nothing */
    return 0;
}

int __init arch_cpu_init(int cpu, struct dt_device_node *dn)
{
    const char *enable_method;

    enable_method = dt_get_property(dn, "enable-method", NULL);
    if (!enable_method)
    {
        printk("CPU%d has no enable method\n", cpu);
        return -EINVAL;
    }

    if ( !strcmp(enable_method, "spin-table") )
        smp_spin_table_init(cpu, dn);
    /* TODO: method "psci" */
    else
    {
        printk("CPU%d has unknown enable method \"%s\"\n", cpu, enable_method);
        return -EINVAL;
    }

    return 0;
}

int __init arch_cpu_up(int cpu)
{
    if ( !smp_enable_ops[cpu].prepare_cpu )
        return -ENODEV;

    return smp_enable_ops[cpu].prepare_cpu(cpu);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
