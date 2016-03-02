#include <xen/cpu.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/smp.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/psci.h>
#include <asm/acpi.h>

struct smp_enable_ops {
        int             (*prepare_cpu)(int);
};

static paddr_t cpu_release_addr[NR_CPUS];
static struct smp_enable_ops smp_enable_ops[NR_CPUS];

static int __init smp_spin_table_cpu_up(int cpu)
{
    paddr_t __iomem *release;

    if (!cpu_release_addr[cpu])
    {
        printk("CPU%d: No release addr\n", cpu);
        return -ENODEV;
    }

    release = ioremap_nocache(cpu_release_addr[cpu], 8);
    if ( !release )
    {
        dprintk(XENLOG_ERR, "CPU%d: Unable to map release address\n", cpu);
        return -EFAULT;
    }

    writeq(__pa(init_secondary), release);

    iounmap(release);

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

static int __init smp_psci_init(int cpu)
{
    if ( !psci_ver )
    {
        printk("CPU%d asks for PSCI, but DTB has no PSCI node\n", cpu);
        return -ENODEV;
    }

    smp_enable_ops[cpu].prepare_cpu = call_psci_cpu_on;
    return 0;
}

int __init arch_smp_init(void)
{
    /* Nothing */
    return 0;
}

static int __init dt_arch_cpu_init(int cpu, struct dt_device_node *dn)
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
    else if ( !strcmp(enable_method, "psci") )
        return smp_psci_init(cpu);
    else
    {
        printk("CPU%d has unknown enable method \"%s\"\n", cpu, enable_method);
        return -EINVAL;
    }

    return 0;
}

int __init arch_cpu_init(int cpu, struct dt_device_node *dn)
{
    if ( acpi_disabled )
        return dt_arch_cpu_init(cpu, dn);
    else
        /* acpi only supports psci at present */
        return smp_psci_init(cpu);
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
