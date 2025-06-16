#include <xen/cpumask.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/current.h>

cpumask_t __read_mostly cpu_online_map;
cpumask_t __ro_after_init cpu_possible_map;

void __init smp_prepare_boot_cpu(void)
{
    set_processor_id(0);

    cpumask_set_cpu(0, &cpu_possible_map);
    cpumask_set_cpu(0, &cpu_online_map);
}

/**
 * dt_get_hartid - Get the hartid from a CPU device node
 *
 * @cpun: CPU number(logical index) for which device node is required
 *
 * Return: The hartid for the CPU node or ~0UL if not found.
 */
static unsigned long dt_get_hartid(const struct dt_device_node *cpun)
{
    const __be32 *cell;
    unsigned int ac;
    uint32_t len;

    ac = dt_n_addr_cells(cpun);
    cell = dt_get_property(cpun, "reg", &len);

    /*
     * If ac > 2, the result may be truncated or meaningless unless
     * dt_read_number() supports wider integers.
     *
     * TODO: drop (ac > 2) when dt_read_number() will support wider
     *       integers.
     */
    if ( !cell || !ac || (ac > 2) || (ac > len / sizeof(*cell)) )
        return ~0UL;

    return dt_read_number(cell, ac);
}

/*
 * Returns the hartid of the given device tree node, or -ENODEV if the node
 * isn't an enabled and valid RISC-V hart node.
 */
int dt_processor_hartid(const struct dt_device_node *node,
                        unsigned long *hartid)
{
    const char *isa;
    int ret;

    if ( !dt_device_is_compatible(node, "riscv") )
    {
        printk("Found incompatible CPU\n");
        return -ENODEV;
    }

    *hartid = dt_get_hartid(node);
    if ( *hartid == ~0UL )
    {
        printk("Found CPU without CPU ID\n");
        return -ENODATA;
    }

    if ( !dt_device_is_available(node))
    {
        printk("CPU with hartid=%#lx is not available\n", *hartid);
        return -ENODEV;
    }

    if ( (ret = dt_property_read_string(node, "riscv,isa", &isa)) )
    {
        printk("CPU with hartid=%#lx has no \"riscv,isa\" property\n", *hartid);
        return ret;
    }

    if ( isa[0] != 'r' || isa[1] != 'v' )
    {
        printk("CPU with hartid=%#lx has an invalid ISA of \"%s\"\n", *hartid,
               isa);
        return -ENODEV;
    }

    return 0;
}
