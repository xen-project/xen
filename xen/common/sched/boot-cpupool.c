/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/common/boot_cpupools.c
 *
 * Code to create cpupools at boot time.
 *
 * Copyright (C) 2022 Arm Ltd.
 */

#include <xen/acpi.h>
#include <xen/sched.h>

/*
 * pool_cpu_map:   Index is logical cpu number, content is cpupool id, (-1) for
 *                 unassigned.
 * pool_sched_map: Index is cpupool id, content is scheduler id, (-1) for
 *                 unassigned.
 */
static int __initdata pool_cpu_map[NR_CPUS]   = { [0 ... NR_CPUS-1] = -1 };
static int __initdata pool_sched_map[NR_CPUS] = { [0 ... NR_CPUS-1] = -1 };
static unsigned int __initdata next_pool_id;

#define BTCPUPOOLS_DT_NODE_NO_REG     (-1)
#define BTCPUPOOLS_DT_NODE_NO_LOG_CPU (-2)
#define BTCPUPOOLS_DT_WRONG_NODE      (-3)
#define BTCPUPOOLS_DT_CORRUPTED_NODE  (-4)

static int __init get_logical_cpu_from_hw_id(unsigned int hwid)
{
    unsigned int i;

    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpu_physical_id(i) == hwid )
            return i;
    }

    return -1;
}

static int __init
get_logical_cpu_from_cpu_node(const struct dt_device_node *cpu_node)
{
    int cpu_num;
    const __be32 *prop;
    unsigned int cpu_reg;

    prop = dt_get_property(cpu_node, "reg", NULL);
    if ( !prop )
        return BTCPUPOOLS_DT_NODE_NO_REG;

    cpu_reg = dt_read_number(prop, dt_n_addr_cells(cpu_node));

    cpu_num = get_logical_cpu_from_hw_id(cpu_reg);
    if ( cpu_num < 0 )
        return BTCPUPOOLS_DT_NODE_NO_LOG_CPU;

    return cpu_num;
}

int __init btcpupools_get_domain_pool_id(const struct dt_device_node *node)
{
    const struct dt_device_node *phandle_node;
    int cpu_num;

    if ( !dt_device_is_compatible(node, "xen,cpupool") )
        return BTCPUPOOLS_DT_WRONG_NODE;
    /*
     * Get first cpu listed in the cpupool, from its reg it's possible to
     * retrieve the cpupool id.
     */
    phandle_node = dt_parse_phandle(node, "cpupool-cpus", 0);
    if ( !phandle_node )
        return BTCPUPOOLS_DT_CORRUPTED_NODE;

    cpu_num = get_logical_cpu_from_cpu_node(phandle_node);
    if ( cpu_num < 0 )
        return cpu_num;

    return pool_cpu_map[cpu_num];
}

static int __init check_and_get_sched_id(const char* scheduler_name)
{
    int sched_id = sched_get_id_by_name(scheduler_name);

    if ( sched_id < 0 )
        panic("Scheduler %s does not exists!\n", scheduler_name);

    return sched_id;
}

void __init btcpupools_dtb_parse(void)
{
    const struct dt_device_node *chosen, *node;

    if ( !acpi_disabled )
        return;

    chosen = dt_find_node_by_path("/chosen");
    if ( !chosen )
        panic("/chosen missing. Boot time cpupools can't be parsed from DT.\n");

    dt_for_each_child_node(chosen, node)
    {
        const struct dt_device_node *phandle_node;
        int sched_id = -1;
        const char* scheduler_name;
        unsigned int i = 0;

        if ( !dt_device_is_compatible(node, "xen,cpupool") )
            continue;

        if ( !dt_property_read_string(node, "cpupool-sched", &scheduler_name) )
            sched_id = check_and_get_sched_id(scheduler_name);

        phandle_node = dt_parse_phandle(node, "cpupool-cpus", i++);
        if ( !phandle_node )
            panic("Missing or empty cpupool-cpus property!\n");

        while ( phandle_node )
        {
            int cpu_num;

            cpu_num = get_logical_cpu_from_cpu_node(phandle_node);

            if ( cpu_num < 0 )
                panic("Error retrieving logical cpu from node %s (%d)\n",
                      dt_node_name(node), cpu_num);

            if ( pool_cpu_map[cpu_num] != -1 )
                panic("Logical cpu %d already added to a cpupool!\n", cpu_num);

            pool_cpu_map[cpu_num] = next_pool_id;

            phandle_node = dt_parse_phandle(node, "cpupool-cpus", i++);
        }

        /* Save scheduler choice for this cpupool id */
        pool_sched_map[next_pool_id] = sched_id;

        /* Let Xen generate pool ids */
        next_pool_id++;
    }
}

void __init btcpupools_allocate_pools(void)
{
    unsigned int i;
    bool add_extra_cpupool = false;
    int swap_id = -1;

    /*
     * If there are no cpupools, the value of next_pool_id is zero, so the code
     * below will assign every cpu to cpupool0 as the default behavior.
     * When there are cpupools, the code below is assigning all the not
     * assigned cpu to a new pool (next_pool_id value is the last id + 1).
     * In the same loop we check if there is any assigned cpu that is not
     * online.
     */
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpumask_test_cpu(i, &cpu_online_map) )
        {
            /* Unassigned cpu gets next_pool_id pool id value */
            if ( pool_cpu_map[i] < 0 )
            {
                pool_cpu_map[i] = next_pool_id;
                add_extra_cpupool = true;
            }

            /*
             * Cpu0 must be in cpupool0, otherwise some operations like moving
             * cpus between cpupools, cpu hotplug, destroying cpupools, shutdown
             * of the host, might not work in a sane way.
             */
            if ( !i && (pool_cpu_map[0] != 0) )
                swap_id = pool_cpu_map[0];

            if ( swap_id != -1 )
            {
                if ( pool_cpu_map[i] == swap_id )
                    pool_cpu_map[i] = 0;
                else if ( pool_cpu_map[i] == 0 )
                    pool_cpu_map[i] = swap_id;
            }
        }
        else
        {
            if ( pool_cpu_map[i] >= 0 )
                panic("Pool-%d contains cpu%u that is not online!\n",
                      pool_cpu_map[i], i);
        }
    }

    /* A swap happened, swap schedulers between cpupool id 0 and the other */
    if ( swap_id != -1 )
    {
        int swap_sched = pool_sched_map[swap_id];

        pool_sched_map[swap_id] = pool_sched_map[0];
        pool_sched_map[0] = swap_sched;
    }

    if ( add_extra_cpupool )
        next_pool_id++;

    /* Keep track of cpupool id 0 with the global cpupool0 */
    cpupool0 = cpupool_create_pool(0, pool_sched_map[0]);

    /* Create cpupools with selected schedulers */
    for ( i = 1; i < next_pool_id; i++ )
        cpupool_create_pool(i, pool_sched_map[i]);
}

unsigned int __init btcpupools_get_cpupool_id(unsigned int cpu)
{
    ASSERT((cpu < NR_CPUS) && (pool_cpu_map[cpu] >= 0));

    printk(XENLOG_INFO "Logical CPU %u in Pool-%d (Scheduler id: %d).\n",
           cpu, pool_cpu_map[cpu], pool_sched_map[pool_cpu_map[cpu]]);

    return pool_cpu_map[cpu];
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
