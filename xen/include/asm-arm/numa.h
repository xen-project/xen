#ifndef __ARCH_ARM_NUMA_H
#define __ARCH_ARM_NUMA_H

/* Fake one node for now... */
#define cpu_to_node(cpu) 0
#define node_to_cpumask(node)   (cpu_online_map)

static inline __attribute__((pure)) int phys_to_nid(paddr_t addr)
{
    return 0;
}

#endif /* __ARCH_ARM_NUMA_H */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
