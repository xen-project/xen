#ifndef __ARCH_ARM_NUMA_H
#define __ARCH_ARM_NUMA_H

typedef u8 nodeid_t;

/* Fake one node for now. See also node_online_map. */
#define cpu_to_node(cpu) 0
#define node_to_cpumask(node)   (cpu_online_map)

static inline __attribute__((pure)) nodeid_t phys_to_nid(paddr_t addr)
{
    return 0;
}

/* XXX: implement NUMA support */
#define node_spanned_pages(nid) (total_pages)
#define node_start_pfn(nid) (pdx_to_pfn(frametable_base_pdx))
#define __node_distance(a, b) (20)

static inline unsigned int arch_get_dma_bitsize(void)
{
    return 32;
}

#endif /* __ARCH_ARM_NUMA_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
