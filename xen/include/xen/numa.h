#ifndef _XEN_NUMA_H
#define _XEN_NUMA_H

#include <asm/numa.h>

#define NUMA_NO_NODE     0xFF
#define NUMA_NO_DISTANCE 0xFF

#ifdef CONFIG_NR_NUMA_NODES
#define MAX_NUMNODES CONFIG_NR_NUMA_NODES
#else
#define MAX_NUMNODES 1
#endif

#define NR_NODE_MEMBLKS (MAX_NUMNODES * 2)

#define vcpu_to_node(v) (cpu_to_node((v)->processor))

#define domain_to_node(d) \
  (((d)->vcpu != NULL && (d)->vcpu[0] != NULL) \
   ? vcpu_to_node((d)->vcpu[0]) : NUMA_NO_NODE)

/* The following content can be used when NUMA feature is enabled */
#ifdef CONFIG_NUMA

extern nodeid_t      cpu_to_node[NR_CPUS];
extern cpumask_t     node_to_cpumask[];

#define cpu_to_node(cpu)        cpu_to_node[cpu]
#define parent_node(node)       (node)
#define node_to_cpumask(node)   node_to_cpumask[node]

struct node {
    paddr_t start, end;
};

extern int compute_hash_shift(const struct node *nodes,
                              unsigned int numnodes, const nodeid_t *nodeids);

extern bool numa_off;
extern const char *numa_fw_nid_name;

extern void numa_add_cpu(unsigned int cpu);
extern void numa_init_array(void);
extern void numa_set_node(unsigned int cpu, nodeid_t node);
extern void numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn);
extern void numa_fw_bad(void);

extern int arch_numa_setup(const char *opt);
extern bool arch_numa_unavailable(void);
extern bool arch_numa_disabled(void);
extern void setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end);

static inline void clear_node_cpumask(unsigned int cpu)
{
    cpumask_clear_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
}

/* Simple perfect hash to map pdx to node numbers */
extern unsigned int memnode_shift;
extern unsigned long memnodemapsize;
extern uint8_t *memnodemap;

struct node_data {
    unsigned long node_start_pfn;
    unsigned long node_spanned_pages;
};

extern struct node_data node_data[];

static inline nodeid_t __attribute_pure__ phys_to_nid(paddr_t addr)
{
    nodeid_t nid;
    ASSERT((paddr_to_pdx(addr) >> memnode_shift) < memnodemapsize);
    nid = memnodemap[paddr_to_pdx(addr) >> memnode_shift];
    ASSERT(nid < MAX_NUMNODES && node_data[nid].node_spanned_pages);
    return nid;
}

#define NODE_DATA(nid)          (&node_data[nid])

#define node_start_pfn(nid)     (NODE_DATA(nid)->node_start_pfn)
#define node_spanned_pages(nid) (NODE_DATA(nid)->node_spanned_pages)
#define node_end_pfn(nid)       (NODE_DATA(nid)->node_start_pfn + \
                                 NODE_DATA(nid)->node_spanned_pages)

/*
 * This function provides the ability for caller to get one RAM entry
 * from architectural memory map by index.
 *
 * This function will return zero if it can return a proper RAM entry.
 * Otherwise it will return -ENOENT for out of scope index, or other
 * error codes, e.g. return -ENODATA for non-RAM type memory entry.
 *
 * Note: the range is exclusive at the end, e.g. [*start, *end).
 */
extern int arch_get_ram_range(unsigned int idx,
                              paddr_t *start, paddr_t *end);
extern bool valid_numa_range(paddr_t start, paddr_t end, nodeid_t node);
extern bool numa_memblks_available(void);
extern bool numa_update_node_memblks(nodeid_t node, unsigned int arch_nid,
                                     paddr_t start, paddr_t size, bool hotplug);
extern void numa_set_processor_nodes_parsed(nodeid_t node);

#endif

#endif /* _XEN_NUMA_H */
