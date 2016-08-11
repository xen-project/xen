#ifndef _ASM_X8664_NUMA_H 
#define _ASM_X8664_NUMA_H 1

#include <xen/cpumask.h>

#define NODES_SHIFT 6

typedef u8 nodeid_t;

extern int srat_rev;

extern nodeid_t      cpu_to_node[NR_CPUS];
extern cpumask_t     node_to_cpumask[];

#define cpu_to_node(cpu)		(cpu_to_node[cpu])
#define parent_node(node)		(node)
#define node_to_first_cpu(node)  (__ffs(node_to_cpumask[node]))
#define node_to_cpumask(node)    (node_to_cpumask[node])

struct node { 
	u64 start,end; 
};

extern int compute_hash_shift(struct node *nodes, int numnodes,
			      nodeid_t *nodeids);
extern nodeid_t pxm_to_node(unsigned int pxm);

#define ZONE_ALIGN (1UL << (MAX_ORDER+PAGE_SHIFT))
#define VIRTUAL_BUG_ON(x) 

extern void numa_add_cpu(int cpu);
extern void numa_init_array(void);
extern bool_t numa_off;


extern int srat_disabled(void);
extern void numa_set_node(int cpu, nodeid_t node);
extern nodeid_t setup_node(unsigned int pxm);
extern void srat_detect_node(int cpu);

extern void setup_node_bootmem(nodeid_t nodeid, u64 start, u64 end);
extern nodeid_t apicid_to_node[];
extern void init_cpu_to_node(void);

static inline void clear_node_cpumask(int cpu)
{
	cpumask_clear_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
}

/* Simple perfect hash to map pdx to node numbers */
extern int memnode_shift; 
extern unsigned long memnodemapsize;
extern u8 *memnodemap;

struct node_data {
    unsigned long node_start_pfn;
    unsigned long node_spanned_pages;
};

extern struct node_data node_data[];

static inline __attribute__((pure)) nodeid_t phys_to_nid(paddr_t addr)
{ 
	nodeid_t nid;
	VIRTUAL_BUG_ON((paddr_to_pdx(addr) >> memnode_shift) >= memnodemapsize);
	nid = memnodemap[paddr_to_pdx(addr) >> memnode_shift]; 
	VIRTUAL_BUG_ON(nid >= MAX_NUMNODES || !node_data[nid]); 
	return nid; 
} 

#define NODE_DATA(nid)		(&(node_data[nid]))

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define node_end_pfn(nid)       (NODE_DATA(nid)->node_start_pfn + \
				 NODE_DATA(nid)->node_spanned_pages)

extern int valid_numa_range(u64 start, u64 end, nodeid_t node);

void srat_parse_regions(u64 addr);
extern u8 __node_distance(nodeid_t a, nodeid_t b);
unsigned int arch_get_dma_bitsize(void);

#endif
