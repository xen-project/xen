#ifndef _ASM_X8664_NUMA_H 
#define _ASM_X8664_NUMA_H 1

#include <xen/cpumask.h>

#define NODES_SHIFT 6

extern int srat_rev;

extern unsigned char cpu_to_node[];
extern cpumask_t     node_to_cpumask[];

#define cpu_to_node(cpu)		(cpu_to_node[cpu])
#define parent_node(node)		(node)
#define node_to_first_cpu(node)  (__ffs(node_to_cpumask[node]))
#define node_to_cpumask(node)    (node_to_cpumask[node])

struct node { 
	u64 start,end; 
};

extern int compute_hash_shift(struct node *nodes, int numnodes,
			      int *nodeids);
extern int pxm_to_node(int nid);

#define ZONE_ALIGN (1UL << (MAX_ORDER+PAGE_SHIFT))
#define VIRTUAL_BUG_ON(x) 

extern void numa_add_cpu(int cpu);
extern void numa_init_array(void);
extern int numa_off;


extern int srat_disabled(void);
extern void numa_set_node(int cpu, int node);
extern int setup_node(int pxm);
extern void srat_detect_node(int cpu);

extern void setup_node_bootmem(int nodeid, u64 start, u64 end);
extern unsigned char apicid_to_node[];
#ifdef CONFIG_NUMA
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
    unsigned int  node_id;
};

extern struct node_data node_data[];

static inline __attribute__((pure)) int phys_to_nid(paddr_t addr) 
{ 
	unsigned nid;
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

extern int valid_numa_range(u64 start, u64 end, int node);
#else
#define init_cpu_to_node() do {} while (0)
#define clear_node_cpumask(cpu) do {} while (0)
#define valid_numa_range(start, end, node) 1
#endif

void srat_parse_regions(u64 addr);
extern int __node_distance(int a, int b);

#endif
