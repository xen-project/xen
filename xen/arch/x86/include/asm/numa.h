#ifndef _ASM_X8664_NUMA_H 
#define _ASM_X8664_NUMA_H 1

#include <xen/cpumask.h>

typedef u8 nodeid_t;

extern int srat_rev;

extern nodeid_t pxm_to_node(unsigned int pxm);
extern unsigned int numa_node_to_arch_nid(nodeid_t n);

#define ZONE_ALIGN (1UL << (MAX_ORDER+PAGE_SHIFT))

extern bool numa_disabled(void);
extern nodeid_t setup_node(unsigned int pxm);
extern void srat_detect_node(int cpu);

extern nodeid_t apicid_to_node[];
extern void init_cpu_to_node(void);

#define arch_want_default_dmazone() (num_online_nodes() > 1)

void srat_parse_regions(paddr_t addr);
extern u8 __node_distance(nodeid_t a, nodeid_t b);
unsigned int arch_get_dma_bitsize(void);

#endif
