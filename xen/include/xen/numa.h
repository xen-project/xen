#ifndef _XEN_NUMA_H
#define _XEN_NUMA_H

#include <xen/config.h>

#ifdef CONFIG_DISCONTIGMEM
#include <asm/numnodes.h>
#endif

#ifndef NODES_SHIFT
#define NODES_SHIFT     0
#endif

#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NUMA_NO_NODE    0xff

#define MAX_PXM_DOMAINS    256   /* 1 byte and no promises about values */
#define PXM_BITMAP_LEN (MAX_PXM_DOMAINS / 8)
#define MAX_CHUNKS_PER_NODE   4
#define MAXCHUNKS    (MAX_CHUNKS_PER_NODE * MAX_NUMNODES)

/* needed for drivers/acpi/numa.c */
#define NR_NODE_MEMBLKS (MAX_NUMNODES*2)

extern unsigned int cpu_to_node[];
#include <xen/cpumask.h>
extern cpumask_t node_to_cpumask[];

typedef struct node_data {
    unsigned long node_start_pfn;
    unsigned long node_spanned_pages;
    unsigned int  node_id;
} node_data_t;

#endif /* _XEN_NUMA_H */
