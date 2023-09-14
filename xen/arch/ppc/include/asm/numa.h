#ifndef __ASM_PPC_NUMA_H__
#define __ASM_PPC_NUMA_H__

#include <xen/types.h>
#include <xen/mm.h>

typedef uint8_t nodeid_t;

/* Fake one node for now. See also node_online_map. */
#define cpu_to_node(cpu) 0
#define node_to_cpumask(node)   (cpu_online_map)

/*
 * TODO: make first_valid_mfn static when NUMA is supported on PPC, this
 * is required because the dummy helpers are using it.
 */
extern mfn_t first_valid_mfn;

/* XXX: implement NUMA support */
#define node_spanned_pages(nid) (max_page - mfn_x(first_valid_mfn))
#define node_start_pfn(nid) (mfn_x(first_valid_mfn))
#define __node_distance(a, b) (20)

#define arch_want_default_dmazone() (false)

#endif /* __ASM_PPC_NUMA_H__ */
