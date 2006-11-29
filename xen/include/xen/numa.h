#ifndef _XEN_NUMA_H
#define _XEN_NUMA_H

#include <xen/config.h>
#include <asm/numa.h>

#ifndef NODES_SHIFT
#define NODES_SHIFT     0
#endif

#define MAX_NUMNODES    (1 << NODES_SHIFT)

#endif /* _XEN_NUMA_H */
