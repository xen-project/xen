#ifndef _ASM_MAX_NUMNODES_H
#define _ASM_MAX_NUMNODES_H

#include <xen/config.h>

#if defined(__i386__)
#ifdef CONFIG_X86_NUMAQ

/* Max 16 Nodes */
#define NODES_SHIFT	4

#elif defined(CONFIG_ACPI_SRAT)

/* Max 8 Nodes */
#define NODES_SHIFT	3

#endif /* CONFIG_X86_NUMAQ */


#endif /* __i386__ */

#if defined(CONFIG_NUMA) && defined(__x86_64__)
#define NODES_SHIFT  6
#endif /* __x86_64__ */

#endif /* _ASM_MAX_NUMNODES_H */
