/* 
 * Generic VM initialization for x86-64 NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */ 

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <asm/acpi.h>
#include <asm/e820.h>

#ifndef Dprintk
#define Dprintk(x...)
#endif

/* from proto.h */
#define round_up(x,y) ((((x)+(y))-1) & (~((y)-1)))

/*
 * Keep BIOS's CPU2node information, should not be used for memory allocaion
 */
nodeid_t apicid_to_node[MAX_LOCAL_APIC] = {
    [0 ... MAX_LOCAL_APIC-1] = NUMA_NO_NODE
};

int8_t __ro_after_init acpi_numa = 0;

int __init arch_numa_setup(const char *opt)
{
#ifdef CONFIG_ACPI_NUMA
    if ( !strncmp(opt, "noacpi", 6) )
    {
        numa_off = false;
        acpi_numa = -1;
        return 0;
    }
#endif

    return -EINVAL;
}

bool arch_numa_disabled(void)
{
    return acpi_numa < 0;
}

bool __init arch_numa_unavailable(void)
{
    return acpi_numa <= 0;
}

/*
 * Setup early cpu_to_node.
 *
 * Populate cpu_to_node[] only if x86_cpu_to_apicid[],
 * and apicid_to_node[] tables have valid entries for a CPU.
 * This means we skip cpu_to_node[] initialisation for NUMA
 * emulation and faking node case (when running a kernel compiled
 * for NUMA on a non NUMA box), which is OK as cpu_to_node[]
 * is already initialized in a round robin manner at numa_init_array,
 * prior to this call, and this initialization is good enough
 * for the fake NUMA cases.
 */
void __init init_cpu_to_node(void)
{
    unsigned int i;
    nodeid_t node;

    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        u32 apicid = x86_cpu_to_apicid[i];
        if ( apicid == BAD_APICID )
            continue;
        node = apicid < MAX_LOCAL_APIC ? apicid_to_node[apicid] : NUMA_NO_NODE;
        if ( node == NUMA_NO_NODE || !node_online(node) )
            node = 0;
        numa_set_node(i, node);
    }
}

unsigned int __init arch_get_dma_bitsize(void)
{
    unsigned int node;

    for_each_online_node(node)
        if ( node_spanned_pages(node) &&
             !(node_start_pfn(node) >> (32 - PAGE_SHIFT)) )
            break;
    if ( node >= MAX_NUMNODES )
        panic("No node with memory below 4Gb\n");

    /*
     * Try to not reserve the whole node's memory for DMA, but dividing
     * its spanned pages by (arbitrarily chosen) 4.
     */
    return min_t(unsigned int,
                 flsl(node_start_pfn(node) + node_spanned_pages(node) / 4 - 1)
                 + PAGE_SHIFT, 32);
}

/**
 * @brief Retrieves the RAM range for a given index from the e820 memory map.
 *
 * This function fetches the starting and ending addresses of a RAM range
 * specified by the given index idx from the e820 memory map.
 *
 * @param idx The index of the RAM range in the e820 memory map to retrieve.
 * @param start Pointer to store the starting address of the RAM range.
 * @param end Pointer to store the exclusive ending address of the RAM range.
 *
 * @return 0 on success, -ENOENT if the index is out of bounds,
 *         or -ENODATA if the memory map at index idx is not of type E820_RAM.
 */
int __init arch_get_ram_range(unsigned int idx, paddr_t *start, paddr_t *end)
{
    if ( idx >= e820.nr_map )
        return -ENOENT;

    if ( e820.map[idx].type != E820_RAM )
        return -ENODATA;

    *start = e820.map[idx].addr;
    *end = *start + e820.map[idx].size;

    return 0;
}
