/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for NUMA setup.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#include "wrapped-xen-numa.h"
#include "../../xen/common/numa.c"

static void numa_reset_state(void)
{
    bitmap_clear(processor_nodes_parsed.bits, CONFIG_NR_NUMA_NODES);
    bitmap_clear(memory_nodes_parsed.bits, CONFIG_NR_NUMA_NODES);
    bitmap_clear(memblk_hotplug, NR_NODE_MEMBLKS);
    memset(numa_nodes, 0, sizeof(numa_nodes));
    memset(node_memblk_range, 0, sizeof(node_memblk_range));
    memset(memblk_nodeid, 0, sizeof(memblk_nodeid));
    memset(node_data, 0, sizeof(node_data));
    memset(node_to_cpumask, 0, sizeof(node_to_cpumask));
    memset(cpu_to_node, NUMA_NO_NODE, sizeof(cpu_to_node));
    num_node_memblks = 0;
    memnode_shift = 0;
    memnodemapsize = 0;
    if ( memnodemap != _memnodemap )
        free(memnodemap);
    memnodemap = NULL;
    bitmap_clear(node_online_map.bits, CONFIG_NR_NUMA_NODES);
    node_set(1, node_online_map);
}

struct mem_affinity {
    /* Ranges are defined as [start, end]. */
    paddr_t start, end;
    unsigned int nid;
};

struct mem_range {
    /* Ranges are defined as [start, end]. */
    paddr_t start, end;
};

const static struct mem_range *ram;

int arch_get_ram_range(unsigned int idx, paddr_t *start, paddr_t *end)
{
    if ( idx >= MAX_RANGES || !ram[idx].end )
        return -ENOENT;

    *start = ram[idx].start;
    *end = ram[idx].end + 1;

    return 0;
}

static void print_ranges(const struct mem_affinity *r)
{
    unsigned int i;

    printf("Affinity ranges:\n");
    for ( i = 0; i < MAX_RANGES; i++ )
    {
        if ( !r[i].end )
            break;

        printf(" NID %u [%" PRIpaddr ", %" PRIpaddr "]\n",
               r[i].nid, r[i].start, r[i].end);
    }

    printf("RAM ranges:\n");
    for ( i = 0; i < MAX_RANGES; i++ )
    {
        if ( !ram[i].end )
            break;

        printf(" [%" PRIpaddr ", %" PRIpaddr "]\n",
               ram[i].start, ram[i].end);
    }
}

static bool test_paddr(paddr_t addr)
{
    mfn_t mfn = PFN_DOWN(addr);
    unsigned int idx = mfn >> memnode_shift;
    unsigned int nid;

    if ( idx >= memnodemapsize )
    {
        printf("Fail: MFN %lx -> IDX %u outside of memnodemap range\n",
               mfn, idx);
        return false;
    }

    nid = memnodemap[idx];
    if ( nid >= MAX_NUMNODES )
    {
        printf("Fail: MFN %lx -> NID %u >= MAX_NUMNODES (%u)\n",
               mfn, nid, MAX_NUMNODES);
        return false;
    }

    if ( !node_data[nid].node_spanned_pages )
    {
        printf("Fail: MFN %lx -> NID %u without spanned pages\n",
               mfn, nid);
        return false;

    }

    if ( !node_data[nid].node_spanned_pages )
    {
        printf("Fail: MFN %lx -> NID %u without spanned pages\n",
               mfn, nid);
        return false;

    }

    if ( !node_data[nid].node_spanned_pages )
    {
        printf("Fail: MFN %lx outside NID range [%013lx, %013lx]\n",
               mfn, node_data[nid].node_start_pfn,
               node_data[nid].node_start_pfn +
               node_data[nid].node_spanned_pages - 1);
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
    static const struct {
        struct mem_affinity affinity[MAX_RANGES];
        struct mem_range ram[MAX_RANGES];
    } tests[] = {
        /* From an arbitrary AMD Turin system. */
        {
            .affinity = {
                { .nid = 0, .start = 0x00000000000ULL, .end = 0x0000009ffffULL },
                { .nid = 0, .start = 0x000000c0000ULL, .end = 0x000afffffffULL },
                { .nid = 0, .start = 0x00100000000ULL, .end = 0x0c04fffffffULL },
                { .nid = 1, .start = 0x0c050000000ULL, .end = 0x0fc4fffffffULL },
                { .nid = 1, .start = 0x10000000000ULL, .end = 0x183ffffffffULL },
            },
            .ram = {
                { .start = 0x00000000000ULL, .end = 0x0000009ffffULL },
                { .start = 0x00000100000ULL, .end = 0x0007590ffffULL },
                { .start = 0x000759d1000ULL, .end = 0x00075a0ffffULL },
                { .start = 0x00076000000ULL, .end = 0x00094c73fffULL },
                { .start = 0x0009b5ff000ULL, .end = 0x0009fff9fffULL },
                { .start = 0x0009ffff000ULL, .end = 0x0009fffffffULL },
                { .start = 0x00100010000ULL, .end = 0x0fc4fffffffULL },
                { .start = 0x10000000000ULL, .end = 0x183f7ffffffULL },
                { .start = 0x183f8800000ULL, .end = 0x183faabffffULL },
            },
        },
        /* Found on a pre-production system. */
        {
            .affinity = {
                { .nid = 0, .start = 0x00000000000ULL, .end = 0x000afffffffULL },
                { .nid = 0, .start = 0x00100000000ULL, .end = 0x0fc4fffffffULL },
                { .nid = 0, .start = 0x10000000000ULL, .end = 0x103ffffffffULL },
                { .nid = 1, .start = 0x10400000000ULL, .end = 0x203ffffffffULL },
            },
            .ram = {
                { .start = 0x00000000000ULL, .end = 0x0000009ffffULL },
                { .start = 0x00000100000ULL, .end = 0x000165bffffULL },
                { .start = 0x00016600000ULL, .end = 0x0001aa1dfffULL },
                { .start = 0x0001aa1f000ULL, .end = 0x0001aa53fffULL },
                { .start = 0x0001aab8000ULL, .end = 0x0001aac6fffULL },
                { .start = 0x0001aacc000ULL, .end = 0x0006f3fefffULL },
                { .start = 0x00075dff000ULL, .end = 0x00075dfffffULL },
                { .start = 0x00076000000ULL, .end = 0x000a7ffffffULL },
                { .start = 0x00100010000ULL, .end = 0x0fc43ffffffULL },
                { .start = 0x0fc45000000ULL, .end = 0x0fc47ffffffULL },
                { .start = 0x0fc49000000ULL, .end = 0x0fc4bffffffULL },
                { .start = 0x0fc4d000000ULL, .end = 0x0fc4d3bffffULL },
                { .start = 0x0fc4f000000ULL, .end = 0x0fc4f0fffffULL },
                { .start = 0x10000000000ULL, .end = 0x203fd7fffffULL },
            },
        },
        /*
         * Reduction of the issue above: introduce an unaligned middle region
         * with regards to the hash shift.
         */
        {
            .affinity = {
                { .nid = 0, .start = 0x00000ULL, .end = 0x00fffULL },
                /*
                 * The offset of the region below is not aligned with the hash
                 * shift: the shift calculation only takes into account the
                 * start of node address.
                 */
                { .nid = 0, .start = 0x01000ULL, .end = 0x04fffULL },
                { .nid = 1, .start = 0x14000ULL, .end = 0x14fffULL },
            },
            .ram = {
                { .start = 0x00000ULL, .end = 0x04fffULL },
                { .start = 0x14000ULL, .end = 0x14fffULL },
            },
        },
    };
    int ret_code = EXIT_SUCCESS;

    /* Dummy firmware interface provider name, use TST for TEST. */
    numa_fw_nid_name = "TST";

    for ( unsigned int i = 0 ; i < ARRAY_SIZE(tests); i++ )
    {
        paddr_t min = ~(paddr_t)0, max = 0;
        unsigned int j;

        numa_reset_state();

        ram = tests[i].ram;

        for ( j = 0;
              j < ARRAY_SIZE(tests[i].affinity) && tests[i].affinity[j].end;
              j++ )
        {
            const struct mem_affinity *affinity = &tests[i].affinity[j];
            paddr_t length = affinity->end - affinity->start + 1;

            if ( !numa_update_node_memblks(affinity->nid, affinity->nid,
                                           affinity->start, length, false) )
            {
                printf("Fail to add NID %u [%" PRIpaddr ", %" PRIpaddr "]\n",
                        affinity->nid, affinity->start, affinity->end);
                ret_code = EXIT_FAILURE;
                continue;
            }

            min = min(min, affinity->start);
            max = max(max, affinity->end);
        }

        if ( !numa_process_nodes(min, max + 1) )
        {
            printf("Unable to process nodes\n");
            print_ranges(tests[i].affinity);
            ret_code = EXIT_FAILURE;
            continue;
        }

        for ( j = 0;
              j < ARRAY_SIZE(tests[i].ram) && tests[i].ram[j].end;
              j++ )
            if ( !test_paddr(tests[i].ram[j].start) ||
                 !test_paddr(tests[i].ram[j].end) )
                ret_code = EXIT_FAILURE;
    }

    return ret_code;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
