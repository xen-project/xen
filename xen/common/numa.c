/*
 * Generic VM initialization for NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/mm.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <xen/param.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/softirq.h>

static nodemask_t __initdata processor_nodes_parsed;
static nodemask_t __initdata memory_nodes_parsed;
static struct node __initdata numa_nodes[MAX_NUMNODES];

static unsigned int __ro_after_init num_node_memblks;
static struct node __ro_after_init node_memblk_range[NR_NODE_MEMBLKS];
static nodeid_t __ro_after_init memblk_nodeid[NR_NODE_MEMBLKS];
static __initdata DECLARE_BITMAP(memblk_hotplug, NR_NODE_MEMBLKS);

enum conflicts {
    NO_CONFLICT,
    OVERLAP,
    INTERLEAVE,
};

struct node_data __ro_after_init node_data[MAX_NUMNODES];

/* Mapping from pdx to node id */
unsigned int __ro_after_init memnode_shift;
unsigned long __ro_after_init memnodemapsize;
nodeid_t *__ro_after_init memnodemap;
static typeof(*memnodemap) __ro_after_init _memnodemap[64];

nodeid_t __read_mostly cpu_to_node[NR_CPUS] = {
    [0 ... NR_CPUS-1] = NUMA_NO_NODE
};

cpumask_t __read_mostly node_to_cpumask[MAX_NUMNODES];

nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

bool __ro_after_init numa_off;

const char *__ro_after_init numa_fw_nid_name = "???";

bool numa_disabled(void)
{
    return numa_off || arch_numa_disabled();
}

void __init numa_set_processor_nodes_parsed(nodeid_t node)
{
    node_set(node, processor_nodes_parsed);
}

bool valid_numa_range(paddr_t start, paddr_t end, nodeid_t node)
{
    unsigned int i;

    for ( i = 0; i < num_node_memblks; i++ )
    {
        const struct node *nd = &node_memblk_range[i];

        if ( nd->start <= start && nd->end >= end &&
             memblk_nodeid[i] == node )
            return true;
    }

    return false;
}

static enum conflicts __init conflicting_memblks(
    nodeid_t nid, paddr_t start, paddr_t end, paddr_t nd_start,
    paddr_t nd_end, unsigned int *mblkid)
{
    unsigned int i;

    /*
     * Scan all recorded nodes' memory blocks to check conflicts:
     * Overlap or interleave.
     */
    for ( i = 0; i < num_node_memblks; i++ )
    {
        const struct node *nd = &node_memblk_range[i];

        *mblkid = i;

        /* Skip 0 bytes node memory block. */
        if ( nd->start == nd->end )
            continue;
        /*
         * Use memblk range to check memblk overlaps, include the
         * self-overlap case. As nd's range is non-empty, the special
         * case "nd->end == end && nd->start == start" also can be covered.
         */
        if ( nd->end > start && nd->start < end )
            return OVERLAP;

        /*
         * Use node memory range to check whether new range contains
         * memory from other nodes - interleave check. We just need
         * to check full contains situation. Because overlaps have
         * been checked above.
         */
        if ( nid != memblk_nodeid[i] &&
             nd->start >= nd_start && nd->end <= nd_end )
            return INTERLEAVE;
    }

    return NO_CONFLICT;
}

static void __init cutoff_node(nodeid_t i, paddr_t start, paddr_t end)
{
    struct node *nd = &numa_nodes[i];

    if ( nd->start < start )
    {
        nd->start = start;
        if ( nd->end < nd->start )
            nd->start = nd->end;
    }

    if ( nd->end > end )
    {
        nd->end = end;
        if ( nd->start > nd->end )
            nd->start = nd->end;
    }
}

bool __init numa_memblks_available(void)
{
    return num_node_memblks < NR_NODE_MEMBLKS;
}

/*
 * This function will be called by NUMA memory affinity initialization to
 * update NUMA node's memory range. In this function, we assume all memory
 * regions belonging to a single node are in one chunk. Holes (or MMIO
 * ranges) between them will be included in the node.
 *
 * So in numa_update_node_memblks, if there are multiple banks for each
 * node, start and end are stretched to cover the holes between them, and
 * it works as long as memory banks of different NUMA nodes don't interleave.
 */
bool __init numa_update_node_memblks(nodeid_t node, unsigned int arch_nid,
                                     paddr_t start, paddr_t size, bool hotplug)
{
    unsigned int i;
    bool next = false;
    paddr_t end = start + size;
    paddr_t nd_start = start;
    paddr_t nd_end = end;
    struct node *nd = &numa_nodes[node];

    /*
     * For the node that already has some memory blocks, we will
     * expand the node memory range temporarily to check memory
     * interleaves with other nodes. We will not use this node
     * temp memory range to check overlaps, because it will mask
     * the overlaps in same node.
     *
     * Node with 0 bytes memory doesn't need this expansion.
     */
    if ( nd->start != nd->end )
    {
        if ( nd_start > nd->start )
            nd_start = nd->start;

        if ( nd_end < nd->end )
            nd_end = nd->end;
    }

    /* It is fine to add this area to the nodes data it will be used later */
    switch ( conflicting_memblks(node, start, end, nd_start, nd_end, &i) )
    {
    case OVERLAP:
        if ( memblk_nodeid[i] == node )
        {
            bool mismatch = !hotplug != !test_bit(i, memblk_hotplug);

            printk("%sNUMA: %s %u [%"PRIpaddr", %"PRIpaddr"] overlaps with itself [%"PRIpaddr", %"PRIpaddr"]\n",
                   mismatch ? KERN_ERR : KERN_WARNING, numa_fw_nid_name,
                   arch_nid, start, end - 1,
                   node_memblk_range[i].start, node_memblk_range[i].end - 1);
            if ( mismatch )
                return false;
            break;
        }

        printk(KERN_ERR
               "NUMA: %s %u [%"PRIpaddr", %"PRIpaddr"] overlaps with %s %u [%"PRIpaddr", %"PRIpaddr"]\n",
               numa_fw_nid_name, arch_nid, start, end - 1, numa_fw_nid_name,
               numa_node_to_arch_nid(memblk_nodeid[i]),
               node_memblk_range[i].start, node_memblk_range[i].end - 1);
        return false;

    case INTERLEAVE:
        printk(KERN_ERR
               "NUMA： %s %u: [%"PRIpaddr", %"PRIpaddr"] interleaves with %s %u memblk [%"PRIpaddr", %"PRIpaddr"]\n",
               numa_fw_nid_name, arch_nid, nd_start, nd_end - 1,
               numa_fw_nid_name, numa_node_to_arch_nid(memblk_nodeid[i]),
               node_memblk_range[i].start, node_memblk_range[i].end - 1);
        return false;

    case NO_CONFLICT:
        break;
    }

    if ( !hotplug )
    {
        node_set(node, memory_nodes_parsed);
        nd->start = nd_start;
        nd->end = nd_end;
    }

    printk(KERN_INFO "NUMA: Node %u %s %u [%"PRIpaddr", %"PRIpaddr"]%s\n",
           node, numa_fw_nid_name, arch_nid, start, end - 1,
           hotplug ? " (hotplug)" : "");

    /* Keep node_memblk_range[] sorted by address. */
    for ( i = 0; i < num_node_memblks; ++i )
        if ( node_memblk_range[i].start > start ||
             (node_memblk_range[i].start == start &&
             node_memblk_range[i].end > end) )
            break;

    memmove(&node_memblk_range[i + 1], &node_memblk_range[i],
            (num_node_memblks - i) * sizeof(*node_memblk_range));
    node_memblk_range[i].start = start;
    node_memblk_range[i].end = end;

    memmove(&memblk_nodeid[i + 1], &memblk_nodeid[i],
            (num_node_memblks - i) * sizeof(*memblk_nodeid));
    memblk_nodeid[i] = node;

    if ( hotplug )
    {
        next = true;
        if ( end > mem_hotplug )
            mem_hotplug = end;
    }

    for ( ; i <= num_node_memblks; ++i )
    {
        bool prev = next;

        next = test_bit(i, memblk_hotplug);
        if ( prev )
            __set_bit(i, memblk_hotplug);
        else
            __clear_bit(i, memblk_hotplug);
    }

    num_node_memblks++;

    return true;
}

/*
 * Sanity check to catch more bad SRATs (they are amazingly common).
 * Make sure the PXMs cover all memory.
 */
static bool __init nodes_cover_memory(void)
{
    unsigned int i;

    for ( i = 0; ; i++ )
    {
        int err;
        unsigned int j;
        bool found;
        paddr_t start, end;

        /* Try to loop memory map from index 0 to end to get RAM ranges. */
        err = arch_get_ram_range(i, &start, &end);

        /* Reached the end of the memory map? */
        if ( err == -ENOENT )
            break;

        /* Skip non-RAM entries. */
        if ( err )
            continue;

        do {
            found = false;
            for_each_node_mask ( j, memory_nodes_parsed )
                if ( start < numa_nodes[j].end && end > numa_nodes[j].start )
                {
                    if ( start >= numa_nodes[j].start )
                    {
                        start = numa_nodes[j].end;
                        found = true;
                    }

                    if ( end <= numa_nodes[j].end )
                    {
                        end = numa_nodes[j].start;
                        found = true;
                    }
                }
        } while ( found && start < end );

        if ( start < end )
        {
            printk(KERN_ERR "NUMA: No node for RAM range: "
                   "[%"PRIpaddr", %"PRIpaddr"]\n", start, end - 1);
            return false;
        }
    }

    return true;
}

/* Use discovered information to actually set up the nodes. */
static bool __init numa_process_nodes(paddr_t start, paddr_t end)
{
    int ret;
    unsigned int i;
    nodemask_t all_nodes_parsed;

    /* First clean up the node list */
    for ( i = 0; i < MAX_NUMNODES; i++ )
        cutoff_node(i, start, end);

    /* When numa is on and has data, we can start to process numa nodes. */
    if ( arch_numa_unavailable() )
        return false;

    if ( !nodes_cover_memory() )
    {
        numa_fw_bad();
        return false;
    }

    ret = compute_hash_shift(node_memblk_range, num_node_memblks,
                             memblk_nodeid);
    if ( ret < 0 )
    {
        printk(KERN_ERR
               "NUMA: No NUMA node hash function found. Contact maintainer\n");
        numa_fw_bad();
        return false;
    }
    memnode_shift = ret;

    nodes_or(all_nodes_parsed, memory_nodes_parsed, processor_nodes_parsed);

    /* Finally register nodes */
    for_each_node_mask ( i, all_nodes_parsed )
    {
        if ( numa_nodes[i].end == numa_nodes[i].start )
            printk(KERN_INFO "NUMA: node %u has no memory\n", i);

        setup_node_bootmem(i, numa_nodes[i].start, numa_nodes[i].end);
    }

    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpu_to_node[i] == NUMA_NO_NODE )
            continue;
        if ( !nodemask_test(cpu_to_node[i], &processor_nodes_parsed) )
            numa_set_node(i, NUMA_NO_NODE);
    }

    numa_init_array();

    return true;
}

/*
 * Given a shift value, try to populate memnodemap[]
 * Returns :
 * 1 if OK
 * 0 if memnodmap[] too small (or shift too small)
 * -1 if node overlap or lost ram (shift too big)
 */
static int __init populate_memnodemap(const struct node *nodes,
                                      unsigned int numnodes, unsigned int shift,
                                      const nodeid_t *nodeids)
{
    unsigned int i;
    int res = -1;

    memset(memnodemap, NUMA_NO_NODE, memnodemapsize * sizeof(*memnodemap));

    for ( i = 0; i < numnodes; i++ )
    {
        unsigned long spdx = paddr_to_pdx(nodes[i].start);
        unsigned long epdx = paddr_to_pdx(nodes[i].end - 1);

        if ( spdx > epdx )
            continue;

        if ( (epdx >> shift) >= memnodemapsize )
            return 0;

        do {
            if ( memnodemap[spdx >> shift] != NUMA_NO_NODE &&
                 (!nodeids || memnodemap[spdx >> shift] != nodeids[i]) )
                return -1;

            if ( !nodeids )
                memnodemap[spdx >> shift] = i;
            else
                memnodemap[spdx >> shift] = nodeids[i];

            spdx += (1UL << shift);
        } while ( spdx <= epdx );

        res = 1;
    }

    return res;
}

static int __init allocate_cachealigned_memnodemap(void)
{
    unsigned long size = PFN_UP(memnodemapsize * sizeof(*memnodemap));
    mfn_t mfn = alloc_boot_pages(size, 1);

    memnodemap = vmap_contig(mfn, size);
    if ( !memnodemap )
        panic("Unable to map the NUMA node map. Retry with numa=off");
    size <<= PAGE_SHIFT;
    printk(KERN_DEBUG "NUMA: Allocated memnodemap from %lx - %lx\n",
           mfn_to_maddr(mfn), mfn_to_maddr(mfn) + size);
    memnodemapsize = size / sizeof(*memnodemap);

    return 0;
}

/*
 * The LSB of all start addresses in the node map is the value of the
 * maximum possible shift.
 */
static unsigned int __init extract_lsb_from_nodes(const struct node *nodes,
                                                  nodeid_t numnodes,
                                                  const nodeid_t *nodeids)
{
    unsigned int i, nodes_used = 0;
    unsigned long bitfield = 0, memtop = 0;

    for ( i = 0; i < numnodes; i++ )
    {
        unsigned long spdx = paddr_to_pdx(nodes[i].start);
        unsigned long epdx = paddr_to_pdx(nodes[i].end - 1) + 1;

        if ( spdx >= epdx )
            continue;

        if ( i && (!nodeids || nodeids[i - 1] != nodeids[i]) )
            bitfield |= spdx;

        if ( !i || !nodeids || nodeids[i - 1] != nodeids[i] )
            nodes_used++;

        if ( epdx > memtop )
            memtop = epdx;
    }

    if ( nodes_used <= 1 )
        i = min(PADDR_BITS, BITS_PER_LONG - 1);
    else
        i = find_first_bit(&bitfield, sizeof(unsigned long) * 8);

    memnodemapsize = ((memtop - 1) >> i) + 1;

    return i;
}

int __init compute_hash_shift(const struct node *nodes,
                              unsigned int numnodes, const nodeid_t *nodeids)
{
    unsigned int shift = extract_lsb_from_nodes(nodes, numnodes, nodeids);

    if ( memnodemapsize <= ARRAY_SIZE(_memnodemap) )
        memnodemap = _memnodemap;
    else if ( allocate_cachealigned_memnodemap() )
        return -1;

    printk(KERN_DEBUG "NUMA: Using %u for the hash shift\n", shift);

    if ( populate_memnodemap(nodes, numnodes, shift, nodeids) != 1 )
    {
        printk(KERN_INFO "Your memory is not aligned you need to "
               "rebuild your hypervisor with a bigger NODEMAPSIZE "
               "shift=%u\n", shift);
        return -1;
    }

    return shift;
}

/**
 * @brief Initialize a NUMA node's node_data structure at boot.
 *
 * It is given the NUMA node's index in the node_data array as well
 * as the start and exclusive end address of the node's memory span
 * as arguments and initializes the node_data entry with this information.
 *
 * It then initializes the total number of usable memory pages within
 * the NUMA node's memory span using the arch_get_ram_range() function.
 *
 * @param nodeid The index into the node_data array for the node.
 * @param start The starting physical address of the node's memory range.
 * @param end The exclusive ending physical address of the node's memory range.
 */
void __init setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end)
{
    unsigned long start_pfn = paddr_to_pfn(start);
    unsigned long end_pfn = paddr_to_pfn(end);
    struct node_data *node = NODE_DATA(nodeid);
    unsigned int idx = 0;
    int err;

    node->node_start_pfn = start_pfn;
    node->node_spanned_pages = end_pfn - start_pfn;
    node->node_present_pages = 0;

    /* Calculate the number of present RAM pages within the node */
    do {
        paddr_t ram_start, ram_end;

        err = arch_get_ram_range(idx++, &ram_start, &ram_end);
        if ( !err && ram_start < end && ram_end > start )
            node->node_present_pages += PFN_DOWN(min(ram_end, end)) -
                                        PFN_UP(max(ram_start, start));
    } while ( err != -ENOENT );

    node_set_online(nodeid);
}

void __init numa_init_array(void)
{
    unsigned int i;
    nodeid_t rr;

    /*
     * There are unfortunately some poorly designed mainboards
     * around that only connect memory to a single CPU. This
     * breaks the 1:1 cpu->node mapping. To avoid this fill in
     * the mapping for all possible CPUs, as the number of CPUs
     * is not known yet. We round robin the existing nodes.
     */
    rr = first_node(node_online_map);
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpu_to_node[i] != NUMA_NO_NODE )
            continue;
        numa_set_node(i, rr);
        rr = cycle_node(rr, node_online_map);
    }
}

#ifdef CONFIG_NUMA_EMU
static unsigned int __initdata numa_fake;

/* Numa emulation */
static int __init numa_emulation(unsigned long start_pfn,
                                 unsigned long end_pfn)
{
    int ret;
    unsigned int i;
    struct node nodes[MAX_NUMNODES];
    uint64_t sz = pfn_to_paddr(end_pfn - start_pfn) / numa_fake;

    /* Kludge needed for the hash function */
    if ( multiple_bits_set(sz) )
    {
        uint64_t x = 1;

        while ( (x << 1) < sz )
            x <<= 1;
        if ( x < sz / 2 )
            printk(KERN_ERR "Numa emulation unbalanced. Complain to maintainer\n");
        sz = x;
    }

    memset(&nodes, 0, sizeof(nodes));
    for ( i = 0; i < numa_fake; i++ )
    {
        nodes[i].start = pfn_to_paddr(start_pfn) + i * sz;

        if ( i == numa_fake - 1 )
            sz = pfn_to_paddr(end_pfn) - nodes[i].start;

        nodes[i].end = nodes[i].start + sz;
        printk(KERN_INFO "Faking node %u at %"PRIx64"-%"PRIx64" (%"PRIu64"MB)\n",
               i, nodes[i].start, nodes[i].end,
               (nodes[i].end - nodes[i].start) >> 20);
        node_set_online(i);
    }

    ret = compute_hash_shift(nodes, numa_fake, NULL);
    if ( ret < 0 )
    {
        printk(KERN_ERR "No NUMA hash function found. Emulation disabled.\n");
        return -1;
    }
    memnode_shift = ret;

    for_each_online_node ( i )
        setup_node_bootmem(i, nodes[i].start, nodes[i].end);

    numa_init_array();

    return 0;
}
#endif

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{
    unsigned int i;
    paddr_t start = pfn_to_paddr(start_pfn);
    paddr_t end = pfn_to_paddr(end_pfn);

#ifdef CONFIG_NUMA_EMU
    if ( numa_fake && !numa_emulation(start_pfn, end_pfn) )
        return;
#endif

#ifdef CONFIG_NUMA
    if ( !numa_off && numa_process_nodes(start, end) )
        return;
#endif

    printk(KERN_INFO "%s\n",
           numa_off ? "NUMA turned off" : "No NUMA configuration found");

    printk(KERN_INFO "Faking a node at %"PRIpaddr"-%"PRIpaddr"\n",
           start, end);

    /* Setup dummy node covering all memory */
    memnode_shift = BITS_PER_LONG - 1;
    memnodemap = _memnodemap;

    /* Dummy node only uses 1 slot in reality */
    memnodemap[0] = 0;
    memnodemapsize = 1;

    nodes_clear(node_online_map);
    node_set_online(0);
    for ( i = 0; i < nr_cpu_ids; i++ )
        numa_set_node(i, 0);

    cpumask_copy(&node_to_cpumask[0], cpumask_of(0));
    setup_node_bootmem(0, start, end);
}

void numa_add_cpu(unsigned int cpu)
{
    cpumask_set_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
}

void numa_set_node(unsigned int cpu, nodeid_t node)
{
    cpu_to_node[cpu] = node;
}

/* [numa=off] */
static int __init cf_check numa_setup(const char *opt)
{
    if ( !strncmp(opt, "off", 3) )
        numa_off = true;
    else if ( !strncmp(opt, "on", 2) )
        numa_off = false;
#ifdef CONFIG_NUMA_EMU
    else if ( !strncmp(opt, "fake=", 5) )
    {
        numa_off = false;
        numa_fake = simple_strtoul(opt + 5, NULL, 0);
        if ( numa_fake >= MAX_NUMNODES )
            numa_fake = MAX_NUMNODES;
    }
#endif
    else
        return arch_numa_setup(opt);

    return 0;
}
custom_param("numa", numa_setup);

static void cf_check dump_numa(unsigned char key)
{
    s_time_t now = NOW();
    unsigned int i, j, n;
    struct domain *d;

    printk("'%c' pressed -> dumping numa info (now = %"PRI_stime")\n", key,
           now);

    for_each_online_node ( i )
    {
        mfn_t mfn = _mfn(node_start_pfn(i) + 1);

        printk("NODE%u start->%lu size->%lu free->%lu\n",
               i, node_start_pfn(i), node_spanned_pages(i),
               avail_node_heap_pages(i));
        /* Sanity check mfn_to_nid() */
        if ( node_spanned_pages(i) > 1 && mfn_to_nid(mfn) != i )
            printk("mfn_to_nid(%"PRI_mfn") -> %d should be %u\n",
                   mfn_x(mfn), mfn_to_nid(mfn), i);
    }

    j = cpumask_first(&cpu_online_map);
    n = 0;
    for_each_online_cpu ( i )
    {
        if ( i != j + n || cpu_to_node[j] != cpu_to_node[i] )
        {
            if ( n > 1 )
                printk("CPU%u...%u -> NODE%d\n", j, j + n - 1, cpu_to_node[j]);
            else
                printk("CPU%u -> NODE%d\n", j, cpu_to_node[j]);
            j = i;
            n = 1;
        }
        else
            ++n;
    }
    if ( n > 1 )
        printk("CPU%u...%u -> NODE%d\n", j, j + n - 1, cpu_to_node[j]);
    else
        printk("CPU%u -> NODE%d\n", j, cpu_to_node[j]);

    rcu_read_lock(&domlist_read_lock);

    printk("Memory location of each domain:\n");
    for_each_domain ( d )
    {
        const struct page_info *page;
        unsigned int page_num_node[MAX_NUMNODES];
        const struct vnuma_info *vnuma;

        process_pending_softirqs();

        printk("%pd (total: %u):\n", d, domain_tot_pages(d));

        memset(page_num_node, 0, sizeof(page_num_node));

        nrspin_lock(&d->page_alloc_lock);
        page_list_for_each ( page, &d->page_list )
        {
            i = page_to_nid(page);
            page_num_node[i]++;
        }
        nrspin_unlock(&d->page_alloc_lock);

        for_each_online_node ( i )
            printk("    Node %u: %u\n", i, page_num_node[i]);

        if ( !read_trylock(&d->vnuma_rwlock) )
            continue;

        if ( !d->vnuma )
        {
            read_unlock(&d->vnuma_rwlock);
            continue;
        }

        vnuma = d->vnuma;
        printk("     %u vnodes, %u vcpus, guest physical layout:\n",
               vnuma->nr_vnodes, d->max_vcpus);
        for ( i = 0; i < vnuma->nr_vnodes; i++ )
        {
            unsigned int start_cpu = ~0U;

            if ( vnuma->vnode_to_pnode[i] == NUMA_NO_NODE )
                printk("       %3u: pnode ???,", i);
            else
                printk("       %3u: pnode %3u,", i, vnuma->vnode_to_pnode[i]);

            printk(" vcpus ");

            for ( j = 0; j < d->max_vcpus; j++ )
            {
                if ( !(j & 0x3f) )
                    process_pending_softirqs();

                if ( vnuma->vcpu_to_vnode[j] == i )
                {
                    if ( start_cpu == ~0U )
                    {
                        printk("%u", j);
                        start_cpu = j;
                    }
                }
                else if ( start_cpu != ~0U )
                {
                    if ( j - 1 != start_cpu )
                        printk("-%u ", j - 1);
                    else
                        printk(" ");
                    start_cpu = ~0U;
                }
            }

            if ( start_cpu != ~0U  && start_cpu != j - 1 )
                printk("-%u", j - 1);

            printk("\n");

            for ( j = 0; j < vnuma->nr_vmemranges; j++ )
            {
                if ( vnuma->vmemrange[j].nid == i )
                    printk("           %016"PRIx64" - %016"PRIx64"\n",
                           vnuma->vmemrange[j].start,
                           vnuma->vmemrange[j].end);
            }
        }

        read_unlock(&d->vnuma_rwlock);
    }

    rcu_read_unlock(&domlist_read_lock);
}

static int __init cf_check register_numa_trigger(void)
{
    register_keyhandler('u', dump_numa, "dump NUMA info", 1);
    return 0;
}
__initcall(register_numa_trigger);
