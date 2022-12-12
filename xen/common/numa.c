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
#include <xen/sched.h>
#include <xen/softirq.h>

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

bool numa_disabled(void)
{
    return numa_off || arch_numa_disabled();
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
    unsigned long mfn = mfn_x(alloc_boot_pages(size, 1));

    memnodemap = mfn_to_virt(mfn);
    mfn <<= PAGE_SHIFT;
    size <<= PAGE_SHIFT;
    printk(KERN_DEBUG "NUMA: Allocated memnodemap from %lx - %lx\n",
           mfn, mfn + size);
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

/* Initialize NODE_DATA given nodeid and start/end */
void __init setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end)
{
    unsigned long start_pfn = paddr_to_pfn(start);
    unsigned long end_pfn = paddr_to_pfn(end);

    NODE_DATA(nodeid)->node_start_pfn = start_pfn;
    NODE_DATA(nodeid)->node_spanned_pages = end_pfn - start_pfn;

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
    if ( hweight64(sz) > 1 )
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
    if ( !numa_off && !numa_process_nodes(start, end) )
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
        paddr_t pa = pfn_to_paddr(node_start_pfn(i) + 1);

        printk("NODE%u start->%lu size->%lu free->%lu\n",
               i, node_start_pfn(i), node_spanned_pages(i),
               avail_node_heap_pages(i));
        /* Sanity check phys_to_nid() */
        if ( phys_to_nid(pa) != i )
            printk("phys_to_nid(%"PRIpaddr") -> %d should be %u\n",
                   pa, phys_to_nid(pa), i);
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

        spin_lock(&d->page_alloc_lock);
        page_list_for_each ( page, &d->page_list )
        {
            i = phys_to_nid(page_to_maddr(page));
            page_num_node[i]++;
        }
        spin_unlock(&d->page_alloc_lock);

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
