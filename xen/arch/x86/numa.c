/* 
 * Generic VM initialization for x86-64 NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */ 

#include <xen/mm.h>
#include <xen/string.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <xen/keyhandler.h>
#include <xen/time.h>
#include <xen/smp.h>
#include <xen/pfn.h>
#include <asm/acpi.h>
#include <xen/sched.h>
#include <xen/softirq.h>

static int numa_setup(const char *s);
custom_param("numa", numa_setup);

#ifndef Dprintk
#define Dprintk(x...)
#endif

/* from proto.h */
#define round_up(x,y) ((((x)+(y))-1) & (~((y)-1)))

struct node_data node_data[MAX_NUMNODES];

/* Mapping from pdx to node id */
int memnode_shift;
static typeof(*memnodemap) _memnodemap[64];
unsigned long memnodemapsize;
u8 *memnodemap;

nodeid_t cpu_to_node[NR_CPUS] __read_mostly = {
    [0 ... NR_CPUS-1] = NUMA_NO_NODE
};
/*
 * Keep BIOS's CPU2node information, should not be used for memory allocaion
 */
nodeid_t apicid_to_node[MAX_LOCAL_APIC] = {
    [0 ... MAX_LOCAL_APIC-1] = NUMA_NO_NODE
};
cpumask_t node_to_cpumask[MAX_NUMNODES] __read_mostly;

nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

bool numa_off;
s8 acpi_numa = 0;

int srat_disabled(void)
{
    return numa_off || acpi_numa < 0;
}

/*
 * Given a shift value, try to populate memnodemap[]
 * Returns :
 * 1 if OK
 * 0 if memnodmap[] too small (of shift too small)
 * -1 if node overlap or lost ram (shift too big)
 */
static int __init populate_memnodemap(const struct node *nodes,
                                      int numnodes, int shift, nodeid_t *nodeids)
{
    unsigned long spdx, epdx;
    int i, res = -1;

    memset(memnodemap, NUMA_NO_NODE, memnodemapsize * sizeof(*memnodemap));
    for ( i = 0; i < numnodes; i++ )
    {
        spdx = paddr_to_pdx(nodes[i].start);
        epdx = paddr_to_pdx(nodes[i].end - 1) + 1;
        if ( spdx >= epdx )
            continue;
        if ( (epdx >> shift) >= memnodemapsize )
            return 0;
        do {
            if ( memnodemap[spdx >> shift] != NUMA_NO_NODE )
                return -1;

            if ( !nodeids )
                memnodemap[spdx >> shift] = i;
            else
                memnodemap[spdx >> shift] = nodeids[i];

            spdx += (1UL << shift);
        } while ( spdx < epdx );
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
 * The LSB of all start and end addresses in the node map is the value of the
 * maximum possible shift.
 */
static int __init extract_lsb_from_nodes(const struct node *nodes,
                                         int numnodes)
{
    int i, nodes_used = 0;
    unsigned long spdx, epdx;
    unsigned long bitfield = 0, memtop = 0;

    for ( i = 0; i < numnodes; i++ )
    {
        spdx = paddr_to_pdx(nodes[i].start);
        epdx = paddr_to_pdx(nodes[i].end - 1) + 1;
        if ( spdx >= epdx )
            continue;
        bitfield |= spdx;
        nodes_used++;
        if ( epdx > memtop )
            memtop = epdx;
    }
    if ( nodes_used <= 1 )
        i = BITS_PER_LONG - 1;
    else
        i = find_first_bit(&bitfield, sizeof(unsigned long)*8);
    memnodemapsize = (memtop >> i) + 1;
    return i;
}

int __init compute_hash_shift(struct node *nodes, int numnodes,
                              nodeid_t *nodeids)
{
    int shift;

    shift = extract_lsb_from_nodes(nodes, numnodes);
    if ( memnodemapsize <= ARRAY_SIZE(_memnodemap) )
        memnodemap = _memnodemap;
    else if ( allocate_cachealigned_memnodemap() )
        return -1;
    printk(KERN_DEBUG "NUMA: Using %d for the hash shift.\n", shift);

    if ( populate_memnodemap(nodes, numnodes, shift, nodeids) != 1 )
    {
        printk(KERN_INFO "Your memory is not aligned you need to "
               "rebuild your hypervisor with a bigger NODEMAPSIZE "
               "shift=%d\n", shift);
        return -1;
    }

    return shift;
}
/* initialize NODE_DATA given nodeid and start/end */
void __init setup_node_bootmem(nodeid_t nodeid, u64 start, u64 end)
{ 
    unsigned long start_pfn, end_pfn;

    start_pfn = start >> PAGE_SHIFT;
    end_pfn = end >> PAGE_SHIFT;

    NODE_DATA(nodeid)->node_start_pfn = start_pfn;
    NODE_DATA(nodeid)->node_spanned_pages = end_pfn - start_pfn;

    node_set_online(nodeid);
} 

void __init numa_init_array(void)
{
    int rr, i;

    /* There are unfortunately some poorly designed mainboards around
       that only connect memory to a single CPU. This breaks the 1:1 cpu->node
       mapping. To avoid this fill in the mapping for all possible
       CPUs, as the number of CPUs is not known yet.
       We round robin the existing nodes. */
    rr = first_node(node_online_map);
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpu_to_node[i] != NUMA_NO_NODE )
            continue;
        numa_set_node(i, rr);
        rr = next_node(rr, node_online_map);
        if ( rr == MAX_NUMNODES )
            rr = first_node(node_online_map);
    }
}

#ifdef CONFIG_NUMA_EMU
static int numa_fake __initdata = 0;

/* Numa emulation */
static int __init numa_emulation(u64 start_pfn, u64 end_pfn)
{
    int i;
    struct node nodes[MAX_NUMNODES];
    u64 sz = ((end_pfn - start_pfn)<<PAGE_SHIFT) / numa_fake;

    /* Kludge needed for the hash function */
    if ( hweight64(sz) > 1 )
    {
        u64 x = 1;
        while ( (x << 1) < sz )
            x <<= 1;
        if ( x < sz/2 )
            printk(KERN_ERR "Numa emulation unbalanced. Complain to maintainer\n");
        sz = x;
    }

    memset(&nodes,0,sizeof(nodes));
    for ( i = 0; i < numa_fake; i++ )
    {
        nodes[i].start = (start_pfn<<PAGE_SHIFT) + i*sz;
        if ( i == numa_fake - 1 )
            sz = (end_pfn<<PAGE_SHIFT) - nodes[i].start;
        nodes[i].end = nodes[i].start + sz;
        printk(KERN_INFO "Faking node %d at %"PRIx64"-%"PRIx64" (%"PRIu64"MB)\n",
               i,
               nodes[i].start, nodes[i].end,
               (nodes[i].end - nodes[i].start) >> 20);
        node_set_online(i);
    }
    memnode_shift = compute_hash_shift(nodes, numa_fake, NULL);
    if ( memnode_shift < 0 )
    {
        memnode_shift = 0;
        printk(KERN_ERR "No NUMA hash function found. Emulation disabled.\n");
        return -1;
    }
    for_each_online_node ( i )
        setup_node_bootmem(i, nodes[i].start, nodes[i].end);
    numa_init_array();

    return 0;
}
#endif

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{ 
    int i;

#ifdef CONFIG_NUMA_EMU
    if ( numa_fake && !numa_emulation(start_pfn, end_pfn) )
        return;
#endif

#ifdef CONFIG_ACPI_NUMA
    if ( !numa_off && !acpi_scan_nodes((u64)start_pfn << PAGE_SHIFT,
         (u64)end_pfn << PAGE_SHIFT) )
        return;
#endif

    printk(KERN_INFO "%s\n",
           numa_off ? "NUMA turned off" : "No NUMA configuration found");

    printk(KERN_INFO "Faking a node at %016"PRIx64"-%016"PRIx64"\n",
           (u64)start_pfn << PAGE_SHIFT,
           (u64)end_pfn << PAGE_SHIFT);
    /* setup dummy node covering all memory */
    memnode_shift = BITS_PER_LONG - 1;
    memnodemap = _memnodemap;
    nodes_clear(node_online_map);
    node_set_online(0);
    for ( i = 0; i < nr_cpu_ids; i++ )
        numa_set_node(i, 0);
    cpumask_copy(&node_to_cpumask[0], cpumask_of(0));
    setup_node_bootmem(0, (u64)start_pfn << PAGE_SHIFT,
                    (u64)end_pfn << PAGE_SHIFT);
}

void numa_add_cpu(int cpu)
{
    cpumask_set_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
} 

void numa_set_node(int cpu, nodeid_t node)
{
    cpu_to_node[cpu] = node;
}

/* [numa=off] */
static __init int numa_setup(const char *opt)
{
    if ( !strncmp(opt,"off",3) )
        numa_off = true;
    else if ( !strncmp(opt,"on",2) )
        numa_off = false;
#ifdef CONFIG_NUMA_EMU
    else if ( !strncmp(opt, "fake=", 5) )
    {
        numa_off = false;
        numa_fake = simple_strtoul(opt+5,NULL,0);
        if ( numa_fake >= MAX_NUMNODES )
            numa_fake = MAX_NUMNODES;
    }
#endif
#ifdef CONFIG_ACPI_NUMA
    else if ( !strncmp(opt,"noacpi",6) )
    {
        numa_off = false;
        acpi_numa = -1;
    }
#endif
    else
        return -EINVAL;

    return 0;
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
        panic("No node with memory below 4Gb");

    /*
     * Try to not reserve the whole node's memory for DMA, but dividing
     * its spanned pages by (arbitrarily chosen) 4.
     */
    return min_t(unsigned int,
                 flsl(node_start_pfn(node) + node_spanned_pages(node) / 4 - 1)
                 + PAGE_SHIFT, 32);
}

static void dump_numa(unsigned char key)
{
    s_time_t now = NOW();
    unsigned int i, j, n;
    int err;
    struct domain *d;
    struct page_info *page;
    unsigned int page_num_node[MAX_NUMNODES];
    const struct vnuma_info *vnuma;

    printk("'%c' pressed -> dumping numa info (now-0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now);

    for_each_online_node ( i )
    {
        paddr_t pa = pfn_to_paddr(node_start_pfn(i) + 1);

        printk("NODE%u start->%lu size->%lu free->%lu\n",
               i, node_start_pfn(i), node_spanned_pages(i),
               avail_node_heap_pages(i));
        /* sanity check phys_to_nid() */
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
        process_pending_softirqs();

        printk("Domain %u (total: %u):\n", d->domain_id, d->tot_pages);

        for_each_online_node ( i )
            page_num_node[i] = 0;

        spin_lock(&d->page_alloc_lock);
        page_list_for_each(page, &d->page_list)
        {
            i = phys_to_nid((paddr_t)page_to_mfn(page) << PAGE_SHIFT);
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

            err = snprintf(keyhandler_scratch, 12, "%3u",
                    vnuma->vnode_to_pnode[i]);
            if ( err < 0 || vnuma->vnode_to_pnode[i] == NUMA_NO_NODE )
                strlcpy(keyhandler_scratch, "???", sizeof(keyhandler_scratch));

            printk("       %3u: pnode %s,", i, keyhandler_scratch);

            printk(" vcpus ");

            for ( j = 0; j < d->max_vcpus; j++ )
            {
                if ( !(j & 0x3f) )
                    process_pending_softirqs();

                if ( vnuma->vcpu_to_vnode[j] == i )
                {
                    if ( start_cpu == ~0U )
                    {
                        printk("%d", j);
                        start_cpu = j;
                    }
                }
                else if ( start_cpu != ~0U )
                {
                    if ( j - 1 != start_cpu )
                        printk("-%d ", j - 1);
                    else
                        printk(" ");
                    start_cpu = ~0U;
                }
            }

            if ( start_cpu != ~0U  && start_cpu != j - 1 )
                printk("-%d", j - 1);

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

static __init int register_numa_trigger(void)
{
    register_keyhandler('u', dump_numa, "dump NUMA info", 1);
    return 0;
}
__initcall(register_numa_trigger);

