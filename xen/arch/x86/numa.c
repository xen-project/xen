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
#include <asm/acpi.h>
#include <xen/sched.h>

static int numa_setup(char *s);
custom_param("numa", numa_setup);

#ifndef Dprintk
#define Dprintk(x...)
#endif

/* from proto.h */
#define round_up(x,y) ((((x)+(y))-1) & (~((y)-1)))

struct node_data node_data[MAX_NUMNODES];

int memnode_shift;
u8  memnodemap[NODEMAPSIZE];

unsigned char cpu_to_node[NR_CPUS] __read_mostly = {
	[0 ... NR_CPUS-1] = NUMA_NO_NODE
};
unsigned char apicid_to_node[MAX_LOCAL_APIC] __cpuinitdata = {
 	[0 ... MAX_LOCAL_APIC-1] = NUMA_NO_NODE
};
cpumask_t node_to_cpumask[MAX_NUMNODES] __read_mostly;

nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

/* Default NUMA to off for now. acpi=on required to enable it. */
int numa_off __initdata = 1;

int acpi_numa __initdata;

/*
 * Given a shift value, try to populate memnodemap[]
 * Returns :
 * 1 if OK
 * 0 if memnodmap[] too small (of shift too small)
 * -1 if node overlap or lost ram (shift too big)
 */
static int __init
populate_memnodemap(const struct node *nodes, int numnodes, int shift)
{
	int i; 
	int res = -1;
	paddr_t addr, end;

	if (shift >= 64)
		return -1;
	memset(memnodemap, 0xff, sizeof(memnodemap));
	for (i = 0; i < numnodes; i++) {
		addr = nodes[i].start;
		end = nodes[i].end;
		if (addr >= end)
			continue;
		if ((end >> shift) >= NODEMAPSIZE)
			return 0;
		do {
			if (memnodemap[addr >> shift] != 0xff)
				return -1;
			memnodemap[addr >> shift] = i;
			addr += (1ULL << shift);
		} while (addr < end);
		res = 1;
	} 
	return res;
}

int __init compute_hash_shift(struct node *nodes, int numnodes)
{
	int shift = 20;

	while (populate_memnodemap(nodes, numnodes, shift + 1) >= 0)
		shift++;

	printk(KERN_DEBUG "NUMA: Using %d for the hash shift.\n",
		shift);

	if (populate_memnodemap(nodes, numnodes, shift) != 1) {
		printk(KERN_INFO
	"Your memory is not aligned you need to rebuild your kernel "
	"with a bigger NODEMAPSIZE shift=%d\n",
			shift);
		return -1;
	}
	return shift;
}

/* initialize NODE_DATA given nodeid and start/end */
void __init setup_node_bootmem(int nodeid, u64 start, u64 end)
{ 
	unsigned long start_pfn, end_pfn;

	start_pfn = start >> PAGE_SHIFT;
	end_pfn = end >> PAGE_SHIFT;

	NODE_DATA(nodeid)->node_id = nodeid;
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
	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_to_node[i] != NUMA_NO_NODE)
			continue;
 		numa_set_node(i, rr);
		rr = next_node(rr, node_online_map);
		if (rr == MAX_NUMNODES)
			rr = first_node(node_online_map);
	}

}

#ifdef CONFIG_NUMA_EMU
static int numa_fake __initdata = 0;

/* Numa emulation */
static int numa_emulation(u64 start_pfn, u64 end_pfn)
{
 	int i;
 	struct node nodes[MAX_NUMNODES];
 	u64 sz = ((end_pfn - start_pfn)<<PAGE_SHIFT) / numa_fake;

 	/* Kludge needed for the hash function */
 	if (hweight64(sz) > 1) {
 		u64 x = 1;
 		while ((x << 1) < sz)
 			x <<= 1;
 		if (x < sz/2)
 			printk(KERN_ERR "Numa emulation unbalanced. Complain to maintainer\n");
 		sz = x;
 	}

 	memset(&nodes,0,sizeof(nodes));
 	for (i = 0; i < numa_fake; i++) {
 		nodes[i].start = (start_pfn<<PAGE_SHIFT) + i*sz;
 		if (i == numa_fake-1)
 			sz = (end_pfn<<PAGE_SHIFT) - nodes[i].start;
 		nodes[i].end = nodes[i].start + sz;
 		printk(KERN_INFO "Faking node %d at %"PRIx64"-%"PRIx64" (%"PRIu64"MB)\n",
		       i,
		       nodes[i].start, nodes[i].end,
		       (nodes[i].end - nodes[i].start) >> 20);
		node_set_online(i);
 	}
 	memnode_shift = compute_hash_shift(nodes, numa_fake);
 	if (memnode_shift < 0) {
 		memnode_shift = 0;
 		printk(KERN_ERR "No NUMA hash function found. Emulation disabled.\n");
 		return -1;
 	}
 	for_each_online_node(i)
 		setup_node_bootmem(i, nodes[i].start, nodes[i].end);
 	numa_init_array();
 	return 0;
}
#endif

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{ 
	int i;

#ifdef CONFIG_NUMA_EMU
	if (numa_fake && !numa_emulation(start_pfn, end_pfn))
		return;
#endif

#ifdef CONFIG_ACPI_NUMA
	if (!numa_off && !acpi_scan_nodes((u64)start_pfn << PAGE_SHIFT,
					  (u64)end_pfn << PAGE_SHIFT))
		return;
#endif

	printk(KERN_INFO "%s\n",
	       numa_off ? "NUMA turned off" : "No NUMA configuration found");

	printk(KERN_INFO "Faking a node at %016"PRIx64"-%016"PRIx64"\n",
	       (u64)start_pfn << PAGE_SHIFT,
	       (u64)end_pfn << PAGE_SHIFT);
	/* setup dummy node covering all memory */ 
	memnode_shift = 63; 
	memnodemap[0] = 0;
	nodes_clear(node_online_map);
	node_set_online(0);
	for (i = 0; i < NR_CPUS; i++)
		numa_set_node(i, 0);
	node_to_cpumask[0] = cpumask_of_cpu(0);
	setup_node_bootmem(0, (u64)start_pfn << PAGE_SHIFT, (u64)end_pfn << PAGE_SHIFT);
}

__cpuinit void numa_add_cpu(int cpu)
{
	cpu_set(cpu, node_to_cpumask[cpu_to_node(cpu)]);
} 

void __cpuinit numa_set_node(int cpu, int node)
{
	cpu_to_node[cpu] = node;
}

/* [numa=off] */
static __init int numa_setup(char *opt) 
{ 
	if (!strncmp(opt,"off",3))
		numa_off = 1;
	if (!strncmp(opt,"on",2))
		numa_off = 0;
#ifdef CONFIG_NUMA_EMU
	if(!strncmp(opt, "fake=", 5)) {
		numa_off = 0;
		numa_fake = simple_strtoul(opt+5,NULL,0); ;
		if (numa_fake >= MAX_NUMNODES)
			numa_fake = MAX_NUMNODES;
	}
#endif
#ifdef CONFIG_ACPI_NUMA
	if (!strncmp(opt,"noacpi",6)) {
		numa_off = 0;
		acpi_numa = -1;
	}
#endif
	return 1;
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
	int i;
 	for (i = 0; i < NR_CPUS; i++) {
		u32 apicid = x86_cpu_to_apicid[i];
		if (apicid == BAD_APICID)
			continue;
		if (apicid_to_node[apicid] == NUMA_NO_NODE)
			continue;
		numa_set_node(i,apicid_to_node[apicid]);
	}
}

EXPORT_SYMBOL(cpu_to_node);
EXPORT_SYMBOL(node_to_cpumask);
EXPORT_SYMBOL(memnode_shift);
EXPORT_SYMBOL(memnodemap);
EXPORT_SYMBOL(node_data);

static void dump_numa(unsigned char key)
{
	s_time_t now = NOW();
	int i;
	struct domain *d;
	struct page_info *page;
	unsigned int page_num_node[MAX_NUMNODES];

	printk("'%c' pressed -> dumping numa info (now-0x%X:%08X)\n", key,
		  (u32)(now>>32), (u32)now);

	for_each_online_node(i) {
		paddr_t pa = (paddr_t)(NODE_DATA(i)->node_start_pfn + 1)<< PAGE_SHIFT;
		printk("idx%d -> NODE%d start->%lu size->%lu\n",
			  i, NODE_DATA(i)->node_id,
			  NODE_DATA(i)->node_start_pfn,
			  NODE_DATA(i)->node_spanned_pages);
		/* sanity check phys_to_nid() */
		printk("phys_to_nid(%"PRIpaddr") -> %d should be %d\n", pa, phys_to_nid(pa),
			  NODE_DATA(i)->node_id);
	}
	for_each_online_cpu(i)
		printk("CPU%d -> NODE%d\n", i, cpu_to_node[i]);

	rcu_read_lock(&domlist_read_lock);

	printk("Memory location of each domain:\n");
	for_each_domain(d)
	{
		printk("Domain %u (total: %u):\n", d->domain_id, d->tot_pages);

		for_each_online_node(i)
			page_num_node[i] = 0;

		page_list_for_each(page, &d->page_list)
		{
			i = phys_to_nid((paddr_t)page_to_mfn(page) << PAGE_SHIFT);
			page_num_node[i]++;
		}

		for_each_online_node(i)
			printk("    Node %u: %u\n", i, page_num_node[i]);
	}

	rcu_read_unlock(&domlist_read_lock);
}

static struct keyhandler dump_numa_keyhandler = {
	.diagnostic = 1,
	.u.fn = dump_numa,
	.desc = "dump numa info"
};

static __init int register_numa_trigger(void)
{
	register_keyhandler('u', &dump_numa_keyhandler);
	return 0;
}
__initcall(register_numa_trigger);

