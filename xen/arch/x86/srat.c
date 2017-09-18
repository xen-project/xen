/*
 * ACPI 3.0 based NUMA setup
 * Copyright 2004 Andi Kleen, SuSE Labs.
 *
 * Reads the ACPI SRAT table to figure out what memory belongs to which CPUs.
 *
 * Called from acpi_numa_init while reading the SRAT and SLIT tables.
 * Assumes all memory regions belonging to a single proximity domain
 * are in one chunk. Holes between them will be included in the node.
 * 
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/inttypes.h>
#include <xen/nodemask.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <xen/pfn.h>
#include <asm/e820.h>
#include <asm/page.h>

static struct acpi_table_slit *__read_mostly acpi_slit;

static nodemask_t memory_nodes_parsed __initdata;
static nodemask_t processor_nodes_parsed __initdata;
static struct node nodes[MAX_NUMNODES] __initdata;

struct pxm2node {
	unsigned pxm;
	nodeid_t node;
};
static struct pxm2node __read_mostly pxm2node[MAX_NUMNODES] =
	{ [0 ... MAX_NUMNODES - 1] = {.node = NUMA_NO_NODE} };

static unsigned node_to_pxm(nodeid_t n);

static int num_node_memblks;
static struct node node_memblk_range[NR_NODE_MEMBLKS];
static nodeid_t memblk_nodeid[NR_NODE_MEMBLKS];
static __initdata DECLARE_BITMAP(memblk_hotplug, NR_NODE_MEMBLKS);

static inline bool node_found(unsigned idx, unsigned pxm)
{
	return ((pxm2node[idx].pxm == pxm) &&
		(pxm2node[idx].node != NUMA_NO_NODE));
}

nodeid_t pxm_to_node(unsigned pxm)
{
	unsigned i;

	if ((pxm < ARRAY_SIZE(pxm2node)) && node_found(pxm, pxm))
		return pxm2node[pxm].node;

	for (i = 0; i < ARRAY_SIZE(pxm2node); i++)
		if (node_found(i, pxm))
			return pxm2node[i].node;

	return NUMA_NO_NODE;
}

nodeid_t setup_node(unsigned pxm)
{
	nodeid_t node;
	unsigned idx;
	static bool warned;
	static unsigned nodes_found;

	BUILD_BUG_ON(MAX_NUMNODES >= NUMA_NO_NODE);

	if (pxm < ARRAY_SIZE(pxm2node)) {
		if (node_found(pxm, pxm))
			return pxm2node[pxm].node;

		/* Try to maintain indexing of pxm2node by pxm */
		if (pxm2node[pxm].node == NUMA_NO_NODE) {
			idx = pxm;
			goto finish;
		}
	}

	for (idx = 0; idx < ARRAY_SIZE(pxm2node); idx++)
		if (pxm2node[idx].node == NUMA_NO_NODE)
			goto finish;

	if (!warned) {
		printk(KERN_WARNING "SRAT: Too many proximity domains (%#x)\n",
		       pxm);
		warned = true;
	}

	return NUMA_NO_NODE;

 finish:
	node = nodes_found++;
	if (node >= MAX_NUMNODES)
		return NUMA_NO_NODE;
	pxm2node[idx].pxm = pxm;
	pxm2node[idx].node = node;

	return node;
}

int valid_numa_range(u64 start, u64 end, nodeid_t node)
{
	int i;

	for (i = 0; i < num_node_memblks; i++) {
		struct node *nd = &node_memblk_range[i];

		if (nd->start <= start && nd->end > end &&
			memblk_nodeid[i] == node )
			return 1;
	}

	return 0;
}

static __init int conflicting_memblks(u64 start, u64 end)
{
	int i;

	for (i = 0; i < num_node_memblks; i++) {
		struct node *nd = &node_memblk_range[i];
		if (nd->start == nd->end)
			continue;
		if (nd->end > start && nd->start < end)
			return i;
		if (nd->end == end && nd->start == start)
			return i;
	}
	return -1;
}

static __init void cutoff_node(int i, u64 start, u64 end)
{
	struct node *nd = &nodes[i];
	if (nd->start < start) {
		nd->start = start;
		if (nd->end < nd->start)
			nd->start = nd->end;
	}
	if (nd->end > end) {
		nd->end = end;
		if (nd->start > nd->end)
			nd->start = nd->end;
	}
}

static __init void bad_srat(void)
{
	int i;
	printk(KERN_ERR "SRAT: SRAT not used.\n");
	acpi_numa = -1;
	for (i = 0; i < MAX_LOCAL_APIC; i++)
		apicid_to_node[i] = NUMA_NO_NODE;
	for (i = 0; i < ARRAY_SIZE(pxm2node); i++)
		pxm2node[i].node = NUMA_NO_NODE;
	mem_hotplug = 0;
}

/*
 * A lot of BIOS fill in 10 (= no distance) everywhere. This messes
 * up the NUMA heuristics which wants the local node to have a smaller
 * distance than the others.
 * Do some quick checks here and only use the SLIT if it passes.
 */
static __init int slit_valid(struct acpi_table_slit *slit)
{
	int i, j;
	int d = slit->locality_count;
	for (i = 0; i < d; i++) {
		for (j = 0; j < d; j++)  {
			u8 val = slit->entry[d*i + j];
			if (i == j) {
				if (val != 10)
					return 0;
			} else if (val <= 10)
				return 0;
		}
	}
	return 1;
}

/* Callback for SLIT parsing */
void __init acpi_numa_slit_init(struct acpi_table_slit *slit)
{
	mfn_t mfn;

	if (!slit_valid(slit)) {
		printk(KERN_INFO "ACPI: SLIT table looks invalid. "
		       "Not used.\n");
		return;
	}
	mfn = alloc_boot_pages(PFN_UP(slit->header.length), 1);
	acpi_slit = mfn_to_virt(mfn_x(mfn));
	memcpy(acpi_slit, slit, slit->header.length);
}

/* Callback for Proximity Domain -> x2APIC mapping */
void __init
acpi_numa_x2apic_affinity_init(const struct acpi_srat_x2apic_cpu_affinity *pa)
{
	unsigned pxm;
	nodeid_t node;

	if (srat_disabled())
		return;
	if (pa->header.length < sizeof(struct acpi_srat_x2apic_cpu_affinity)) {
		bad_srat();
		return;
	}
	if (!(pa->flags & ACPI_SRAT_CPU_ENABLED))
		return;
	if (pa->apic_id >= MAX_LOCAL_APIC) {
		printk(KERN_INFO "SRAT: APIC %08x ignored\n", pa->apic_id);
		return;
	}

	pxm = pa->proximity_domain;
	node = setup_node(pxm);
	if (node == NUMA_NO_NODE) {
		bad_srat();
		return;
	}

	apicid_to_node[pa->apic_id] = node;
	node_set(node, processor_nodes_parsed);
	acpi_numa = 1;
	printk(KERN_INFO "SRAT: PXM %u -> APIC %08x -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Callback for Proximity Domain -> LAPIC mapping */
void __init
acpi_numa_processor_affinity_init(const struct acpi_srat_cpu_affinity *pa)
{
	unsigned pxm;
	nodeid_t node;

	if (srat_disabled())
		return;
	if (pa->header.length != sizeof(struct acpi_srat_cpu_affinity)) {
		bad_srat();
		return;
	}
	if (!(pa->flags & ACPI_SRAT_CPU_ENABLED))
		return;
	pxm = pa->proximity_domain_lo;
	if (srat_rev >= 2) {
		pxm |= pa->proximity_domain_hi[0] << 8;
		pxm |= pa->proximity_domain_hi[1] << 16;
		pxm |= pa->proximity_domain_hi[2] << 24;
	}
	node = setup_node(pxm);
	if (node == NUMA_NO_NODE) {
		bad_srat();
		return;
	}
	apicid_to_node[pa->apic_id] = node;
	node_set(node, processor_nodes_parsed);
	acpi_numa = 1;
	printk(KERN_INFO "SRAT: PXM %u -> APIC %02x -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Callback for parsing of the Proximity Domain <-> Memory Area mappings */
void __init
acpi_numa_memory_affinity_init(const struct acpi_srat_mem_affinity *ma)
{
	u64 start, end;
	unsigned pxm;
	nodeid_t node;
	int i;

	if (srat_disabled())
		return;
	if (ma->header.length != sizeof(struct acpi_srat_mem_affinity)) {
		bad_srat();
		return;
	}
	if (!(ma->flags & ACPI_SRAT_MEM_ENABLED))
		return;

	if (num_node_memblks >= NR_NODE_MEMBLKS)
	{
		dprintk(XENLOG_WARNING,
                "Too many numa entry, try bigger NR_NODE_MEMBLKS \n");
		bad_srat();
		return;
	}

	start = ma->base_address;
	end = start + ma->length;
	pxm = ma->proximity_domain;
	if (srat_rev < 2)
		pxm &= 0xff;
	node = setup_node(pxm);
	if (node == NUMA_NO_NODE) {
		bad_srat();
		return;
	}
	/* It is fine to add this area to the nodes data it will be used later*/
	i = conflicting_memblks(start, end);
	if (i < 0)
		/* everything fine */;
	else if (memblk_nodeid[i] == node) {
		bool mismatch = !(ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) !=
		                !test_bit(i, memblk_hotplug);

		printk("%sSRAT: PXM %u (%"PRIx64"-%"PRIx64") overlaps with itself (%"PRIx64"-%"PRIx64")\n",
		       mismatch ? KERN_ERR : KERN_WARNING, pxm, start, end,
		       node_memblk_range[i].start, node_memblk_range[i].end);
		if (mismatch) {
			bad_srat();
			return;
		}
	} else {
		printk(KERN_ERR
		       "SRAT: PXM %u (%"PRIx64"-%"PRIx64") overlaps with PXM %u (%"PRIx64"-%"PRIx64")\n",
		       pxm, start, end, node_to_pxm(memblk_nodeid[i]),
		       node_memblk_range[i].start, node_memblk_range[i].end);
		bad_srat();
		return;
	}
	if (!(ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE)) {
		struct node *nd = &nodes[node];

		if (!node_test_and_set(node, memory_nodes_parsed)) {
			nd->start = start;
			nd->end = end;
		} else {
			if (start < nd->start)
				nd->start = start;
			if (nd->end < end)
				nd->end = end;
		}
	}
	printk(KERN_INFO "SRAT: Node %u PXM %u %"PRIx64"-%"PRIx64"%s\n",
	       node, pxm, start, end,
	       ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE ? " (hotplug)" : "");

	node_memblk_range[num_node_memblks].start = start;
	node_memblk_range[num_node_memblks].end = end;
	memblk_nodeid[num_node_memblks] = node;
	if (ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) {
		__set_bit(num_node_memblks, memblk_hotplug);
		if (end > mem_hotplug)
			mem_hotplug = end;
	}
	num_node_memblks++;
}

/* Sanity check to catch more bad SRATs (they are amazingly common).
   Make sure the PXMs cover all memory. */
static int __init nodes_cover_memory(void)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		int j, found;
		unsigned long long start, end;

		if (e820.map[i].type != E820_RAM) {
			continue;
		}

		start = e820.map[i].addr;
		end = e820.map[i].addr + e820.map[i].size - 1;

		do {
			found = 0;
			for_each_node_mask(j, memory_nodes_parsed)
				if (start < nodes[j].end
				    && end > nodes[j].start) {
					if (start >= nodes[j].start) {
						start = nodes[j].end;
						found = 1;
					}
					if (end <= nodes[j].end) {
						end = nodes[j].start;
						found = 1;
					}
				}
		} while (found && start < end);

		if (start < end) {
			printk(KERN_ERR "SRAT: No PXM for e820 range: "
				"%016Lx - %016Lx\n", start, end);
			return 0;
		}
	}
	return 1;
}

void __init acpi_numa_arch_fixup(void) {}

static u64 __initdata srat_region_mask;

static int __init srat_parse_region(struct acpi_subtable_header *header,
				    const unsigned long end)
{
	struct acpi_srat_mem_affinity *ma;

	if (!header)
		return -EINVAL;

	ma = container_of(header, struct acpi_srat_mem_affinity, header);

	if (!ma->length ||
	    !(ma->flags & ACPI_SRAT_MEM_ENABLED) ||
	    (ma->flags & ACPI_SRAT_MEM_NON_VOLATILE))
		return 0;

	if (numa_off)
		printk(KERN_INFO "SRAT: %013"PRIx64"-%013"PRIx64"\n",
		       ma->base_address, ma->base_address + ma->length - 1);

	srat_region_mask |= ma->base_address |
			    pdx_region_mask(ma->base_address, ma->length);

	return 0;
}

void __init srat_parse_regions(u64 addr)
{
	u64 mask;
	unsigned int i;

	if (acpi_disabled || acpi_numa < 0 ||
	    acpi_table_parse(ACPI_SIG_SRAT, acpi_parse_srat))
		return;

	srat_region_mask = pdx_init_mask(addr);
	acpi_table_parse_srat(ACPI_SRAT_TYPE_MEMORY_AFFINITY,
			      srat_parse_region, 0);

	for (mask = srat_region_mask, i = 0; mask && i < e820.nr_map; i++) {
		if (e820.map[i].type != E820_RAM)
			continue;

		if (~mask & pdx_region_mask(e820.map[i].addr, e820.map[i].size))
			mask = 0;
	}

	pfn_pdx_hole_setup(mask >> PAGE_SHIFT);
}

/* Use the information discovered above to actually set up the nodes. */
int __init acpi_scan_nodes(u64 start, u64 end)
{
	int i;
	nodemask_t all_nodes_parsed;

	/* First clean up the node list */
	for (i = 0; i < MAX_NUMNODES; i++)
		cutoff_node(i, start, end);

	if (acpi_numa <= 0)
		return -1;

	if (!nodes_cover_memory()) {
		bad_srat();
		return -1;
	}

	memnode_shift = compute_hash_shift(node_memblk_range, num_node_memblks,
				memblk_nodeid);

	if (memnode_shift < 0) {
		printk(KERN_ERR
		     "SRAT: No NUMA node hash function found. Contact maintainer\n");
		bad_srat();
		return -1;
	}

	nodes_or(all_nodes_parsed, memory_nodes_parsed, processor_nodes_parsed);

	/* Finally register nodes */
	for_each_node_mask(i, all_nodes_parsed)
	{
		u64 size = nodes[i].end - nodes[i].start;
		if ( size == 0 )
			printk(KERN_WARNING "SRAT: Node %u has no memory. "
			       "BIOS Bug or mis-configured hardware?\n", i);

		setup_node_bootmem(i, nodes[i].start, nodes[i].end);
	}
	for (i = 0; i < nr_cpu_ids; i++) {
		if (cpu_to_node[i] == NUMA_NO_NODE)
			continue;
		if (!node_isset(cpu_to_node[i], processor_nodes_parsed))
			numa_set_node(i, NUMA_NO_NODE);
	}
	numa_init_array();
	return 0;
}

static unsigned node_to_pxm(nodeid_t n)
{
	unsigned i;

	if ((n < ARRAY_SIZE(pxm2node)) && (pxm2node[n].node == n))
		return pxm2node[n].pxm;
	for (i = 0; i < ARRAY_SIZE(pxm2node); i++)
		if (pxm2node[i].node == n)
			return pxm2node[i].pxm;
	return 0;
}

u8 __node_distance(nodeid_t a, nodeid_t b)
{
	unsigned index;
	u8 slit_val;

	if (!acpi_slit)
		return a == b ? 10 : 20;
	index = acpi_slit->locality_count * node_to_pxm(a);
	slit_val = acpi_slit->entry[index + node_to_pxm(b)];

	/* ACPI defines 0xff as an unreachable node and 0-9 are undefined */
	if ((slit_val == 0xff) || (slit_val <= 9))
		return NUMA_NO_DISTANCE;
	else
		return slit_val;
}

EXPORT_SYMBOL(__node_distance);
