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
#include <asm/e820.h>
#include <asm/page.h>

static struct acpi_table_slit *__read_mostly acpi_slit;

static nodemask_t nodes_parsed __initdata;
static nodemask_t nodes_found __initdata;
static struct node nodes[MAX_NUMNODES] __initdata;
static u8 __read_mostly pxm2node[256] = { [0 ... 255] = 0xff };

/* Too small nodes confuse the VM badly. Usually they result
   from BIOS bugs. */
#define NODE_MIN_SIZE (4*1024*1024)

static int node_to_pxm(int n);

int pxm_to_node(int pxm)
{
	if ((unsigned)pxm >= 256)
		return -1;
	/* Extend 0xff to (int)-1 */
	return (signed char)pxm2node[pxm];
}

__devinit int setup_node(int pxm)
{
	unsigned node = pxm2node[pxm];
	if (node == 0xff) {
		if (nodes_weight(nodes_found) >= MAX_NUMNODES)
			return -1;
		node = first_unset_node(nodes_found); 
		node_set(node, nodes_found);
		pxm2node[pxm] = node;
	}
	return pxm2node[pxm];
}

static __init int conflicting_nodes(u64 start, u64 end)
{
	int i;
	for_each_node_mask(i, nodes_parsed) {
		struct node *nd = &nodes[i];
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
	if (!slit_valid(slit)) {
		printk(KERN_INFO "ACPI: SLIT table looks invalid. Not used.\n");
		return;
	}
	acpi_slit = slit;
}

/* Callback for Proximity Domain -> LAPIC mapping */
void __init
acpi_numa_processor_affinity_init(struct acpi_srat_cpu_affinity *pa)
{
	int pxm, node;
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
	if (node < 0) {
		printk(KERN_ERR "SRAT: Too many proximity domains %x\n", pxm);
		bad_srat();
		return;
	}
	apicid_to_node[pa->apic_id] = node;
	acpi_numa = 1;
	printk(KERN_INFO "SRAT: PXM %u -> APIC %u -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Callback for parsing of the Proximity Domain <-> Memory Area mappings */
void __init
acpi_numa_memory_affinity_init(struct acpi_srat_mem_affinity *ma)
{
	struct node *nd;
	u64 start, end;
	int node, pxm;
	int i;

	if (srat_disabled())
		return;
	if (ma->header.length != sizeof(struct acpi_srat_mem_affinity)) {
		bad_srat();
		return;
	}
	if (!(ma->flags & ACPI_SRAT_MEM_ENABLED))
		return;
	start = ma->base_address;
	end = start + ma->length;
	pxm = ma->proximity_domain;
	if (srat_rev < 2)
		pxm &= 0xff;
	node = setup_node(pxm);
	if (node < 0) {
		printk(KERN_ERR "SRAT: Too many proximity domains.\n");
		bad_srat();
		return;
	}
	if (ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) {
		if (page_is_ram_type(paddr_to_pfn(start), RAM_TYPE_CONVENTIONAL))
			printk(KERN_INFO "SRAT: hot-pluggable zone found %"PRIx64" - %"PRIx64" \n",
				start, end);
		else {
			/* TODO: This range contains no existing memory yet,
			 * and shouldn't be included in nodes' [start, end]. It
			 * will be covered with physical memory hotplug support
			 * in future.
			 */
			printk(KERN_INFO "SRAT: future hotplug zone found %"PRIx64" - %"PRIx64" \n",
				start, end);
			return;
		}
	}
	i = conflicting_nodes(start, end);
	if (i == node) {
		printk(KERN_WARNING
		"SRAT: Warning: PXM %d (%"PRIx64"-%"PRIx64") overlaps with itself (%"
		PRIx64"-%"PRIx64")\n", pxm, start, end, nodes[i].start, nodes[i].end);
	} else if (i >= 0) {
		printk(KERN_ERR
		       "SRAT: PXM %d (%"PRIx64"-%"PRIx64") overlaps with PXM %d (%"
		       PRIx64"-%"PRIx64")\n", pxm, start, end, node_to_pxm(i),
			   nodes[i].start, nodes[i].end);
		bad_srat();
		return;
	}
	nd = &nodes[node];
	if (!node_test_and_set(node, nodes_parsed)) {
		nd->start = start;
		nd->end = end;
	} else {
		if (start < nd->start)
			nd->start = start;
		if (nd->end < end)
			nd->end = end;
	}
	printk(KERN_INFO "SRAT: Node %u PXM %u %"PRIx64"-%"PRIx64"\n", node, pxm,
	       nd->start, nd->end);
}

/* Sanity check to catch more bad SRATs (they are amazingly common).
   Make sure the PXMs cover all memory. */
static int nodes_cover_memory(void)
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
			for_each_node_mask(j, nodes_parsed)
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

static void unparse_node(int node)
{
	int i;
	node_clear(node, nodes_parsed);
	for (i = 0; i < MAX_LOCAL_APIC; i++) {
		if (apicid_to_node[i] == node)
			apicid_to_node[i] = NUMA_NO_NODE;
	}
}

void __init acpi_numa_arch_fixup(void) {}

#ifdef __x86_64__

static u64 __initdata srat_region_mask;

static u64 __init fill_mask(u64 mask)
{
	while (mask & (mask + 1))
		mask |= mask + 1;
	return mask;
}

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
			    fill_mask(ma->base_address ^
				      (ma->base_address + ma->length - 1));

	return 0;
}

void __init srat_parse_regions(u64 addr)
{
	u64 mask;
	unsigned int i;

	if (acpi_disabled || acpi_numa < 0 ||
	    acpi_table_parse(ACPI_SIG_SRAT, acpi_parse_srat))
		return;

	srat_region_mask = fill_mask(addr - 1);
	acpi_table_parse_srat(ACPI_SRAT_MEMORY_AFFINITY, srat_parse_region, 0);

	for (mask = srat_region_mask, i = 0; mask && i < e820.nr_map; i++) {
		if (e820.map[i].type != E820_RAM)
			continue;

		if (~mask &
		    fill_mask(e820.map[i].addr ^
			      (e820.map[i].addr + e820.map[i].size - 1)))
			mask = 0;
	}

	pfn_pdx_hole_setup(mask >> PAGE_SHIFT);
}

#endif /* __x86_64__ */

/* Use the information discovered above to actually set up the nodes. */
int __init acpi_scan_nodes(u64 start, u64 end)
{
	int i;

	/* First clean up the node list */
	for (i = 0; i < MAX_NUMNODES; i++) {
		cutoff_node(i, start, end);
		if ((nodes[i].end - nodes[i].start) < NODE_MIN_SIZE)
			unparse_node(i);
	}

	if (acpi_numa <= 0)
		return -1;

	if (!nodes_cover_memory()) {
		bad_srat();
		return -1;
	}

	memnode_shift = compute_hash_shift(nodes, MAX_NUMNODES);
	if (memnode_shift < 0) {
		printk(KERN_ERR
		     "SRAT: No NUMA node hash function found. Contact maintainer\n");
		bad_srat();
		return -1;
	}

	/* Finally register nodes */
	for_each_node_mask(i, nodes_parsed)
		setup_node_bootmem(i, nodes[i].start, nodes[i].end);
	for (i = 0; i < NR_CPUS; i++) { 
		if (cpu_to_node[i] == NUMA_NO_NODE)
			continue;
		if (!node_isset(cpu_to_node[i], nodes_parsed))
			numa_set_node(i, NUMA_NO_NODE);
	}
	numa_init_array();
	return 0;
}

static int node_to_pxm(int n)
{
       int i;
       if (pxm2node[n] == n)
               return n;
       for (i = 0; i < 256; i++)
               if (pxm2node[i] == n)
                       return i;
       return 0;
}

int __node_distance(int a, int b)
{
	int index;

	if (!acpi_slit)
		return a == b ? 10 : 20;
	index = acpi_slit->locality_count * node_to_pxm(a);
	return acpi_slit->entry[index + node_to_pxm(b)];
}

EXPORT_SYMBOL(__node_distance);
