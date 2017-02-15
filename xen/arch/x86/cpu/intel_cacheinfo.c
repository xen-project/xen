/*
 *      Routines to indentify caches on Intel CPU.
 *
 *      Changes:
 *      Venkatesh Pallipadi	: Adding cache identification through cpuid(4)
 *		Ashok Raj <ashok.raj@intel.com>: Work with CPU hotplug infrastructure.
 *	Andi Kleen / Andreas Herrmann	: CPUID4 emulation on AMD.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <asm/processor.h>

#define LVL_1_INST	1
#define LVL_1_DATA	2
#define LVL_2		3
#define LVL_3		4
#define LVL_TRACE	5

struct _cache_table
{
	unsigned char descriptor;
	char cache_type;
	short size;
};

/* all the cache descriptor types we care about (no TLB or trace cache entries) */
static const struct _cache_table cache_table[] =
{
	{ 0x06, LVL_1_INST, 8 },	/* 4-way set assoc, 32 byte line size */
	{ 0x08, LVL_1_INST, 16 },	/* 4-way set assoc, 32 byte line size */
	{ 0x0a, LVL_1_DATA, 8 },	/* 2 way set assoc, 32 byte line size */
	{ 0x0c, LVL_1_DATA, 16 },	/* 4-way set assoc, 32 byte line size */
	{ 0x22, LVL_3,      512 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x23, LVL_3,      1024 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x25, LVL_3,      2048 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x29, LVL_3,      4096 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x2c, LVL_1_DATA, 32 },	/* 8-way set assoc, 64 byte line size */
	{ 0x30, LVL_1_INST, 32 },	/* 8-way set assoc, 64 byte line size */
	{ 0x39, LVL_2,      128 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x3a, LVL_2,      192 },	/* 6-way set assoc, sectored cache, 64 byte line size */
	{ 0x3b, LVL_2,      128 },	/* 2-way set assoc, sectored cache, 64 byte line size */
	{ 0x3c, LVL_2,      256 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x3d, LVL_2,      384 },	/* 6-way set assoc, sectored cache, 64 byte line size */
	{ 0x3e, LVL_2,      512 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x41, LVL_2,      128 },	/* 4-way set assoc, 32 byte line size */
	{ 0x42, LVL_2,      256 },	/* 4-way set assoc, 32 byte line size */
	{ 0x43, LVL_2,      512 },	/* 4-way set assoc, 32 byte line size */
	{ 0x44, LVL_2,      1024 },	/* 4-way set assoc, 32 byte line size */
	{ 0x45, LVL_2,      2048 },	/* 4-way set assoc, 32 byte line size */
	{ 0x46, LVL_3,      4096 },	/* 4-way set assoc, 64 byte line size */
	{ 0x47, LVL_3,      8192 },	/* 8-way set assoc, 64 byte line size */
	{ 0x49, LVL_3,      4096 },	/* 16-way set assoc, 64 byte line size */
	{ 0x4a, LVL_3,      6144 },	/* 12-way set assoc, 64 byte line size */
	{ 0x4b, LVL_3,      8192 },	/* 16-way set assoc, 64 byte line size */
	{ 0x4c, LVL_3,     12288 },	/* 12-way set assoc, 64 byte line size */
	{ 0x4d, LVL_3,     16384 },	/* 16-way set assoc, 64 byte line size */
	{ 0x60, LVL_1_DATA, 16 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x66, LVL_1_DATA, 8 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x67, LVL_1_DATA, 16 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x68, LVL_1_DATA, 32 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x70, LVL_TRACE,  12 },	/* 8-way set assoc */
	{ 0x71, LVL_TRACE,  16 },	/* 8-way set assoc */
	{ 0x72, LVL_TRACE,  32 },	/* 8-way set assoc */
	{ 0x73, LVL_TRACE,  64 },	/* 8-way set assoc */
	{ 0x78, LVL_2,    1024 },	/* 4-way set assoc, 64 byte line size */
	{ 0x79, LVL_2,     128 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7a, LVL_2,     256 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7b, LVL_2,     512 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7c, LVL_2,    1024 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7d, LVL_2,    2048 },	/* 8-way set assoc, 64 byte line size */
	{ 0x7f, LVL_2,     512 },	/* 2-way set assoc, 64 byte line size */
	{ 0x82, LVL_2,     256 },	/* 8-way set assoc, 32 byte line size */
	{ 0x83, LVL_2,     512 },	/* 8-way set assoc, 32 byte line size */
	{ 0x84, LVL_2,    1024 },	/* 8-way set assoc, 32 byte line size */
	{ 0x85, LVL_2,    2048 },	/* 8-way set assoc, 32 byte line size */
	{ 0x86, LVL_2,     512 },	/* 4-way set assoc, 64 byte line size */
	{ 0x87, LVL_2,    1024 },	/* 8-way set assoc, 64 byte line size */
	{ 0x00, 0, 0}
};

unsigned short			num_cache_leaves;

int cpuid4_cache_lookup(int index, struct cpuid4_info *this_leaf)
{
	union _cpuid4_leaf_eax 	eax;
	union _cpuid4_leaf_ebx 	ebx;
	union _cpuid4_leaf_ecx 	ecx;
	unsigned		edx;

        cpuid_count(4, index, &eax.full, &ebx.full, &ecx.full,  &edx);
	if (eax.split.type == CACHE_TYPE_NULL)
		return -EIO; /* better error ? */

	this_leaf->eax = eax;
	this_leaf->ebx = ebx;
	this_leaf->ecx = ecx;
	this_leaf->size = (ecx.split.number_of_sets + 1) *
		(ebx.split.coherency_line_size + 1) *
		(ebx.split.physical_line_partition + 1) *
		(ebx.split.ways_of_associativity + 1);
	return 0;
}

static int find_num_cache_leaves(void)
{
	unsigned int		eax, ebx, ecx, edx;
	union _cpuid4_leaf_eax	cache_eax;
	int 			i = -1;

	do {
		++i;
		/* Do cpuid(4) loop to find out num_cache_leaves */
		cpuid_count(4, i, &eax, &ebx, &ecx, &edx);
		cache_eax.full = eax;
	} while (cache_eax.split.type != CACHE_TYPE_NULL);
	return i;
}

unsigned int init_intel_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int trace = 0, l1i = 0, l1d = 0, l2 = 0, l3 = 0; /* Cache sizes */
	unsigned int new_l1d = 0, new_l1i = 0; /* Cache sizes from cpuid(4) */
	unsigned int new_l2 = 0, new_l3 = 0, i; /* Cache sizes from cpuid(4) */
	unsigned int l2_id = 0, l3_id = 0, num_threads_sharing, index_msb;

	if (c->cpuid_level > 3) {
		static int is_initialized;

		if (is_initialized == 0) {
			/* Init num_cache_leaves from boot CPU */
			num_cache_leaves = find_num_cache_leaves();
			is_initialized++;
		}

		/*
		 * Whenever possible use cpuid(4), deterministic cache
		 * parameters cpuid leaf to find the cache details
		 */
		for (i = 0; i < num_cache_leaves; i++) {
			struct cpuid4_info this_leaf;

			int retval;

			retval = cpuid4_cache_lookup(i, &this_leaf);
			if (retval >= 0) {
				switch(this_leaf.eax.split.level) {
				    case 1:
					if (this_leaf.eax.split.type ==
							CACHE_TYPE_DATA)
						new_l1d = this_leaf.size/1024;
					else if (this_leaf.eax.split.type ==
							CACHE_TYPE_INST)
						new_l1i = this_leaf.size/1024;
					break;
				    case 2:
					new_l2 = this_leaf.size/1024;
					num_threads_sharing = 1 + this_leaf.eax.split.num_threads_sharing;
					index_msb = get_count_order(num_threads_sharing);
					l2_id = c->apicid >> index_msb;
					break;
				    case 3:
					new_l3 = this_leaf.size/1024;
					num_threads_sharing = 1 + this_leaf.eax.split.num_threads_sharing;
					index_msb = get_count_order(num_threads_sharing);
					l3_id = c->apicid >> index_msb;
					break;
				    default:
					break;
				}
			}
		}
	}
	/*
	 * Don't use cpuid2 if cpuid4 is supported. For P4, we use cpuid2 for
	 * trace cache
	 */
	if ((num_cache_leaves == 0 || c->x86 == 15) && c->cpuid_level > 1) {
		/* supports eax=2  call */
		int i, j, n;
		int regs[4];
		unsigned char *dp = (unsigned char *)regs;
		int only_trace = 0;

		if (num_cache_leaves != 0 && c->x86 == 15)
			only_trace = 1;

		/* Number of times to iterate */
		n = cpuid_eax(2) & 0xFF;

		for ( i = 0 ; i < n ; i++ ) {
			cpuid(2, &regs[0], &regs[1], &regs[2], &regs[3]);

			/* If bit 31 is set, this is an unknown format */
			for ( j = 0 ; j < 3 ; j++ ) {
				if ( regs[j] < 0 ) regs[j] = 0;
			}

			/* Byte 0 is level count, not a descriptor */
			for ( j = 1 ; j < 16 ; j++ ) {
				unsigned char des = dp[j];
				unsigned char k = 0;

				/* look up this descriptor in the table */
				while (cache_table[k].descriptor != 0)
				{
					if (cache_table[k].descriptor == des) {
						if (only_trace && cache_table[k].cache_type != LVL_TRACE)
							break;
						switch (cache_table[k].cache_type) {
						case LVL_1_INST:
							l1i += cache_table[k].size;
							break;
						case LVL_1_DATA:
							l1d += cache_table[k].size;
							break;
						case LVL_2:
							l2 += cache_table[k].size;
							break;
						case LVL_3:
							l3 += cache_table[k].size;
							break;
						case LVL_TRACE:
							trace += cache_table[k].size;
							break;
						}

						break;
					}

					k++;
				}
			}
		}
	}

	if (new_l1d)
		l1d = new_l1d;

	if (new_l1i)
		l1i = new_l1i;

	if (new_l2) {
		l2 = new_l2;
	}

	if (new_l3) {
		l3 = new_l3;
	}

	if (opt_cpu_info) {
		if (trace)
			printk("CPU: Trace cache: %dK uops", trace);
		else if ( l1i )
			printk("CPU: L1 I cache: %dK", l1i);

		if (l1d)
			printk(", L1 D cache: %dK\n", l1d);
		else
			printk("\n");

		if (l2)
			printk("CPU: L2 cache: %dK\n", l2);

		if (l3)
			printk("CPU: L3 cache: %dK\n", l3);
	}

	c->x86_cache_size = l3 ? l3 : (l2 ? l2 : (l1i+l1d));

	return l2;
}
