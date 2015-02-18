#ifndef __XEN_CPUMASK_H
#define __XEN_CPUMASK_H

/*
 * Cpumasks provide a bitmap suitable for representing the
 * set of CPU's in a system, one bit position per CPU number.
 *
 * See detailed comments in the file xen/bitmap.h describing the
 * data type on which these cpumasks are based.
 *
 * For details of cpumask_scnprintf() and cpulist_scnprintf(),
 * see bitmap_scnprintf() and bitmap_scnlistprintf() in lib/bitmap.c.
 *
 * The available cpumask operations are:
 *
 * void cpumask_set_cpu(cpu, mask)	turn on bit 'cpu' in mask
 * void cpumask_clear_cpu(cpu, mask)	turn off bit 'cpu' in mask
 * void cpumask_setall(mask)		set all bits
 * void cpumask_clear(mask)		clear all bits
 * int cpumask_test_cpu(cpu, mask)	true iff bit 'cpu' set in mask
 * int cpumask_test_and_set_cpu(cpu, mask) test and set bit 'cpu' in mask
 * int cpumask_test_and_clear_cpu(cpu, mask) test and clear bit 'cpu' in mask
 *
 * void cpumask_and(dst, src1, src2)	dst = src1 & src2  [intersection]
 * void cpumask_or(dst, src1, src2)	dst = src1 | src2  [union]
 * void cpumask_xor(dst, src1, src2)	dst = src1 ^ src2
 * void cpumask_andnot(dst, src1, src2)	dst = src1 & ~src2
 * void cpumask_complement(dst, src)	dst = ~src
 *
 * int cpumask_equal(mask1, mask2)	Does mask1 == mask2?
 * int cpumask_intersects(mask1, mask2)	Do mask1 and mask2 intersect?
 * int cpumask_subset(mask1, mask2)	Is mask1 a subset of mask2?
 * int cpumask_empty(mask)		Is mask empty (no bits sets)?
 * int cpumask_full(mask)		Is mask full (all bits sets)?
 * int cpumask_weight(mask)		Hamming weigh - number of set bits
 *
 * void cpumask_shift_right(dst, src, n) Shift right
 * void cpumask_shift_left(dst, src, n)	Shift left
 *
 * int cpumask_first(mask)		Number lowest set bit, or NR_CPUS
 * int cpumask_next(cpu, mask)		Next cpu past 'cpu', or NR_CPUS
 * int cpumask_last(mask)		Number highest set bit, or NR_CPUS
 * int cpumask_any(mask)		Any cpu in mask, or NR_CPUS
 * int cpumask_cycle(cpu, mask)		Next cpu cycling from 'cpu', or NR_CPUS
 *
 * const cpumask_t *cpumask_of(cpu)	Return cpumask with bit 'cpu' set
 * unsigned long *cpumask_bits(mask)	Array of unsigned long's in mask
 *
 * int cpumask_scnprintf(buf, len, mask) Format cpumask for printing
 * int cpulist_scnprintf(buf, len, mask) Format cpumask as list for printing
 *
 * for_each_cpu(cpu, mask)		for-loop cpu over mask
 *
 * int num_online_cpus()		Number of online CPUs
 * int num_possible_cpus()		Number of all possible CPUs
 * int num_present_cpus()		Number of present CPUs
 *
 * int cpu_online(cpu)			Is some cpu online?
 * int cpu_possible(cpu)		Is some cpu possible?
 * int cpu_present(cpu)			Is some cpu present (can schedule)?
 *
 * int any_online_cpu(mask)		First online cpu in mask, or NR_CPUS
 *
 * for_each_possible_cpu(cpu)		for-loop cpu over cpu_possible_map
 * for_each_online_cpu(cpu)		for-loop cpu over cpu_online_map
 * for_each_present_cpu(cpu)		for-loop cpu over cpu_present_map
 *
 * Subtlety:
 * 1) The 'type-checked' form of cpumask_test_cpu() causes gcc (3.3.2, anyway)
 *    to generate slightly worse code.  Note for example the additional
 *    40 lines of assembly code compiling the "for each possible cpu"
 *    loops buried in the disk_stat_read() macros calls when compiling
 *    drivers/block/genhd.c (arch i386, CONFIG_SMP=y).  So use a simple
 *    one-line #define for cpumask_test_cpu(), instead of wrapping an inline
 *    inside a macro, the way we do the other calls.
 */

#include <xen/bitmap.h>
#include <xen/kernel.h>
#include <xen/random.h>

typedef struct cpumask{ DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

extern unsigned int nr_cpu_ids;

#if NR_CPUS > 4 * BITS_PER_LONG
/* Assuming NR_CPUS is huge, a runtime limit is more efficient.  Also,
 * not all bits may be allocated. */
extern unsigned int nr_cpumask_bits;
#else
# define nr_cpumask_bits (BITS_TO_LONGS(NR_CPUS) * BITS_PER_LONG)
#endif

/* verify cpu argument to cpumask_* operators */
static inline unsigned int cpumask_check(unsigned int cpu)
{
	ASSERT(cpu < nr_cpu_ids);
	return cpu;
}

static inline void cpumask_set_cpu(int cpu, volatile cpumask_t *dstp)
{
	set_bit(cpumask_check(cpu), dstp->bits);
}

static inline void __cpumask_set_cpu(int cpu, cpumask_t *dstp)
{
	__set_bit(cpumask_check(cpu), dstp->bits);
}

static inline void cpumask_clear_cpu(int cpu, volatile cpumask_t *dstp)
{
	clear_bit(cpumask_check(cpu), dstp->bits);
}

static inline void __cpumask_clear_cpu(int cpu, cpumask_t *dstp)
{
	__clear_bit(cpumask_check(cpu), dstp->bits);
}

static inline void cpumask_setall(cpumask_t *dstp)
{
	bitmap_fill(dstp->bits, nr_cpumask_bits);
}

static inline void cpumask_clear(cpumask_t *dstp)
{
	bitmap_zero(dstp->bits, nr_cpumask_bits);
}

/* No static inline type checking - see Subtlety (1) above. */
#define cpumask_test_cpu(cpu, cpumask) \
	test_bit(cpumask_check(cpu), (cpumask)->bits)

static inline int cpumask_test_and_set_cpu(int cpu, volatile cpumask_t *addr)
{
	return test_and_set_bit(cpumask_check(cpu), addr->bits);
}

static inline int __cpumask_test_and_set_cpu(int cpu, cpumask_t *addr)
{
	return __test_and_set_bit(cpumask_check(cpu), addr->bits);
}

static inline int cpumask_test_and_clear_cpu(int cpu, volatile cpumask_t *addr)
{
	return test_and_clear_bit(cpumask_check(cpu), addr->bits);
}

static inline int __cpumask_test_and_clear_cpu(int cpu, cpumask_t *addr)
{
	return __test_and_clear_bit(cpumask_check(cpu), addr->bits);
}

static inline void cpumask_and(cpumask_t *dstp, const cpumask_t *src1p,
			       const cpumask_t *src2p)
{
	bitmap_and(dstp->bits, src1p->bits, src2p->bits, nr_cpumask_bits);
}

static inline void cpumask_or(cpumask_t *dstp, const cpumask_t *src1p,
			      const cpumask_t *src2p)
{
	bitmap_or(dstp->bits, src1p->bits, src2p->bits, nr_cpumask_bits);
}

static inline void cpumask_xor(cpumask_t *dstp, const cpumask_t *src1p,
			       const cpumask_t *src2p)
{
	bitmap_xor(dstp->bits, src1p->bits, src2p->bits, nr_cpumask_bits);
}

static inline void cpumask_andnot(cpumask_t *dstp, const cpumask_t *src1p,
				  const cpumask_t *src2p)
{
	bitmap_andnot(dstp->bits, src1p->bits, src2p->bits, nr_cpumask_bits);
}

static inline void cpumask_complement(cpumask_t *dstp, const cpumask_t *srcp)
{
	bitmap_complement(dstp->bits, srcp->bits, nr_cpumask_bits);
}

static inline int cpumask_equal(const cpumask_t *src1p,
				const cpumask_t *src2p)
{
	return bitmap_equal(src1p->bits, src2p->bits, nr_cpu_ids);
}

static inline int cpumask_intersects(const cpumask_t *src1p,
				     const cpumask_t *src2p)
{
	return bitmap_intersects(src1p->bits, src2p->bits, nr_cpu_ids);
}

static inline int cpumask_subset(const cpumask_t *src1p,
				 const cpumask_t *src2p)
{
	return bitmap_subset(src1p->bits, src2p->bits, nr_cpu_ids);
}

static inline int cpumask_empty(const cpumask_t *srcp)
{
	return bitmap_empty(srcp->bits, nr_cpu_ids);
}

static inline int cpumask_full(const cpumask_t *srcp)
{
	return bitmap_full(srcp->bits, nr_cpu_ids);
}

static inline int cpumask_weight(const cpumask_t *srcp)
{
	return bitmap_weight(srcp->bits, nr_cpu_ids);
}

static inline void cpumask_copy(cpumask_t *dstp, const cpumask_t *srcp)
{
	bitmap_copy(dstp->bits, srcp->bits, nr_cpumask_bits);
}

static inline void cpumask_shift_right(cpumask_t *dstp,
				       const cpumask_t *srcp, int n)
{
	bitmap_shift_right(dstp->bits, srcp->bits, n, nr_cpumask_bits);
}

static inline void cpumask_shift_left(cpumask_t *dstp,
				      const cpumask_t *srcp, int n)
{
	bitmap_shift_left(dstp->bits, srcp->bits, n, nr_cpumask_bits);
}

static inline int cpumask_first(const cpumask_t *srcp)
{
	return min_t(int, nr_cpu_ids, find_first_bit(srcp->bits, nr_cpu_ids));
}

static inline int cpumask_next(int n, const cpumask_t *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		cpumask_check(n);

	return min_t(int, nr_cpu_ids,
                     find_next_bit(srcp->bits, nr_cpu_ids, n + 1));
}

static inline int cpumask_last(const cpumask_t *srcp)
{
	int cpu, pcpu = nr_cpu_ids;

	for (cpu = cpumask_first(srcp);
	     cpu < nr_cpu_ids;
	     cpu = cpumask_next(cpu, srcp))
		pcpu = cpu;
	return pcpu;
}

static inline int cpumask_cycle(int n, const cpumask_t *srcp)
{
    int nxt = cpumask_next(n, srcp);

    if (nxt == nr_cpu_ids)
        nxt = cpumask_first(srcp);
    return nxt;
}

static inline unsigned int cpumask_any(const cpumask_t *srcp)
{
    unsigned int cpu = cpumask_first(srcp);
    unsigned int w = cpumask_weight(srcp);

    if ( w > 1 && cpu < nr_cpu_ids )
        for ( w = get_random() % w; w--; )
        {
            unsigned int next = cpumask_next(cpu, srcp);

            if ( next >= nr_cpu_ids )
                break;
            cpu = next;
        }

    return cpu;
}

/*
 * Special-case data structure for "single bit set only" constant CPU masks.
 *
 * We pre-generate all the 64 (or 32) possible bit positions, with enough
 * padding to the left and the right, and return the constant pointer
 * appropriately offset.
 */
extern const unsigned long
	cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)];

static inline const cpumask_t *cpumask_of(unsigned int cpu)
{
	const unsigned long *p = cpu_bit_bitmap[1 + cpu % BITS_PER_LONG];
	return (const cpumask_t *)(p - cpu / BITS_PER_LONG);
}

#define cpumask_bits(maskp) ((maskp)->bits)

static inline int cpumask_scnprintf(char *buf, int len,
				    const cpumask_t *srcp)
{
	return bitmap_scnprintf(buf, len, srcp->bits, nr_cpu_ids);
}

static inline int cpulist_scnprintf(char *buf, int len,
				    const cpumask_t *srcp)
{
	return bitmap_scnlistprintf(buf, len, srcp->bits, nr_cpu_ids);
}

/*
 * cpumask_var_t: struct cpumask for stack usage.
 *
 * Oh, the wicked games we play!  In order to make kernel coding a
 * little more difficult, we typedef cpumask_var_t to an array or a
 * pointer: doing &mask on an array is a noop, so it still works.
 *
 * ie.
 *	cpumask_var_t tmpmask;
 *	if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
 *		return -ENOMEM;
 *
 *	  ... use 'tmpmask' like a normal struct cpumask * ...
 *
 *	free_cpumask_var(tmpmask);
 */
#if NR_CPUS > 2 * BITS_PER_LONG
#include <xen/xmalloc.h>

typedef cpumask_t *cpumask_var_t;

static inline bool_t alloc_cpumask_var(cpumask_var_t *mask)
{
	*(void **)mask = _xmalloc(nr_cpumask_bits / 8, sizeof(long));
	return *mask != NULL;
}

static inline bool_t zalloc_cpumask_var(cpumask_var_t *mask)
{
	*(void **)mask = _xzalloc(nr_cpumask_bits / 8, sizeof(long));
	return *mask != NULL;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
	xfree(mask);
}
#else
typedef cpumask_t cpumask_var_t[1];

static inline bool_t alloc_cpumask_var(cpumask_var_t *mask)
{
	return 1;
}

static inline bool_t zalloc_cpumask_var(cpumask_var_t *mask)
{
	cpumask_clear(*mask);
	return 1;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}
#endif

#if NR_CPUS > 1
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = cpumask_first(mask);	\
	     (cpu) < nr_cpu_ids;		\
	     (cpu) = cpumask_next(cpu, mask))
#else /* NR_CPUS == 1 */
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)(mask))
#endif /* NR_CPUS */

/*
 * The following particular system cpumasks and operations manage
 * possible, present and online cpus.  Each of them is a fixed size
 * bitmap of size NR_CPUS.
 *
 *  #ifdef CONFIG_HOTPLUG_CPU
 *     cpu_possible_map - has bit 'cpu' set iff cpu is populatable
 *     cpu_present_map  - has bit 'cpu' set iff cpu is populated
 *     cpu_online_map   - has bit 'cpu' set iff cpu available to scheduler
 *  #else
 *     cpu_possible_map - has bit 'cpu' set iff cpu is populated
 *     cpu_present_map  - copy of cpu_possible_map
 *     cpu_online_map   - has bit 'cpu' set iff cpu available to scheduler
 *  #endif
 *
 *  In either case, NR_CPUS is fixed at compile time, as the static
 *  size of these bitmaps.  The cpu_possible_map is fixed at boot
 *  time, as the set of CPU id's that it is possible might ever
 *  be plugged in at anytime during the life of that system boot.
 *  The cpu_present_map is dynamic(*), representing which CPUs
 *  are currently plugged in.  And cpu_online_map is the dynamic
 *  subset of cpu_present_map, indicating those CPUs available
 *  for scheduling.
 *
 *  If HOTPLUG is enabled, then cpu_possible_map is forced to have
 *  all NR_CPUS bits set, otherwise it is just the set of CPUs that
 *  ACPI reports present at boot.
 *
 *  If HOTPLUG is enabled, then cpu_present_map varies dynamically,
 *  depending on what ACPI reports as currently plugged in, otherwise
 *  cpu_present_map is just a copy of cpu_possible_map.
 *
 *  (*) Well, cpu_present_map is dynamic in the hotplug case.  If not
 *      hotplug, it's a copy of cpu_possible_map, hence fixed at boot.
 *
 * Subtleties:
 * 1) UP arch's (NR_CPUS == 1, CONFIG_SMP not defined) hardcode
 *    assumption that their single CPU is online.  The UP
 *    cpu_{online,possible,present}_maps are placebos.  Changing them
 *    will have no useful affect on the following num_*_cpus()
 *    and cpu_*() macros in the UP case.  This ugliness is a UP
 *    optimization - don't waste any instructions or memory references
 *    asking if you're online or how many CPUs there are if there is
 *    only one CPU.
 * 2) Most SMP arch's #define some of these maps to be some
 *    other map specific to that arch.  Therefore, the following
 *    must be #define macros, not inlines.  To see why, examine
 *    the assembly code produced by the following.  Note that
 *    set1() writes phys_x_map, but set2() writes x_map:
 *        int x_map, phys_x_map;
 *        #define set1(a) x_map = a
 *        inline void set2(int a) { x_map = a; }
 *        #define x_map phys_x_map
 *        main(){ set1(3); set2(5); }
 */

extern cpumask_t cpu_possible_map;
extern cpumask_t cpu_online_map;
extern cpumask_t cpu_present_map;

#if NR_CPUS > 1
#define num_online_cpus()	cpumask_weight(&cpu_online_map)
#define num_possible_cpus()	cpumask_weight(&cpu_possible_map)
#define num_present_cpus()	cpumask_weight(&cpu_present_map)
#define cpu_online(cpu)		cpumask_test_cpu(cpu, &cpu_online_map)
#define cpu_possible(cpu)	cpumask_test_cpu(cpu, &cpu_possible_map)
#define cpu_present(cpu)	cpumask_test_cpu(cpu, &cpu_present_map)
#else
#define num_online_cpus()	1
#define num_possible_cpus()	1
#define num_present_cpus()	1
#define cpu_online(cpu)		((cpu) == 0)
#define cpu_possible(cpu)	((cpu) == 0)
#define cpu_present(cpu)	((cpu) == 0)
#endif

#define for_each_possible_cpu(cpu) for_each_cpu(cpu, &cpu_possible_map)
#define for_each_online_cpu(cpu)   for_each_cpu(cpu, &cpu_online_map)
#define for_each_present_cpu(cpu)  for_each_cpu(cpu, &cpu_present_map)

/* Copy to/from cpumap provided by control tools. */
struct xenctl_bitmap;
int cpumask_to_xenctl_bitmap(struct xenctl_bitmap *, const cpumask_t *);
int xenctl_bitmap_to_cpumask(cpumask_var_t *, const struct xenctl_bitmap *);

#endif /* __XEN_CPUMASK_H */
