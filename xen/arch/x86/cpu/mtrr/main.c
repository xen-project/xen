/*  Generic MTRR (Memory Type Range Register) driver.

    Copyright (C) 1997-2000  Richard Gooch
    Copyright (c) 2002	     Patrick Mochel

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    Richard Gooch may be reached by email at  rgooch@atnf.csiro.au
    The postal address is:
      Richard Gooch, c/o ATNF, P. O. Box 76, Epping, N.S.W., 2121, Australia.

    Source: "Pentium Pro Family Developer's Manual, Volume 3:
    Operating System Writer's Guide" (Intel document number 242692),
    section 11.11.7

    This was cleaned and made readable by Patrick Mochel <mochel@osdl.org> 
    on 6-7 March 2002. 
    Source: Intel Architecture Software Developers Manual, Volume 3: 
    System Programming Guide; Section 9.11. (1997 edition - PPro).
*/

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <asm/mtrr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include "mtrr.h"

/* No blocking mutexes in Xen. Spin instead. */
#define DEFINE_MUTEX(_m) DEFINE_SPINLOCK(_m)
#define mutex_lock(_m) spin_lock(_m)
#define mutex_unlock(_m) spin_unlock(_m)
#define dump_stack() ((void)0)
#define	get_cpu()	smp_processor_id()
#define put_cpu()	do {} while(0)

u32 __read_mostly num_var_ranges = 0;

unsigned int *__read_mostly usage_table;
static DEFINE_MUTEX(mtrr_mutex);

u64 __read_mostly size_or_mask;
u64 __read_mostly size_and_mask;

const struct mtrr_ops *__read_mostly mtrr_if = NULL;

static void set_mtrr(unsigned int reg, unsigned long base,
		     unsigned long size, mtrr_type type);

static const char *const mtrr_strings[MTRR_NUM_TYPES] =
{
    "uncachable",               /* 0 */
    "write-combining",          /* 1 */
    "?",                        /* 2 */
    "?",                        /* 3 */
    "write-through",            /* 4 */
    "write-protect",            /* 5 */
    "write-back",               /* 6 */
};

static const char *mtrr_attrib_to_str(int x)
{
	return (x <= 6) ? mtrr_strings[x] : "?";
}

/*  Returns non-zero if we have the write-combining memory type  */
static int have_wrcomb(void)
{
	return (mtrr_if->have_wrcomb ? mtrr_if->have_wrcomb() : 0);
}

/*  This function returns the number of variable MTRRs  */
static void __init set_num_var_ranges(void)
{
	unsigned long config = 0;

	if (use_intel()) {
		rdmsrl(MSR_MTRRcap, config);
	} else if (is_cpu(AMD))
		config = 2;
	else if (is_cpu(CYRIX) || is_cpu(CENTAUR))
		config = 8;
	num_var_ranges = config & 0xff;
}

static void __init init_table(void)
{
	int i, max;

	max = num_var_ranges;
	if ((usage_table = xmalloc_array(unsigned int, max)) == NULL) {
		printk(KERN_ERR "mtrr: could not allocate\n");
		return;
	}
	for (i = 0; i < max; i++)
		usage_table[i] = 1;
}

struct set_mtrr_data {
	atomic_t	count;
	atomic_t	gate;
	unsigned long	smp_base;
	unsigned long	smp_size;
	unsigned int	smp_reg;
	mtrr_type	smp_type;
};

/* As per the IA32 SDM vol-3: 10.11.8 MTRR Considerations in MP Systems section
 * MTRRs updates must to be synchronized across all the processors.
 * This flags avoids multiple cpu synchronization while booting each cpu.
 * At the boot & resume time, this flag is turned on in mtrr_aps_sync_begin().
 * Using this flag the mtrr initialization (and the all cpus sync up) in the 
 * mtrr_ap_init() is avoided while booting each cpu. 
 * After all the cpus have came up, then mtrr_aps_sync_end() synchronizes all 
 * the cpus and updates mtrrs on all of them. Then this flag is turned off.
 */
int hold_mtrr_updates_on_aps;

static void ipi_handler(void *info)
/*  [SUMMARY] Synchronisation handler. Executed by "other" CPUs.
    [RETURNS] Nothing.
*/
{
	struct set_mtrr_data *data = info;
	unsigned long flags;

	local_irq_save(flags);

	atomic_dec(&data->count);
	while(!atomic_read(&data->gate))
		cpu_relax();

	/*  The master has cleared me to execute  */
	if (data->smp_reg == ~0U) /* update all mtrr registers */
		/* At the cpu hot-add time this will reinitialize mtrr 
 		 * registres on the existing cpus. It is ok.  */
		mtrr_if->set_all();
	else /* single mtrr register update */
		mtrr_if->set(data->smp_reg, data->smp_base, 
			     data->smp_size, data->smp_type);

	atomic_dec(&data->count);
	while(atomic_read(&data->gate))
		cpu_relax();

	atomic_dec(&data->count);
	local_irq_restore(flags);
}

static inline int types_compatible(mtrr_type type1, mtrr_type type2) {
	return type1 == MTRR_TYPE_UNCACHABLE ||
	       type2 == MTRR_TYPE_UNCACHABLE ||
	       (type1 == MTRR_TYPE_WRTHROUGH && type2 == MTRR_TYPE_WRBACK) ||
	       (type1 == MTRR_TYPE_WRBACK && type2 == MTRR_TYPE_WRTHROUGH);
}

/**
 * set_mtrr - update mtrrs on all processors
 * @reg:	mtrr in question
 * @base:	mtrr base
 * @size:	mtrr size
 * @type:	mtrr type
 *
 * This is kinda tricky, but fortunately, Intel spelled it out for us cleanly:
 * 
 * 1. Send IPI to do the following:
 * 2. Disable Interrupts
 * 3. Wait for all procs to do so 
 * 4. Enter no-fill cache mode
 * 5. Flush caches
 * 6. Clear PGE bit
 * 7. Flush all TLBs
 * 8. Disable all range registers
 * 9. Update the MTRRs
 * 10. Enable all range registers
 * 11. Flush all TLBs and caches again
 * 12. Enter normal cache mode and reenable caching
 * 13. Set PGE 
 * 14. Wait for buddies to catch up
 * 15. Enable interrupts.
 * 
 * What does that mean for us? Well, first we set data.count to the number
 * of CPUs. As each CPU disables interrupts, it'll decrement it once. We wait
 * until it hits 0 and proceed. We set the data.gate flag and reset data.count.
 * Meanwhile, they are waiting for that flag to be set. Once it's set, each 
 * CPU goes through the transition of updating MTRRs. The CPU vendors may each do it 
 * differently, so we call mtrr_if->set() callback and let them take care of it.
 * When they're done, they again decrement data->count and wait for data.gate to 
 * be reset. 
 * When we finish, we wait for data.count to hit 0 and toggle the data.gate flag.
 * Everyone then enables interrupts and we all continue on.
 *
 * Note that the mechanism is the same for UP systems, too; all the SMP stuff
 * becomes nops.
 */
static void set_mtrr(unsigned int reg, unsigned long base,
		     unsigned long size, mtrr_type type)
{
	cpumask_t allbutself;
	unsigned int nr_cpus;
	struct set_mtrr_data data;
	unsigned long flags;

	cpumask_andnot(&allbutself, &cpu_online_map,
                      cpumask_of(smp_processor_id()));
	nr_cpus = cpumask_weight(&allbutself);

	data.smp_reg = reg;
	data.smp_base = base;
	data.smp_size = size;
	data.smp_type = type;
	atomic_set(&data.count, nr_cpus);
	atomic_set(&data.gate,0);

	/* Start the ball rolling on other CPUs */
	on_selected_cpus(&allbutself, ipi_handler, &data, 0);

	local_irq_save(flags);

	while (atomic_read(&data.count))
		cpu_relax();

	/* ok, reset count and toggle gate */
	atomic_set(&data.count, nr_cpus);
	smp_wmb();
	atomic_set(&data.gate,1);

	/* do our MTRR business */

	/* HACK!
	 * We use this same function to initialize the mtrrs on boot.
	 * The state of the boot cpu's mtrrs has been saved, and we want
	 * to replicate across all the APs. 
	 * If we're doing that @reg is set to something special...
	 */
	if (reg == ~0U)  /* update all mtrr registers */
		/* at boot or resume time, this will reinitialize the mtrrs on 
		 * the bp. It is ok. */
		mtrr_if->set_all();
	else /* update the single mtrr register */
		mtrr_if->set(reg,base,size,type);

	/* wait for the others */
	while (atomic_read(&data.count))
		cpu_relax();

	atomic_set(&data.count, nr_cpus);
	smp_wmb();
	atomic_set(&data.gate,0);

	/*
	 * Wait here for everyone to have seen the gate change
	 * So we're the last ones to touch 'data'
	 */
	while (atomic_read(&data.count))
		cpu_relax();

	local_irq_restore(flags);
}

/**
 *	mtrr_add_page - Add a memory type region
 *	@base: Physical base address of region in pages (in units of 4 kB!)
 *	@size: Physical size of region in pages (4 kB)
 *	@type: Type of MTRR desired
 *	@increment: If this is true do usage counting on the region
 *
 *	Memory type region registers control the caching on newer Intel and
 *	non Intel processors. This function allows drivers to request an
 *	MTRR is added. The details and hardware specifics of each processor's
 *	implementation are hidden from the caller, but nevertheless the 
 *	caller should expect to need to provide a power of two size on an
 *	equivalent power of two boundary.
 *
 *	If the region cannot be added either because all regions are in use
 *	or the CPU cannot support it a negative value is returned. On success
 *	the register number for this entry is returned, but should be treated
 *	as a cookie only.
 *
 *	On a multiprocessor machine the changes are made to all processors.
 *	This is required on x86 by the Intel processors.
 *
 *	The available types are
 *
 *	%MTRR_TYPE_UNCACHABLE	-	No caching
 *
 *	%MTRR_TYPE_WRBACK	-	Write data back in bursts whenever
 *
 *	%MTRR_TYPE_WRCOMB	-	Write data back soon but allow bursts
 *
 *	%MTRR_TYPE_WRTHROUGH	-	Cache reads but not writes
 *
 *	BUGS: Needs a quiet flag for the cases where drivers do not mind
 *	failures and do not wish system log messages to be sent.
 */

int mtrr_add_page(unsigned long base, unsigned long size, 
		  unsigned int type, char increment)
{
	int i, replace, error;
	mtrr_type ltype;
	unsigned long lbase, lsize;

	if (!mtrr_if)
		return -ENXIO;
		
	if ((error = mtrr_if->validate_add_page(base,size,type)))
		return error;

	if (type >= MTRR_NUM_TYPES) {
		printk(KERN_WARNING "mtrr: type: %u invalid\n", type);
		return -EINVAL;
	}

	/*  If the type is WC, check that this processor supports it  */
	if ((type == MTRR_TYPE_WRCOMB) && !have_wrcomb()) {
		printk(KERN_WARNING
		       "mtrr: your processor doesn't support write-combining\n");
		return -ENOSYS;
	}

	if (!size) {
		printk(KERN_WARNING "mtrr: zero sized request\n");
		return -EINVAL;
	}

	if ((base | (base + size - 1)) >> (paddr_bits - PAGE_SHIFT)) {
		printk(KERN_WARNING "mtrr: base or size exceeds the MTRR width\n");
		return -EINVAL;
	}

	error = -EINVAL;
	replace = -1;

	/*  Search for existing MTRR  */
	mutex_lock(&mtrr_mutex);
	for (i = 0; i < num_var_ranges; ++i) {
		mtrr_if->get(i, &lbase, &lsize, &ltype);
		if (!lsize || base > lbase + lsize - 1 || base + size - 1 < lbase)
			continue;
		/*  At this point we know there is some kind of overlap/enclosure  */
		if (base < lbase || base + size - 1 > lbase + lsize - 1) {
			if (base <= lbase && base + size - 1 >= lbase + lsize - 1) {
				/*  New region encloses an existing region  */
				if (type == ltype) {
					replace = replace == -1 ? i : -2;
					continue;
				}
				else if (types_compatible(type, ltype))
					continue;
			}
			printk(KERN_WARNING
			       "mtrr: %#lx000,%#lx000 overlaps existing"
			       " %#lx000,%#lx000\n", base, size, lbase,
			       lsize);
			goto out;
		}
		/*  New region is enclosed by an existing region  */
		if (ltype != type) {
			if (types_compatible(type, ltype))
				continue;
			printk (KERN_WARNING "mtrr: type mismatch for %lx000,%lx000 old: %s new: %s\n",
			     base, size, mtrr_attrib_to_str(ltype),
			     mtrr_attrib_to_str(type));
			goto out;
		}
		if (increment)
			++usage_table[i];
		error = i;
		goto out;
	}
	/*  Search for an empty MTRR  */
	i = mtrr_if->get_free_region(base, size, replace);
	if (i >= 0) {
		set_mtrr(i, base, size, type);
		if (likely(replace < 0))
			usage_table[i] = 1;
		else {
			usage_table[i] = usage_table[replace] + !!increment;
			if (unlikely(replace != i)) {
				set_mtrr(replace, 0, 0, 0);
				usage_table[replace] = 0;
			}
		}
	} else
		printk(KERN_INFO "mtrr: no more MTRRs available\n");
	error = i;
 out:
	mutex_unlock(&mtrr_mutex);
	return error;
}

static int mtrr_check(unsigned long base, unsigned long size)
{
	if ((base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1))) {
		printk(KERN_WARNING
			"mtrr: size and base must be multiples of 4 kiB\n");
		printk(KERN_DEBUG
			"mtrr: size: %#lx  base: %#lx\n", size, base);
		dump_stack();
		return -1;
	}
	return 0;
}

/**
 *	mtrr_add - Add a memory type region
 *	@base: Physical base address of region
 *	@size: Physical size of region
 *	@type: Type of MTRR desired
 *	@increment: If this is true do usage counting on the region
 *
 *	Memory type region registers control the caching on newer Intel and
 *	non Intel processors. This function allows drivers to request an
 *	MTRR is added. The details and hardware specifics of each processor's
 *	implementation are hidden from the caller, but nevertheless the 
 *	caller should expect to need to provide a power of two size on an
 *	equivalent power of two boundary.
 *
 *	If the region cannot be added either because all regions are in use
 *	or the CPU cannot support it a negative value is returned. On success
 *	the register number for this entry is returned, but should be treated
 *	as a cookie only.
 *
 *	On a multiprocessor machine the changes are made to all processors.
 *	This is required on x86 by the Intel processors.
 *
 *	The available types are
 *
 *	%MTRR_TYPE_UNCACHABLE	-	No caching
 *
 *	%MTRR_TYPE_WRBACK	-	Write data back in bursts whenever
 *
 *	%MTRR_TYPE_WRCOMB	-	Write data back soon but allow bursts
 *
 *	%MTRR_TYPE_WRTHROUGH	-	Cache reads but not writes
 *
 *	BUGS: Needs a quiet flag for the cases where drivers do not mind
 *	failures and do not wish system log messages to be sent.
 */

int __init
mtrr_add(unsigned long base, unsigned long size, unsigned int type,
	 char increment)
{
	if (mtrr_check(base, size))
		return -EINVAL;
	return mtrr_add_page(base >> PAGE_SHIFT, size >> PAGE_SHIFT, type,
			     increment);
}

/**
 *	mtrr_del_page - delete a memory type region
 *	@reg: Register returned by mtrr_add
 *	@base: Physical base address
 *	@size: Size of region
 *
 *	If register is supplied then base and size are ignored. This is
 *	how drivers should call it.
 *
 *	Releases an MTRR region. If the usage count drops to zero the 
 *	register is freed and the region returns to default state.
 *	On success the register is returned, on failure a negative error
 *	code.
 */

int mtrr_del_page(int reg, unsigned long base, unsigned long size)
{
	int i, max;
	mtrr_type ltype;
	unsigned long lbase, lsize;
	int error = -EINVAL;

	if (!mtrr_if)
		return -ENXIO;

	max = num_var_ranges;
	mutex_lock(&mtrr_mutex);
	if (reg < 0) {
		/*  Search for existing MTRR  */
		for (i = 0; i < max; ++i) {
			mtrr_if->get(i, &lbase, &lsize, &ltype);
			if (lbase == base && lsize == size) {
				reg = i;
				break;
			}
		}
		if (reg < 0) {
			printk(KERN_DEBUG "mtrr: no MTRR for %lx000,%lx000 found\n", base,
			       size);
			goto out;
		}
	}
	if (reg >= max) {
		printk(KERN_WARNING "mtrr: register: %d too big\n", reg);
		goto out;
	}
	mtrr_if->get(reg, &lbase, &lsize, &ltype);
	if (lsize < 1) {
		printk(KERN_WARNING "mtrr: MTRR %d not used\n", reg);
		goto out;
	}
	if (usage_table[reg] < 1) {
		printk(KERN_WARNING "mtrr: reg: %d has count=0\n", reg);
		goto out;
	}
	if (--usage_table[reg] < 1)
		set_mtrr(reg, 0, 0, 0);
	error = reg;
 out:
	mutex_unlock(&mtrr_mutex);
	return error;
}
/**
 *	mtrr_del - delete a memory type region
 *	@reg: Register returned by mtrr_add
 *	@base: Physical base address
 *	@size: Size of region
 *
 *	If register is supplied then base and size are ignored. This is
 *	how drivers should call it.
 *
 *	Releases an MTRR region. If the usage count drops to zero the 
 *	register is freed and the region returns to default state.
 *	On success the register is returned, on failure a negative error
 *	code.
 */

int __init
mtrr_del(int reg, unsigned long base, unsigned long size)
{
	if (mtrr_check(base, size))
		return -EINVAL;
	return mtrr_del_page(reg, base >> PAGE_SHIFT, size >> PAGE_SHIFT);
}

/* The suspend/resume methods are only for CPU without MTRR. CPU using generic
 * MTRR driver doesn't require this
 */
struct mtrr_value {
	mtrr_type	ltype;
	unsigned long	lbase;
	unsigned long	lsize;
};

/**
 * mtrr_bp_init - initialize mtrrs on the boot CPU
 *
 * This needs to be called early; before any of the other CPUs are 
 * initialized (i.e. before smp_init()).
 * 
 */
void __init mtrr_bp_init(void)
{
	if (cpu_has_mtrr) {
		mtrr_if = &generic_mtrr_ops;
		size_or_mask = ~((1ULL << (paddr_bits - PAGE_SHIFT)) - 1);
		size_and_mask = ~size_or_mask & 0xfffff00000ULL;
	}

	if (mtrr_if) {
		set_num_var_ranges();
		init_table();
		if (use_intel())
			get_mtrr_state();
	}
}

void mtrr_ap_init(void)
{
	if (!mtrr_if || !use_intel() || hold_mtrr_updates_on_aps)
		return;
	/*
	 * Ideally we should hold mtrr_mutex here to avoid mtrr entries changed,
	 * but this routine will be called in cpu boot time, holding the lock
	 * breaks it. This routine is called in two cases: 1.very earily time
	 * of software resume, when there absolutely isn't mtrr entry changes;
	 * 2.cpu hotadd time. We let mtrr_add/del_page hold cpuhotplug lock to
	 * prevent mtrr entry changes
	 */
	set_mtrr(~0U, 0, 0, 0);
}

/**
 * Save current fixed-range MTRR state of the BSP
 */
void mtrr_save_state(void)
{
	int cpu = get_cpu();

	if (cpu == 0)
		mtrr_save_fixed_ranges(NULL);
	else
		on_selected_cpus(cpumask_of(0), mtrr_save_fixed_ranges, NULL, 1);
	put_cpu();
}

void mtrr_aps_sync_begin(void)
{
	if (!use_intel())
		return;
	hold_mtrr_updates_on_aps = 1;
}

void mtrr_aps_sync_end(void)
{
	if (!use_intel())
		return;
	set_mtrr(~0U, 0, 0, 0);
	hold_mtrr_updates_on_aps = 0;
}

void mtrr_bp_restore(void)
{
	if (!use_intel())
		return;
	mtrr_if->set_all();
}

static int __init mtrr_init_finialize(void)
{
	if (!mtrr_if)
		return 0;
	if (use_intel())
		mtrr_state_warn();
	return 0;
}
__initcall(mtrr_init_finialize);
