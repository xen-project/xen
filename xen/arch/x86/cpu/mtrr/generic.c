/* This only handles 32bit MTRR on 32bit hosts. This is strictly wrong
   because MTRRs can span upto 40 bits (36bits on most modern x86) */ 
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/mtrr.h>
#include <asm/msr.h>
#include <asm/system.h>
#include <asm/cpufeature.h>
#include "mtrr.h"

static const struct fixed_range_block {
	uint32_t base_msr;   /* start address of an MTRR block */
	unsigned int ranges; /* number of MTRRs in this block  */
} fixed_range_blocks[] = {
	{ MSR_MTRRfix64K_00000, (0x80000 - 0x00000) >> (16 + 3) },
	{ MSR_MTRRfix16K_80000, (0xC0000 - 0x80000) >> (14 + 3) },
	{ MSR_MTRRfix4K_C0000, (0x100000 - 0xC0000) >> (12 + 3) },
	{}
};

static unsigned long smp_changes_mask;
struct mtrr_state mtrr_state = {};

/*  Get the MSR pair relating to a var range  */
static void
get_mtrr_var_range(unsigned int index, struct mtrr_var_range *vr)
{
	rdmsrl(MSR_IA32_MTRR_PHYSBASE(index), vr->base);
	rdmsrl(MSR_IA32_MTRR_PHYSMASK(index), vr->mask);
}

static void
get_fixed_ranges(mtrr_type * frs)
{
	uint64_t *p = (uint64_t *) frs;
	const struct fixed_range_block *block;

	if (!mtrr_state.have_fixed)
		return;

	for (block = fixed_range_blocks; block->ranges; ++block) {
		unsigned int i;

		for (i = 0; i < block->ranges; ++i, ++p)
			rdmsrl(block->base_msr + i, *p);
	}
}

void mtrr_save_fixed_ranges(void *info)
{
	get_fixed_ranges(mtrr_state.fixed_ranges);
}

/*  Grab all of the MTRR state for this CPU into *state  */
void __init get_mtrr_state(void)
{
	unsigned int i;
	struct mtrr_var_range *vrs;
	uint64_t msr_content;

	if (!mtrr_state.var_ranges) {
		mtrr_state.var_ranges = xmalloc_array(struct mtrr_var_range,
						  num_var_ranges);
		if (!mtrr_state.var_ranges)
			return;
	} 
	vrs = mtrr_state.var_ranges;

	rdmsrl(MSR_MTRRcap, msr_content);
	mtrr_state.have_fixed = (msr_content >> 8) & 1;

	for (i = 0; i < num_var_ranges; i++)
		get_mtrr_var_range(i, &vrs[i]);
	get_fixed_ranges(mtrr_state.fixed_ranges);

	rdmsrl(MSR_MTRRdefType, msr_content);
	mtrr_state.def_type = (msr_content & 0xff);
	mtrr_state.enabled = (msr_content & 0xc00) >> 10;

	/* Store mtrr_cap for HVM MTRR virtualisation. */
	rdmsrl(MSR_MTRRcap, mtrr_state.mtrr_cap);
}

static bool_t __initdata mtrr_show;
boolean_param("mtrr.show", mtrr_show);

static const char *__init mtrr_attrib_to_str(mtrr_type x)
{
	static const char __initconst strings[MTRR_NUM_TYPES][16] =
	{
		[MTRR_TYPE_UNCACHABLE]     = "uncachable",
		[MTRR_TYPE_WRCOMB]         = "write-combining",
		[MTRR_TYPE_WRTHROUGH]      = "write-through",
		[MTRR_TYPE_WRPROT]         = "write-protect",
		[MTRR_TYPE_WRBACK]         = "write-back",
	};

	return (x < ARRAY_SIZE(strings) && strings[x][0]) ? strings[x] : "?";
}

static unsigned int __initdata last_fixed_start;
static unsigned int __initdata last_fixed_end;
static mtrr_type __initdata last_fixed_type;

static void __init print_fixed_last(const char *level)
{
	if (!last_fixed_end)
		return;

	printk("%s  %05x-%05x %s\n", level, last_fixed_start,
	       last_fixed_end - 1, mtrr_attrib_to_str(last_fixed_type));

	last_fixed_end = 0;
}

static void __init update_fixed_last(unsigned int base, unsigned int end,
				     mtrr_type type)
{
	last_fixed_start = base;
	last_fixed_end = end;
	last_fixed_type = type;
}

static void __init print_fixed(unsigned int base, unsigned int step,
			       const mtrr_type *types, const char *level)
{
	unsigned i;

	for (i = 0; i < 8; ++i, ++types, base += step) {
		if (last_fixed_end == 0) {
			update_fixed_last(base, base + step, *types);
			continue;
		}
		if (last_fixed_end == base && last_fixed_type == *types) {
			last_fixed_end = base + step;
			continue;
		}
		/* new segments: gap or different type */
		print_fixed_last(level);
		update_fixed_last(base, base + step, *types);
	}
}

static void __init print_mtrr_state(const char *level)
{
	unsigned int i;
	int width;

	printk("%sMTRR default type: %s\n", level,
	       mtrr_attrib_to_str(mtrr_state.def_type));
	if (mtrr_state.have_fixed) {
		const mtrr_type *fr = mtrr_state.fixed_ranges;
		const struct fixed_range_block *block = fixed_range_blocks;
		unsigned int base = 0, step = 0x10000;

		printk("%sMTRR fixed ranges %sabled:\n", level,
		       mtrr_state.enabled & 1 ? "en" : "dis");
		for (; block->ranges; ++block, step >>= 2) {
			for (i = 0; i < block->ranges; ++i, fr += 8) {
				print_fixed(base, step, fr, level);
				base += 8 * step;
			}
		}
		print_fixed_last(level);
	}
	printk("%sMTRR variable ranges %sabled:\n", level,
	       mtrr_state.enabled & 2 ? "en" : "dis");
	width = (paddr_bits - PAGE_SHIFT + 3) / 4;

	for (i = 0; i < num_var_ranges; ++i) {
		if (mtrr_state.var_ranges[i].mask & MTRR_PHYSMASK_VALID)
			printk("%s  %u base %0*"PRIx64"000 mask %0*"PRIx64"000 %s\n",
			       level, i,
			       width, mtrr_state.var_ranges[i].base >> 12,
			       width, mtrr_state.var_ranges[i].mask >> 12,
			       mtrr_attrib_to_str(mtrr_state.var_ranges[i].base &
			                          MTRR_PHYSBASE_TYPE_MASK));
		else
			printk("%s  %u disabled\n", level, i);
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD
	    && boot_cpu_data.x86 >= 0xf) {
		uint64_t syscfg, tom2;

		rdmsrl(MSR_K8_SYSCFG, syscfg);
		if (syscfg & (1 << 21)) {
			rdmsrl(MSR_K8_TOP_MEM2, tom2);
			printk("%sTOM2: %012"PRIx64"%s\n", level, tom2,
			       syscfg & (1 << 22) ? " (WB)" : "");
		}
	}
}

/*  Some BIOS's are fucked and don't set all MTRRs the same!  */
void __init mtrr_state_warn(void)
{
	unsigned long mask = smp_changes_mask;

	if (mtrr_show)
		print_mtrr_state(mask ? KERN_WARNING : "");
	if (!mask)
		return;
	if (mask & MTRR_CHANGE_MASK_FIXED)
		printk(KERN_WARNING "mtrr: your CPUs had inconsistent fixed MTRR settings\n");
	if (mask & MTRR_CHANGE_MASK_VARIABLE)
		printk(KERN_WARNING "mtrr: your CPUs had inconsistent variable MTRR settings\n");
	if (mask & MTRR_CHANGE_MASK_DEFTYPE)
		printk(KERN_WARNING "mtrr: your CPUs had inconsistent MTRRdefType settings\n");
	printk(KERN_INFO "mtrr: probably your BIOS does not setup all CPUs.\n");
	printk(KERN_INFO "mtrr: corrected configuration.\n");
	if (!mtrr_show)
		print_mtrr_state(KERN_INFO);
}

/* Doesn't attempt to pass an error out to MTRR users
   because it's quite complicated in some cases and probably not
   worth it because the best error handling is to ignore it. */
static void mtrr_wrmsr(unsigned int msr, uint64_t msr_content)
{
	if (wrmsr_safe(msr, msr_content) < 0)
		printk(KERN_ERR
			"MTRR: CPU %u: Writing MSR %x to %"PRIx64" failed\n",
			smp_processor_id(), msr, msr_content);
	/* Cache overlap status for efficient HVM MTRR virtualisation. */
	mtrr_state.overlapped = is_var_mtrr_overlapped(&mtrr_state);
}

/**
 * Checks and updates an fixed-range MTRR if it differs from the value it
 * should have. If K8 extenstions are wanted, update the K8 SYSCFG MSR also.
 * see AMD publication no. 24593, chapter 7.8.1, page 233 for more information
 * \param msr MSR address of the MTTR which should be checked and updated
 * \param changed pointer which indicates whether the MTRR needed to be changed
 * \param msrwords pointer to the MSR values which the MSR should have
 */
static void set_fixed_range(int msr, int * changed, unsigned int * msrwords)
{
	uint64_t msr_content, val;

	rdmsrl(msr, msr_content);
	val = ((uint64_t)msrwords[1] << 32) | msrwords[0];

	if (msr_content != val) {
		mtrr_wrmsr(msr, val);
		*changed = TRUE;
	}
}

int generic_get_free_region(unsigned long base, unsigned long size, int replace_reg)
/*  [SUMMARY] Get a free MTRR.
    <base> The starting (base) address of the region.
    <size> The size (in bytes) of the region.
    [RETURNS] The index of the region on success, else -1 on error.
*/
{
	int i, max;
	mtrr_type ltype;
	unsigned long lbase, lsize;

	max = num_var_ranges;
	if (replace_reg >= 0 && replace_reg < max)
		return replace_reg;
	for (i = 0; i < max; ++i) {
		mtrr_if->get(i, &lbase, &lsize, &ltype);
		if (lsize == 0)
			return i;
	}
	return -ENOSPC;
}

static void generic_get_mtrr(unsigned int reg, unsigned long *base,
			     unsigned long *size, mtrr_type *type)
{
	uint64_t _mask, _base;

	rdmsrl(MSR_IA32_MTRR_PHYSMASK(reg), _mask);
	if (!(_mask & MTRR_PHYSMASK_VALID)) {
		/*  Invalid (i.e. free) range  */
		*base = 0;
		*size = 0;
		*type = 0;
		return;
	}

	rdmsrl(MSR_IA32_MTRR_PHYSBASE(reg), _base);

	/* Work out the shifted address mask. */
	_mask = size_or_mask | (_mask >> PAGE_SHIFT);

	/* This works correctly if size is a power of two, i.e. a
	   contiguous range. */
	*size = -(uint32_t)_mask;
	*base = _base >> PAGE_SHIFT;
	*type = _base & 0xff;
}

/**
 * Checks and updates the fixed-range MTRRs if they differ from the saved set
 * \param frs pointer to fixed-range MTRR values, saved by get_fixed_ranges()
 */
static int set_fixed_ranges(mtrr_type * frs)
{
	unsigned long long *saved = (unsigned long long *) frs;
	int changed = FALSE;
	int block=-1, range;

	while (fixed_range_blocks[++block].ranges)
	    for (range=0; range < fixed_range_blocks[block].ranges; range++)
		set_fixed_range(fixed_range_blocks[block].base_msr + range,
		    &changed, (unsigned int *) saved++);

	return changed;
}

/*  Set the MSR pair relating to a var range. Returns TRUE if
    changes are made  */
static int set_mtrr_var_ranges(unsigned int index, struct mtrr_var_range *vr)
{
	uint32_t lo, hi, base_lo, base_hi, mask_lo, mask_hi;
	uint64_t msr_content;
	int changed = FALSE;

	rdmsrl(MSR_IA32_MTRR_PHYSBASE(index), msr_content);
	lo = (uint32_t)msr_content;
	hi = (uint32_t)(msr_content >> 32);
	base_lo = (uint32_t)vr->base;
	base_hi = (uint32_t)(vr->base >> 32);

	lo &= 0xfffff0ffUL;
	base_lo &= 0xfffff0ffUL;
	hi &= size_and_mask >> (32 - PAGE_SHIFT);
	base_hi &= size_and_mask >> (32 - PAGE_SHIFT);

	if ((base_lo != lo) || (base_hi != hi)) {
		mtrr_wrmsr(MSR_IA32_MTRR_PHYSBASE(index), vr->base);
		changed = TRUE;
	}

	rdmsrl(MSR_IA32_MTRR_PHYSMASK(index), msr_content);
	lo = (uint32_t)msr_content;
	hi = (uint32_t)(msr_content >> 32);
	mask_lo = (uint32_t)vr->mask;
	mask_hi = (uint32_t)(vr->mask >> 32);

	lo &= 0xfffff800UL;
	mask_lo &= 0xfffff800UL;
	hi &= size_and_mask >> (32 - PAGE_SHIFT);
	mask_hi &= size_and_mask >> (32 - PAGE_SHIFT);

	if ((mask_lo != lo) || (mask_hi != hi)) {
		mtrr_wrmsr(MSR_IA32_MTRR_PHYSMASK(index), vr->mask);
		changed = TRUE;
	}
	return changed;
}

static uint64_t deftype;

static unsigned long set_mtrr_state(void)
/*  [SUMMARY] Set the MTRR state for this CPU.
    <state> The MTRR state information to read.
    <ctxt> Some relevant CPU context.
    [NOTE] The CPU must already be in a safe state for MTRR changes.
    [RETURNS] 0 if no changes made, else a mask indication what was changed.
*/
{
	unsigned int i;
	unsigned long change_mask = 0;

	for (i = 0; i < num_var_ranges; i++)
		if (set_mtrr_var_ranges(i, &mtrr_state.var_ranges[i]))
			change_mask |= MTRR_CHANGE_MASK_VARIABLE;

	if (mtrr_state.have_fixed && set_fixed_ranges(mtrr_state.fixed_ranges))
		change_mask |= MTRR_CHANGE_MASK_FIXED;

	/*  Set_mtrr_restore restores the old value of MTRRdefType,
	   so to set it we fiddle with the saved value  */
	if ((deftype & 0xff) != mtrr_state.def_type
	    || ((deftype & 0xc00) >> 10) != mtrr_state.enabled) {
		deftype = (deftype & ~0xcff) | mtrr_state.def_type | (mtrr_state.enabled << 10);
		change_mask |= MTRR_CHANGE_MASK_DEFTYPE;
	}

	return change_mask;
}


static unsigned long cr4 = 0;
static DEFINE_SPINLOCK(set_atomicity_lock);

/*
 * Since we are disabling the cache don't allow any interrupts - they
 * would run extremely slow and would only increase the pain.  The caller must
 * ensure that local interrupts are disabled and are reenabled after post_set()
 * has been called.
 */

static void prepare_set(void)
{
	unsigned long cr0;

	/*  Note that this is not ideal, since the cache is only flushed/disabled
	   for this CPU while the MTRRs are changed, but changing this requires
	   more invasive changes to the way the kernel boots  */

	spin_lock(&set_atomicity_lock);

	/*  Enter the no-fill (CD=1, NW=0) cache mode and flush caches. */
	cr0 = read_cr0() | 0x40000000;	/* set CD flag */
	write_cr0(cr0);
	wbinvd();

	/*  Save value of CR4 and clear Page Global Enable (bit 7)  */
	if ( cpu_has_pge ) {
		cr4 = read_cr4();
		write_cr4(cr4 & ~X86_CR4_PGE);
	}

	/* Flush all TLBs via a mov %cr3, %reg; mov %reg, %cr3 */
	flush_tlb_local();

	/*  Save MTRR state */
	rdmsrl(MSR_MTRRdefType, deftype);

	/*  Disable MTRRs, and set the default type to uncached  */
	mtrr_wrmsr(MSR_MTRRdefType, deftype & ~0xcff);
}

static void post_set(void)
{
	/*  Flush TLBs (no need to flush caches - they are disabled)  */
	flush_tlb_local();

	/* Intel (P6) standard MTRRs */
	mtrr_wrmsr(MSR_MTRRdefType, deftype);
		
	/*  Enable caches  */
	write_cr0(read_cr0() & 0xbfffffff);

	/*  Restore value of CR4  */
	if ( cpu_has_pge )
		write_cr4(cr4);
	spin_unlock(&set_atomicity_lock);
}

static void generic_set_all(void)
{
	unsigned long mask, count;
	unsigned long flags;

	local_irq_save(flags);
	prepare_set();

	/* Actually set the state */
	mask = set_mtrr_state();

	post_set();
	local_irq_restore(flags);

	/*  Use the atomic bitops to update the global mask  */
	for (count = 0; count < sizeof mask * 8; ++count) {
		if (mask & 0x01)
			set_bit(count, &smp_changes_mask);
		mask >>= 1;
	}
	
}

static void generic_set_mtrr(unsigned int reg, unsigned long base,
			     unsigned long size, mtrr_type type)
/*  [SUMMARY] Set variable MTRR register on the local CPU.
    <reg> The register to set.
    <base> The base address of the region.
    <size> The size of the region. If this is 0 the region is disabled.
    <type> The type of the region.
    <do_safe> If TRUE, do the change safely. If FALSE, safety measures should
    be done externally.
    [RETURNS] Nothing.
*/
{
	unsigned long flags;
	struct mtrr_var_range *vr;

	vr = &mtrr_state.var_ranges[reg];

	local_irq_save(flags);
	prepare_set();

	if (size == 0) {
		/* The invalid bit is kept in the mask, so we simply clear the
		   relevant mask register to disable a range. */
		memset(vr, 0, sizeof(*vr));
		mtrr_wrmsr(MSR_IA32_MTRR_PHYSMASK(reg), 0);
	} else {
		uint32_t base_lo, base_hi, mask_lo, mask_hi;

		base_lo = base << PAGE_SHIFT | type;
		base_hi = (base & size_and_mask) >> (32 - PAGE_SHIFT);
		mask_lo = (-size << PAGE_SHIFT) | MTRR_PHYSMASK_VALID;
		mask_hi = (-size & size_and_mask) >> (32 - PAGE_SHIFT);
		vr->base = ((uint64_t)base_hi << 32) | base_lo;
		vr->mask = ((uint64_t)mask_hi << 32) | mask_lo;

		mtrr_wrmsr(MSR_IA32_MTRR_PHYSBASE(reg), vr->base);
		mtrr_wrmsr(MSR_IA32_MTRR_PHYSMASK(reg), vr->mask);
	}

	post_set();
	local_irq_restore(flags);
}

int generic_validate_add_page(unsigned long base, unsigned long size, unsigned int type)
{
	unsigned long lbase, last;

	/*  For Intel PPro stepping <= 7, must be 4 MiB aligned 
	    and not touch 0x70000000->0x7003FFFF */
	if (is_cpu(INTEL) && boot_cpu_data.x86 == 6 &&
	    boot_cpu_data.x86_model == 1 &&
	    boot_cpu_data.x86_mask <= 7) {
		if (base & ((1 << (22 - PAGE_SHIFT)) - 1)) {
			printk(KERN_WARNING "mtrr: base(%#lx000) is not 4 MiB aligned\n", base);
			return -EINVAL;
		}
		if (!(base + size < 0x70000 || base > 0x7003F) &&
		    (type == MTRR_TYPE_WRCOMB
		     || type == MTRR_TYPE_WRBACK)) {
			printk(KERN_WARNING "mtrr: writable mtrr between 0x70000000 and 0x7003FFFF may hang the CPU.\n");
			return -EINVAL;
		}
	}

	/*  Check upper bits of base and last are equal and lower bits are 0
	    for base and 1 for last  */
	last = base + size - 1;
	for (lbase = base; !(lbase & 1) && (last & 1);
	     lbase = lbase >> 1, last = last >> 1) ;
	if (lbase != last) {
		printk(KERN_WARNING "mtrr: base(%#lx000) is not aligned on a size(%#lx000) boundary\n",
		       base, size);
		return -EINVAL;
	}
	return 0;
}


static int generic_have_wrcomb(void)
{
	unsigned long config;
	rdmsrl(MSR_MTRRcap, config);
	return (config & (1ULL << 10));
}

int positive_have_wrcomb(void)
{
	return 1;
}

/* generic structure...
 */
const struct mtrr_ops generic_mtrr_ops = {
	.use_intel_if      = 1,
	.set_all	   = generic_set_all,
	.get               = generic_get_mtrr,
	.get_free_region   = generic_get_free_region,
	.set               = generic_set_mtrr,
	.validate_add_page = generic_validate_add_page,
	.have_wrcomb       = generic_have_wrcomb,
};
