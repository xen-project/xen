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

struct fixed_range_block {
	int base_msr; /* start address of an MTRR block */
	int ranges;   /* number of MTRRs in this block  */
};

static struct fixed_range_block fixed_range_blocks[] = {
	{ MTRRfix64K_00000_MSR, 1 }, /* one  64k MTRR  */
	{ MTRRfix16K_80000_MSR, 2 }, /* two  16k MTRRs */
	{ MTRRfix4K_C0000_MSR,  8 }, /* eight 4k MTRRs */
	{}
};

static unsigned long smp_changes_mask;
struct mtrr_state mtrr_state = {};

/*  Get the MSR pair relating to a var range  */
static void
get_mtrr_var_range(unsigned int index, struct mtrr_var_range *vr)
{
	rdmsrl(MTRRphysBase_MSR(index), vr->base);
	rdmsrl(MTRRphysMask_MSR(index), vr->mask);
}

static void
get_fixed_ranges(mtrr_type * frs)
{
	unsigned int *p = (unsigned int *) frs;
	int i;

	rdmsr(MTRRfix64K_00000_MSR, p[0], p[1]);

	for (i = 0; i < 2; i++)
		rdmsr(MTRRfix16K_80000_MSR + i, p[2 + i * 2], p[3 + i * 2]);
	for (i = 0; i < 8; i++)
		rdmsr(MTRRfix4K_C0000_MSR + i, p[6 + i * 2], p[7 + i * 2]);
}

void mtrr_save_fixed_ranges(void *info)
{
	if (cpu_has_mtrr)
		get_fixed_ranges(mtrr_state.fixed_ranges);
}

/*  Grab all of the MTRR state for this CPU into *state  */
void __init get_mtrr_state(void)
{
	unsigned int i;
	struct mtrr_var_range *vrs;
	unsigned lo, dummy;

	if (!mtrr_state.var_ranges) {
		mtrr_state.var_ranges = xmalloc_array(struct mtrr_var_range,
						  num_var_ranges);
		if (!mtrr_state.var_ranges)
			return;
	} 
	vrs = mtrr_state.var_ranges;

	rdmsr(MTRRcap_MSR, lo, dummy);
	mtrr_state.have_fixed = (lo >> 8) & 1;

	for (i = 0; i < num_var_ranges; i++)
		get_mtrr_var_range(i, &vrs[i]);
	if (mtrr_state.have_fixed)
		get_fixed_ranges(mtrr_state.fixed_ranges);

	rdmsr(MTRRdefType_MSR, lo, dummy);
	mtrr_state.def_type = (lo & 0xff);
	mtrr_state.enabled = (lo & 0xc00) >> 10;

	/* Store mtrr_cap for HVM MTRR virtualisation. */
	rdmsrl(MTRRcap_MSR, mtrr_state.mtrr_cap);
}

/*  Some BIOS's are fucked and don't set all MTRRs the same!  */
void __init mtrr_state_warn(void)
{
	unsigned long mask = smp_changes_mask;

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
}

/* Doesn't attempt to pass an error out to MTRR users
   because it's quite complicated in some cases and probably not
   worth it because the best error handling is to ignore it. */
void mtrr_wrmsr(unsigned int msr, uint64_t msr_content)
{
	if (wrmsr_safe(msr, msr_content) < 0)
		printk(KERN_ERR
			"MTRR: CPU %u: Writing MSR %x to %"PRIx64" failed\n",
			smp_processor_id(), msr, msr_content);
	/* Cache overlap status for efficient HVM MTRR virtualisation. */
	mtrr_state.overlapped = is_var_mtrr_overlapped(&mtrr_state);
}

/**
 * Enable and allow read/write of extended fixed-range MTRR bits on K8 CPUs
 * see AMD publication no. 24593, chapter 3.2.1 for more information
 */
static inline void k8_enable_fixed_iorrs(void)
{
	uint64_t msr_content;

	rdmsrl(MSR_K8_SYSCFG, msr_content);
	mtrr_wrmsr(MSR_K8_SYSCFG, msr_content 
				| K8_MTRRFIXRANGE_DRAM_ENABLE
				| K8_MTRRFIXRANGE_DRAM_MODIFY);
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
		if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		    boot_cpu_data.x86 == 15 &&
		    ((msrwords[0] | msrwords[1]) & K8_MTRR_RDMEM_WRMEM_MASK))
			k8_enable_fixed_iorrs();
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
	unsigned int mask_lo, mask_hi, base_lo, base_hi;

	rdmsr(MTRRphysMask_MSR(reg), mask_lo, mask_hi);
	if ((mask_lo & 0x800) == 0) {
		/*  Invalid (i.e. free) range  */
		*base = 0;
		*size = 0;
		*type = 0;
		return;
	}

	rdmsr(MTRRphysBase_MSR(reg), base_lo, base_hi);

	/* Work out the shifted address mask. */
	mask_lo = size_or_mask | mask_hi << (32 - PAGE_SHIFT)
	    | mask_lo >> PAGE_SHIFT;

	/* This works correctly if size is a power of two, i.e. a
	   contiguous range. */
	*size = -mask_lo;
	*base = base_hi << (32 - PAGE_SHIFT) | base_lo >> PAGE_SHIFT;
	*type = base_lo & 0xff;
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
	int changed = FALSE;

	rdmsr(MTRRphysBase_MSR(index), lo, hi);
	base_lo = (uint32_t)vr->base;
	base_hi = (uint32_t)(vr->base >> 32);

	lo &= 0xfffff0ffUL;
	base_lo &= 0xfffff0ffUL;
	hi &= size_and_mask >> (32 - PAGE_SHIFT);
	base_hi &= size_and_mask >> (32 - PAGE_SHIFT);

	if ((base_lo != lo) || (base_hi != hi)) {
		mtrr_wrmsr(MTRRphysBase_MSR(index), vr->base);
		changed = TRUE;
	}

	rdmsr(MTRRphysMask_MSR(index), lo, hi);
	mask_lo = (uint32_t)vr->mask;
	mask_hi = (uint32_t)(vr->mask >> 32);

	lo &= 0xfffff800UL;
	mask_lo &= 0xfffff800UL;
	hi &= size_and_mask >> (32 - PAGE_SHIFT);
	mask_hi &= size_and_mask >> (32 - PAGE_SHIFT);

	if ((mask_lo != lo) || (mask_hi != hi)) {
		mtrr_wrmsr(MTRRphysMask_MSR(index), vr->mask);
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
	rdmsrl(MTRRdefType_MSR, deftype);

	/*  Disable MTRRs, and set the default type to uncached  */
	mtrr_wrmsr(MTRRdefType_MSR, deftype & ~0xcff);
}

static void post_set(void)
{
	/*  Flush TLBs (no need to flush caches - they are disabled)  */
	flush_tlb_local();

	/* Intel (P6) standard MTRRs */
	mtrr_wrmsr(MTRRdefType_MSR, deftype);
		
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
		mtrr_wrmsr(MTRRphysMask_MSR(reg), 0);
		memset(vr, 0, sizeof(struct mtrr_var_range));
	} else {
		uint32_t base_lo, base_hi, mask_lo, mask_hi;

		base_lo = base << PAGE_SHIFT | type;
		base_hi = (base & size_and_mask) >> (32 - PAGE_SHIFT);
		mask_lo = -size << PAGE_SHIFT | 0x800;
		mask_hi = (-size & size_and_mask) >> (32 - PAGE_SHIFT);
		vr->base = ((uint64_t)base_hi << 32) | base_lo;
		vr->mask = ((uint64_t)mask_hi << 32) | mask_lo;

		mtrr_wrmsr(MTRRphysBase_MSR(reg), vr->base);
		mtrr_wrmsr(MTRRphysMask_MSR(reg), vr->mask);
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
			printk(KERN_WARNING "mtrr: base(0x%lx000) is not 4 MiB aligned\n", base);
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
		printk(KERN_WARNING "mtrr: base(0x%lx000) is not aligned on a size(0x%lx000) boundary\n",
		       base, size);
		return -EINVAL;
	}
	return 0;
}


static int generic_have_wrcomb(void)
{
	unsigned long config, dummy;
	rdmsr(MTRRcap_MSR, config, dummy);
	return (config & (1 << 10));
}

int positive_have_wrcomb(void)
{
	return 1;
}

/* generic structure...
 */
struct mtrr_ops generic_mtrr_ops = {
	.use_intel_if      = 1,
	.set_all	   = generic_set_all,
	.get               = generic_get_mtrr,
	.get_free_region   = generic_get_free_region,
	.set               = generic_set_mtrr,
	.validate_add_page = generic_validate_add_page,
	.have_wrcomb       = generic_have_wrcomb,
};
