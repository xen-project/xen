#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/bitops.h>
#include <xen/smp.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/i387.h>
#include <mach_apic.h>
#include <asm/hvm/support.h>
#include <asm/setup.h>

#include "cpu.h"

#define select_idle_routine(x) ((void)0)

#ifdef CONFIG_X86_INTEL_USERCOPY
/*
 * Alignment at which movsl is preferred for bulk memory copies.
 */
struct movsl_mask movsl_mask __read_mostly;
#endif

static unsigned int probe_intel_cpuid_faulting(void)
{
	uint64_t x;
	return !rdmsr_safe(MSR_INTEL_PLATFORM_INFO, x) && (x & (1u<<31));
}

static DEFINE_PER_CPU(bool_t, cpuid_faulting_enabled);
void set_cpuid_faulting(bool_t enable)
{
	uint32_t hi, lo;

	if (!cpu_has_cpuid_faulting ||
	    this_cpu(cpuid_faulting_enabled) == enable )
		return;

	rdmsr(MSR_INTEL_MISC_FEATURES_ENABLES, lo, hi);
	lo &= ~1;
	if (enable)
		lo |= 1;
	wrmsr(MSR_INTEL_MISC_FEATURES_ENABLES, lo, hi);

	this_cpu(cpuid_faulting_enabled) = enable;
}

/*
 * opt_cpuid_mask_ecx/edx: cpuid.1[ecx, edx] feature mask.
 * For example, E8400[Intel Core 2 Duo Processor series] ecx = 0x0008E3FD,
 * edx = 0xBFEBFBFF when executing CPUID.EAX = 1 normally. If you want to
 * 'rev down' to E8400, you can set these values in these Xen boot parameters.
 */
static void __devinit set_cpuidmask(const struct cpuinfo_x86 *c)
{
	u32 eax, edx;
	const char *extra = "";

	if (!~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx &
	       opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx &
               opt_cpuid_mask_xsave_eax))
		return;

	/* Only family 6 supports this feature  */
	switch ((c->x86 == 6) * c->x86_model) {
	case 0x17:
		if ((c->x86_mask & 0x0f) < 4)
			break;
		/* fall through */
	case 0x1d:
		wrmsr(MSR_INTEL_CPUID_FEATURE_MASK,
		      opt_cpuid_mask_ecx,
		      opt_cpuid_mask_edx);
		if (~(opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx))
			extra = "extended ";
		else if (~opt_cpuid_mask_xsave_eax)
			extra = "xsave ";
		else
			return;
		break;
/* 
 * CPU supports this feature if the processor signature meets the following:
 * (CPUID.(EAX=01h):EAX) > 000106A2h, or
 * (CPUID.(EAX=01h):EAX) == 000106Exh, 0002065xh, 000206Cxh, 000206Exh, or 000206Fxh
 *
 */
	case 0x1a:
		if ((c->x86_mask & 0x0f) <= 2)
			break;
		/* fall through */
	case 0x1e: case 0x1f:
	case 0x25: case 0x2c: case 0x2e: case 0x2f:
		wrmsr(MSR_INTEL_CPUID1_FEATURE_MASK,
		      opt_cpuid_mask_ecx,
		      opt_cpuid_mask_edx);
		wrmsr(MSR_INTEL_CPUID80000001_FEATURE_MASK,
		      opt_cpuid_mask_ext_ecx,
		      opt_cpuid_mask_ext_edx);
		if (!~opt_cpuid_mask_xsave_eax)
			return;
		extra = "xsave ";
		break;
	case 0x2a:
		wrmsr(MSR_INTEL_CPUID1_FEATURE_MASK_V2,
		      opt_cpuid_mask_ecx,
		      opt_cpuid_mask_edx);
		rdmsr(MSR_INTEL_CPUIDD_01_FEATURE_MASK, eax, edx);
		wrmsr(MSR_INTEL_CPUIDD_01_FEATURE_MASK,
		      opt_cpuid_mask_xsave_eax, edx);
		wrmsr(MSR_INTEL_CPUID80000001_FEATURE_MASK_V2,
		      opt_cpuid_mask_ext_ecx,
		      opt_cpuid_mask_ext_edx);
		return;
	}

	printk(XENLOG_ERR "Cannot set CPU %sfeature mask on CPU#%d\n",
	       extra, smp_processor_id());
}

void __devinit early_intel_workaround(struct cpuinfo_x86 *c)
{
	if (c->x86_vendor != X86_VENDOR_INTEL)
		return;
	/* Netburst reports 64 bytes clflush size, but does IO in 128 bytes */
	if (c->x86 == 15 && c->x86_cache_alignment == 64)
		c->x86_cache_alignment = 128;

	/* Unmask CPUID levels if masked: */
	if (c->x86 > 6 || (c->x86 == 6 && c->x86_model >= 0xd)) {
		u64 misc_enable;

		rdmsrl(MSR_IA32_MISC_ENABLE, misc_enable);

		if (misc_enable & MSR_IA32_MISC_ENABLE_LIMIT_CPUID) {
			misc_enable &= ~MSR_IA32_MISC_ENABLE_LIMIT_CPUID;
			wrmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
			c->cpuid_level = cpuid_eax(0);
			if (opt_cpu_info || c == &boot_cpu_data)
				printk(KERN_INFO "revised cpuid level: %d\n",
				       c->cpuid_level);
		}
	}
}

/*
 * P4 Xeon errata 037 workaround.
 * Hardware prefetcher may cause stale data to be loaded into the cache.
 */
static void __devinit Intel_errata_workarounds(struct cpuinfo_x86 *c)
{
	unsigned long lo, hi;

	if ((c->x86 == 15) && (c->x86_model == 1) && (c->x86_mask == 1)) {
		rdmsr (MSR_IA32_MISC_ENABLE, lo, hi);
		if ((lo & (1<<9)) == 0) {
			printk (KERN_INFO "CPU: C0 stepping P4 Xeon detected.\n");
			printk (KERN_INFO "CPU: Disabling hardware prefetching (Errata 037)\n");
			lo |= (1<<9);	/* Disable hw prefetching */
			wrmsr (MSR_IA32_MISC_ENABLE, lo, hi);
		}
	}
}


/*
 * find out the number of processor cores on the die
 */
static int __devinit num_cpu_cores(struct cpuinfo_x86 *c)
{
	unsigned int eax, ebx, ecx, edx;

	if (c->cpuid_level < 4)
		return 1;

	/* Intel has a non-standard dependency on %ecx for this CPUID level. */
	cpuid_count(4, 0, &eax, &ebx, &ecx, &edx);
	if (eax & 0x1f)
		return ((eax >> 26) + 1);
	else
		return 1;
}

static void __devinit init_intel(struct cpuinfo_x86 *c)
{
	unsigned int l2 = 0;
	char *p = NULL;

	/* Detect the extended topology information if available */
	detect_extended_topology(c);

	select_idle_routine(c);
	l2 = init_intel_cacheinfo(c);
	if (c->cpuid_level > 9) {
		unsigned eax = cpuid_eax(10);
		/* Check for version and the number of counters */
		if ((eax & 0xff) && (((eax>>8) & 0xff) > 1))
			set_bit(X86_FEATURE_ARCH_PERFMON, c->x86_capability);
	}

	/* SEP CPUID bug: Pentium Pro reports SEP but doesn't have it until model 3 mask 3 */
	if ((c->x86<<8 | c->x86_model<<4 | c->x86_mask) < 0x633)
		clear_bit(X86_FEATURE_SEP, c->x86_capability);

	/* Names for the Pentium II/Celeron processors 
	   detectable only by also checking the cache size.
	   Dixon is NOT a Celeron. */
	if (c->x86 == 6) {
		switch (c->x86_model) {
		case 5:
			if (c->x86_mask == 0) {
				if (l2 == 0)
					p = "Celeron (Covington)";
				else if (l2 == 256)
					p = "Mobile Pentium II (Dixon)";
			}
			break;
			
		case 6:
			if (l2 == 128)
				p = "Celeron (Mendocino)";
			else if (c->x86_mask == 0 || c->x86_mask == 5)
				p = "Celeron-A";
			break;
			
		case 8:
			if (l2 == 128)
				p = "Celeron (Coppermine)";
			break;
		}
	}

	if ( p )
		safe_strcpy(c->x86_model_id, p);

	if ( !cpu_has(c, X86_FEATURE_XTOPOLOGY) )
	{
		c->x86_max_cores = num_cpu_cores(c);
		detect_ht(c);
	}

	if (smp_processor_id() == 0) {
		if (probe_intel_cpuid_faulting())
			set_bit(X86_FEATURE_CPUID_FAULTING, c->x86_capability);
	} else if (boot_cpu_has(X86_FEATURE_CPUID_FAULTING)) {
		BUG_ON(!probe_intel_cpuid_faulting());
		set_bit(X86_FEATURE_CPUID_FAULTING, c->x86_capability);
	}

	if (!cpu_has_cpuid_faulting)
		set_cpuidmask(c);

	/* Work around errata */
	Intel_errata_workarounds(c);

#ifdef CONFIG_X86_INTEL_USERCOPY
	/*
	 * Set up the preferred alignment for movsl bulk memory moves
	 */
	switch (c->x86) {
	case 6:		/* PII/PIII only like movsl with 8-byte alignment */
		movsl_mask.mask = 7;
		break;
	case 15:	/* P4 is OK down to 8-byte alignment */
		movsl_mask.mask = 7;
		break;
	}
#endif

	if (c->x86 == 15)
		set_bit(X86_FEATURE_P4, c->x86_capability);
	if (c->x86 == 6) 
		set_bit(X86_FEATURE_P3, c->x86_capability);
	if ((c->x86 == 0xf && c->x86_model >= 0x03) ||
		(c->x86 == 0x6 && c->x86_model >= 0x0e))
		set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
	if (cpuid_edx(0x80000007) & (1u<<8)) {
		set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
		set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
		set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
	}
	if ((c->cpuid_level >= 0x00000006) &&
	    (cpuid_eax(0x00000006) & (1u<<2)))
		set_bit(X86_FEATURE_ARAT, c->x86_capability);
}


static unsigned int intel_size_cache(struct cpuinfo_x86 * c, unsigned int size)
{
	/* Intel PIII Tualatin. This comes in two flavours.
	 * One has 256kb of cache, the other 512. We have no way
	 * to determine which, so we use a boottime override
	 * for the 512kb model, and assume 256 otherwise.
	 */
	if ((c->x86 == 6) && (c->x86_model == 11) && (size == 0))
		size = 256;
	return size;
}

static struct cpu_dev intel_cpu_dev __cpuinitdata = {
	.c_vendor	= "Intel",
	.c_ident 	= { "GenuineIntel" },
	.c_models = {
		{ .vendor = X86_VENDOR_INTEL, .family = 6, .model_names =
		  { 
			  [0] = "Pentium Pro A-step",
			  [1] = "Pentium Pro", 
			  [3] = "Pentium II (Klamath)", 
			  [4] = "Pentium II (Deschutes)", 
			  [5] = "Pentium II (Deschutes)", 
			  [6] = "Mobile Pentium II",
			  [7] = "Pentium III (Katmai)", 
			  [8] = "Pentium III (Coppermine)", 
			  [10] = "Pentium III (Cascades)",
			  [11] = "Pentium III (Tualatin)",
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 15, .model_names =
		  {
			  [0] = "Pentium 4 (Unknown)",
			  [1] = "Pentium 4 (Willamette)",
			  [2] = "Pentium 4 (Northwood)",
			  [4] = "Pentium 4 (Foster)",
			  [5] = "Pentium 4 (Foster)",
		  }
		},
	},
	.c_init		= init_intel,
	.c_size_cache	= intel_size_cache,
};

int __init intel_cpu_init(void)
{
	cpu_devs[X86_VENDOR_INTEL] = &intel_cpu_dev;
	return 0;
}

// arch_initcall(intel_cpu_init);

