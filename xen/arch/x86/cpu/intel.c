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

static unsigned int probe_intel_cpuid_faulting(void)
{
	uint64_t x;
	return !rdmsr_safe(MSR_INTEL_PLATFORM_INFO, x) &&
		(x & MSR_PLATFORM_INFO_CPUID_FAULTING);
}

static DEFINE_PER_CPU(bool_t, cpuid_faulting_enabled);
void set_cpuid_faulting(bool_t enable)
{
	uint32_t hi, lo;

	if (!cpu_has_cpuid_faulting ||
	    this_cpu(cpuid_faulting_enabled) == enable )
		return;

	rdmsr(MSR_INTEL_MISC_FEATURES_ENABLES, lo, hi);
	lo &= ~MSR_MISC_FEATURES_CPUID_FAULTING;
	if (enable)
		lo |= MSR_MISC_FEATURES_CPUID_FAULTING;
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
	static unsigned int msr_basic, msr_ext, msr_xsave;
	static enum { not_parsed, no_mask, set_mask } status;
	u64 msr_val;

	if (status == no_mask)
		return;

	if (status == set_mask)
		goto setmask;

	ASSERT((status == not_parsed) && (c == &boot_cpu_data));
	status = no_mask;

	if (!~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx &
	       opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx &
	       opt_cpuid_mask_xsave_eax))
		return;

	/* Only family 6 supports this feature. */
	if (c->x86 != 6) {
		printk("No CPUID feature masking support available\n");
		return;
	}

	switch (c->x86_model) {
	case 0x17: /* Yorkfield, Wolfdale, Penryn, Harpertown(DP) */
	case 0x1d: /* Dunnington(MP) */
		msr_basic = MSR_INTEL_MASK_V1_CPUID1;
		break;

	case 0x1a: /* Bloomfield, Nehalem-EP(Gainestown) */
	case 0x1e: /* Clarksfield, Lynnfield, Jasper Forest */
	case 0x1f: /* Something Nehalem-based - perhaps Auburndale/Havendale? */
	case 0x25: /* Arrandale, Clarksdale */
	case 0x2c: /* Gulftown, Westmere-EP */
	case 0x2e: /* Nehalem-EX(Beckton) */
	case 0x2f: /* Westmere-EX */
		msr_basic = MSR_INTEL_MASK_V2_CPUID1;
		msr_ext   = MSR_INTEL_MASK_V2_CPUID80000001;
		break;

	case 0x2a: /* SandyBridge */
	case 0x2d: /* SandyBridge-E, SandyBridge-EN, SandyBridge-EP */
		msr_basic = MSR_INTEL_MASK_V3_CPUID1;
		msr_ext   = MSR_INTEL_MASK_V3_CPUID80000001;
		msr_xsave = MSR_INTEL_MASK_V3_CPUIDD_01;
		break;
	}

	status = set_mask;

	if (~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx)) {
		if (msr_basic)
			printk("Writing CPUID feature mask ecx:edx -> %08x:%08x\n",
			       opt_cpuid_mask_ecx, opt_cpuid_mask_edx);
		else
			printk("No CPUID feature mask available\n");
	}
	else
		msr_basic = 0;

	if (~(opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx)) {
		if (msr_ext)
			printk("Writing CPUID extended feature mask ecx:edx -> %08x:%08x\n",
			       opt_cpuid_mask_ext_ecx, opt_cpuid_mask_ext_edx);
		else
			printk("No CPUID extended feature mask available\n");
	}
	else
		msr_ext = 0;

	if (~opt_cpuid_mask_xsave_eax) {
		if (msr_xsave)
			printk("Writing CPUID xsave feature mask eax -> %08x\n",
			       opt_cpuid_mask_xsave_eax);
		else
			printk("No CPUID xsave feature mask available\n");
	}
	else
		msr_xsave = 0;

 setmask:
	if (msr_basic &&
	    wrmsr_safe(msr_basic,
		       ((u64)opt_cpuid_mask_edx << 32) | opt_cpuid_mask_ecx)){
		msr_basic = 0;
		printk("Failed to set CPUID feature mask\n");
	}

	if (msr_ext &&
	    wrmsr_safe(msr_ext,
		       ((u64)opt_cpuid_mask_ext_edx << 32) | opt_cpuid_mask_ext_ecx)){
		msr_ext = 0;
		printk("Failed to set CPUID extended feature mask\n");
	}

	if (msr_xsave &&
	    (rdmsr_safe(msr_xsave, msr_val) ||
	     wrmsr_safe(msr_xsave,
			(msr_val & (~0ULL << 32)) | opt_cpuid_mask_xsave_eax))){
		msr_xsave = 0;
		printk("Failed to set CPUID xsave feature mask\n");
	}
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

	/* CPUID workaround for Intel 0F33/0F34 CPU */
	if (boot_cpu_data.x86 == 0xF && boot_cpu_data.x86_model == 3 &&
	    (boot_cpu_data.x86_mask == 3 || boot_cpu_data.x86_mask == 4))
		paddr_bits = 36;
}

/*
 * P4 Xeon errata 037 workaround.
 * Hardware prefetcher may cause stale data to be loaded into the cache.
 *
 * Xeon 7400 erratum AAI65 (and further newer Xeons)
 * MONITOR/MWAIT may have excessive false wakeups
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

	if (c->x86 == 6 && cpu_has_clflush &&
	    (c->x86_model == 29 || c->x86_model == 46 || c->x86_model == 47))
		set_bit(X86_FEATURE_CLFLUSH_MONITOR, c->x86_capability);
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

	if ( !cpu_has(c, X86_FEATURE_XTOPOLOGY) )
	{
		c->x86_max_cores = num_cpu_cores(c);
		detect_ht(c);
	}

	if (c == &boot_cpu_data && c->x86 == 6) {
		if (probe_intel_cpuid_faulting())
			set_bit(X86_FEATURE_CPUID_FAULTING, c->x86_capability);
	} else if (boot_cpu_has(X86_FEATURE_CPUID_FAULTING)) {
		BUG_ON(!probe_intel_cpuid_faulting());
		set_bit(X86_FEATURE_CPUID_FAULTING, c->x86_capability);
	}

	if (!cpu_has_cpuid_faulting)
		set_cpuidmask(c);
	else if ((c == &boot_cpu_data) &&
		 (~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx &
		    opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx &
		    opt_cpuid_mask_xsave_eax)))
		printk("No CPUID feature masking support available\n");

	/* Work around errata */
	Intel_errata_workarounds(c);

	if ((c->x86 == 0xf && c->x86_model >= 0x03) ||
		(c->x86 == 0x6 && c->x86_model >= 0x0e))
		set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
	if (cpuid_edx(0x80000007) & (1u<<8)) {
		set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
		set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
		set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
	}
	if ( opt_arat &&
	     ( c->cpuid_level >= 0x00000006 ) &&
	     ( cpuid_eax(0x00000006) & (1u<<2) ) )
		set_bit(X86_FEATURE_ARAT, c->x86_capability);
}

static struct cpu_dev intel_cpu_dev __cpuinitdata = {
	.c_vendor	= "Intel",
	.c_ident 	= { "GenuineIntel" },
	.c_init		= init_intel,
};

int __init intel_cpu_init(void)
{
	cpu_devs[X86_VENDOR_INTEL] = &intel_cpu_dev;
	return 0;
}

// arch_initcall(intel_cpu_init);

