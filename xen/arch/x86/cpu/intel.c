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
	case 0x2a: case 0x2d:
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

