#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/sched.h>
#include <xen/string.h>
#include <xen/bitops.h>
#include <xen/smp.h>

#include <asm/intel-family.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/i387.h>
#include <asm/trampoline.h>

#include "cpu.h"

/*
 * MSR_MCU_OPT_CTRL is a collection of unrelated functionality, with separate
 * enablement requirements, but which want to be consistent across the system.
 */
static uint32_t __read_mostly mcu_opt_ctrl_mask;
static uint32_t __read_mostly mcu_opt_ctrl_val;

void update_mcu_opt_ctrl(void)
{
    uint32_t mask = mcu_opt_ctrl_mask, lo, hi;

    if ( !mask )
        return;

    rdmsr(MSR_MCU_OPT_CTRL, lo, hi);

    lo &= ~mask;
    lo |= mcu_opt_ctrl_val;

    wrmsr(MSR_MCU_OPT_CTRL, lo, hi);
}

void __init set_in_mcu_opt_ctrl(uint32_t mask, uint32_t val)
{
    mcu_opt_ctrl_mask |= mask;

    mcu_opt_ctrl_val &= ~mask;
    mcu_opt_ctrl_val |= (val & mask);

    update_mcu_opt_ctrl();
}

/*
 * Processors which have self-snooping capability can handle conflicting
 * memory type across CPUs by snooping its own cache. However, there exists
 * CPU models in which having conflicting memory types still leads to
 * unpredictable behavior, machine check errors, or hangs. Clear this
 * feature to prevent its use on machines with known erratas.
 */
static void __init check_memory_type_self_snoop_errata(void)
{
	if (!boot_cpu_has(X86_FEATURE_SS))
		return;

	switch (boot_cpu_data.x86_model) {
	case 0x0f: /* Merom */
	case 0x16: /* Merom L */
	case 0x17: /* Penryn */
	case 0x1d: /* Dunnington */
	case 0x1e: /* Nehalem */
	case 0x1f: /* Auburndale / Havendale */
	case 0x1a: /* Nehalem EP */
	case 0x2e: /* Nehalem EX */
	case 0x25: /* Westmere */
	case 0x2c: /* Westmere EP */
	case 0x2a: /* SandyBridge */
		return;
	}

	setup_force_cpu_cap(X86_FEATURE_XEN_SELFSNOOP);
}

/*
 * Set caps in expected_levelling_cap, probe a specific masking MSR, and set
 * caps in levelling_caps if it is found, or clobber the MSR index if missing.
 * If preset, reads the default value into msr_val.
 */
static uint64_t __init _probe_mask_msr(unsigned int *msr, uint64_t caps)
{
	uint64_t val = 0;

	expected_levelling_cap |= caps;

	if (rdmsr_safe(*msr, val) || wrmsr_safe(*msr, val))
		*msr = 0;
	else
		levelling_caps |= caps;

	return val;
}

/* Indices of the masking MSRs, or 0 if unavailable. */
static unsigned int __read_mostly msr_basic, __read_mostly msr_ext,
	__read_mostly msr_xsave;

/*
 * Probe for the existance of the expected masking MSRs.  They might easily
 * not be available if Xen is running virtualised.
 */
static void __init probe_masking_msrs(void)
{
	const struct cpuinfo_x86 *c = &boot_cpu_data;
	unsigned int exp_msr_basic, exp_msr_ext, exp_msr_xsave;

	/* Only family 6 supports this feature. */
	if (c->x86 != 6)
		return;

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

	exp_msr_basic = msr_basic;
	exp_msr_ext   = msr_ext;
	exp_msr_xsave = msr_xsave;

	if (msr_basic)
		cpuidmask_defaults._1cd = _probe_mask_msr(&msr_basic, LCAP_1cd);

	if (msr_ext)
		cpuidmask_defaults.e1cd = _probe_mask_msr(&msr_ext, LCAP_e1cd);

	if (msr_xsave)
		cpuidmask_defaults.Da1 = _probe_mask_msr(&msr_xsave, LCAP_Da1);

	/*
	 * Don't bother warning about a mismatch if virtualised.  These MSRs
	 * are not architectural and almost never virtualised.
	 */
	if ((expected_levelling_cap == levelling_caps) ||
	    cpu_has_hypervisor)
		return;

	printk(XENLOG_WARNING "Mismatch between expected (%#x) "
	       "and real (%#x) levelling caps: missing %#x\n",
	       expected_levelling_cap, levelling_caps,
	       (expected_levelling_cap ^ levelling_caps) & levelling_caps);
	printk(XENLOG_WARNING "Fam %#x, model %#x expected (%#x/%#x/%#x), "
	       "got (%#x/%#x/%#x)\n", c->x86, c->x86_model,
	       exp_msr_basic, exp_msr_ext, exp_msr_xsave,
	       msr_basic, msr_ext, msr_xsave);
	printk(XENLOG_WARNING
	       "If not running virtualised, please report a bug\n");
}

/*
 * Context switch CPUID masking state to the next domain.  Only called if
 * CPUID Faulting isn't available, but masking MSRs have been detected.  A
 * parameter of NULL is used to context switch to the default host state (by
 * the cpu bringup-code, crash path, etc).
 */
static void cf_check intel_ctxt_switch_masking(const struct vcpu *next)
{
	struct cpuidmasks *these_masks = &this_cpu(cpuidmasks);
	const struct domain *nextd = next ? next->domain : NULL;
	const struct cpuidmasks *masks =
		(nextd && is_pv_domain(nextd) && nextd->arch.pv.cpuidmasks)
		? nextd->arch.pv.cpuidmasks : &cpuidmask_defaults;

        if (msr_basic) {
		uint64_t val = masks->_1cd;

		/*
		 * OSXSAVE defaults to 1, which causes fast-forwarding of
		 * Xen's real setting.  Clobber it if disabled by the guest
		 * kernel.
		 */
		if (next && is_pv_vcpu(next) && !is_idle_vcpu(next) &&
		    !(next->arch.pv.ctrlreg[4] & X86_CR4_OSXSAVE))
			val &= ~(uint64_t)cpufeat_mask(X86_FEATURE_OSXSAVE);

		if (unlikely(these_masks->_1cd != val)) {
			wrmsrl(msr_basic, val);
			these_masks->_1cd = val;
		}
        }

#define LAZY(msr, field)						\
	({								\
		if (unlikely(these_masks->field != masks->field) &&	\
		    (msr))						\
		{							\
			wrmsrl((msr), masks->field);			\
			these_masks->field = masks->field;		\
		}							\
	})

	LAZY(msr_ext,   e1cd);
	LAZY(msr_xsave, Da1);

#undef LAZY
}

#ifdef CONFIG_XEN_IBT /* Announce the function to ENDBR clobbering logic. */
static const typeof(ctxt_switch_masking) __initconst_cf_clobber __used csm =
    intel_ctxt_switch_masking;
#endif

/*
 * opt_cpuid_mask_ecx/edx: cpuid.1[ecx, edx] feature mask.
 * For example, E8400[Intel Core 2 Duo Processor series] ecx = 0x0008E3FD,
 * edx = 0xBFEBFBFF when executing CPUID.EAX = 1 normally. If you want to
 * 'rev down' to E8400, you can set these values in these Xen boot parameters.
 */
static void __init noinline intel_init_levelling(void)
{
	/*
	 * Intel Fam0f is old enough that probing for CPUID faulting support
	 * introduces spurious #GP(0) when the appropriate MSRs are read,
	 * so skip it altogether. In the case where Xen is virtualized these
	 * MSRs may be emulated though, so we allow it in that case.
	 */
	if ((boot_cpu_data.x86 != 0xf || cpu_has_hypervisor) &&
	    probe_cpuid_faulting()) {
		expected_levelling_cap |= LCAP_faulting;
		levelling_caps |= LCAP_faulting;
		return;
	}

	probe_masking_msrs();

	if (msr_basic) {
		uint32_t ecx, edx, tmp;

		cpuid(0x00000001, &tmp, &tmp, &ecx, &edx);

		ecx &= opt_cpuid_mask_ecx;
		edx &= opt_cpuid_mask_edx;

		/* Fast-forward bits - Must be set. */
		if (ecx & cpufeat_mask(X86_FEATURE_XSAVE))
			ecx |= cpufeat_mask(X86_FEATURE_OSXSAVE);
		edx |= cpufeat_mask(X86_FEATURE_APIC);

		cpuidmask_defaults._1cd &= ((u64)edx << 32) | ecx;
	}

	if (msr_ext) {
		uint32_t ecx, edx, tmp;

		cpuid(0x80000001, &tmp, &tmp, &ecx, &edx);

		ecx &= opt_cpuid_mask_ext_ecx;
		edx &= opt_cpuid_mask_ext_edx;

		cpuidmask_defaults.e1cd &= ((u64)edx << 32) | ecx;
	}

	if (msr_xsave) {
		uint32_t eax, tmp;

		cpuid_count(0x0000000d, 1, &eax, &tmp, &tmp, &tmp);

		eax &= opt_cpuid_mask_xsave_eax;

		cpuidmask_defaults.Da1 &= (~0ULL << 32) | eax;
	}

	if (opt_cpu_info) {
		printk(XENLOG_INFO "Levelling caps: %#x\n", levelling_caps);

		if (!cpu_has_cpuid_faulting)
			printk(XENLOG_INFO
			       "MSR defaults: 1d 0x%08x, 1c 0x%08x, e1d 0x%08x, "
			       "e1c 0x%08x, Da1 0x%08x\n",
			       (uint32_t)(cpuidmask_defaults._1cd >> 32),
			       (uint32_t)cpuidmask_defaults._1cd,
			       (uint32_t)(cpuidmask_defaults.e1cd >> 32),
			       (uint32_t)cpuidmask_defaults.e1cd,
			       (uint32_t)cpuidmask_defaults.Da1);
	}

	if (levelling_caps)
		ctxt_switch_masking = intel_ctxt_switch_masking;
}

/* Unmask CPUID levels if masked. */
void intel_unlock_cpuid_leaves(struct cpuinfo_x86 *c)
{
	uint64_t misc_enable, disable;

	rdmsrl(MSR_IA32_MISC_ENABLE, misc_enable);

	disable = misc_enable & MSR_IA32_MISC_ENABLE_LIMIT_CPUID;
	if (disable) {
		wrmsrl(MSR_IA32_MISC_ENABLE, misc_enable & ~disable);
		bootsym(trampoline_misc_enable_off) |= disable;
		c->cpuid_level = cpuid_eax(0);
		printk(KERN_INFO "revised cpuid level: %u\n", c->cpuid_level);
	}
}

static void cf_check early_init_intel(struct cpuinfo_x86 *c)
{
	/* Netburst reports 64 bytes clflush size, but does IO in 128 bytes */
	if (c->x86 == 15 && c->x86_cache_alignment == 64)
		c->x86_cache_alignment = 128;

	if (c == &boot_cpu_data &&
	    bootsym(trampoline_misc_enable_off) & MSR_IA32_MISC_ENABLE_XD_DISABLE)
		printk(KERN_INFO "re-enabled NX (Execute Disable) protection\n");

	intel_unlock_cpuid_leaves(c);

	/* CPUID workaround for Intel 0F33/0F34 CPU */
	if (boot_cpu_data.x86 == 0xF && boot_cpu_data.x86_model == 3 &&
	    (boot_cpu_data.x86_mask == 3 || boot_cpu_data.x86_mask == 4))
		paddr_bits = 36;

	if (c == &boot_cpu_data) {
		check_memory_type_self_snoop_errata();

		intel_init_levelling();
	}

	ctxt_switch_levelling(NULL);
}

/*
 * Errata BA80, AAK120, AAM108, AAO67, BD59, AAY54: Rapid Core C3/C6 Transition
 * May Cause Unpredictable System Behavior
 *
 * Under a complex set of internal conditions, cores rapidly performing C3/C6
 * transitions in a system with Intel Hyper-Threading Technology enabled may
 * cause a machine check error (IA32_MCi_STATUS.MCACOD = 0x0106), system hang
 * or unpredictable system behavior.
 */
static void probe_c3_errata(const struct cpuinfo_x86 *c)
{
#define INTEL_FAM6_MODEL(m) { X86_VENDOR_INTEL, 6, m, X86_FEATURE_ALWAYS }
    static const struct x86_cpu_id models[] = {
        /* Nehalem */
        INTEL_FAM6_MODEL(0x1a),
        INTEL_FAM6_MODEL(0x1e),
        INTEL_FAM6_MODEL(0x1f),
        INTEL_FAM6_MODEL(0x2e),
        /* Westmere (note Westmere-EX is not affected) */
        INTEL_FAM6_MODEL(0x2c),
        INTEL_FAM6_MODEL(0x25),
        { }
    };
#undef INTEL_FAM6_MODEL

    /* Serialized by the AP bringup code. */
    if ( max_cstate > 1 && (c->apicid & (c->x86_num_siblings - 1)) &&
         x86_match_cpu(models) )
    {
        printk(XENLOG_WARNING
	       "Disabling C-states C3 and C6 due to CPU errata\n");
        max_cstate = 1;
    }
}

/*
 * P4 Xeon errata 037 workaround.
 * Hardware prefetcher may cause stale data to be loaded into the cache.
 *
 * Xeon 7400 erratum AAI65 (and further newer Xeons)
 * MONITOR/MWAIT may have excessive false wakeups
 */
static void Intel_errata_workarounds(struct cpuinfo_x86 *c)
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
		__set_bit(X86_FEATURE_CLFLUSH_MONITOR, c->x86_capability);

	probe_c3_errata(c);
}


/*
 * find out the number of processor cores on the die
 */
static int num_cpu_cores(struct cpuinfo_x86 *c)
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

static void intel_log_freq(const struct cpuinfo_x86 *c)
{
    unsigned int eax, ebx, ecx, edx, factor;
    uint64_t msrval;
    uint8_t max_ratio, min_ratio;

    if ( c->cpuid_level >= 0x15 )
    {
        cpuid(0x15, &eax, &ebx, &ecx, &edx);
        if ( ecx && ebx && eax )
        {
            unsigned long long val = ecx;

            val *= ebx;
            printk("CPU%u: TSC: %u Hz * %u / %u = %Lu Hz\n",
                   smp_processor_id(), ecx, ebx, eax, val / eax);
        }
        else if ( ecx | eax | ebx )
        {
            printk("CPU%u: TSC:", smp_processor_id());
            if ( ecx )
                printk(" core: %u Hz", ecx);
            if ( ebx && eax )
                printk(" ratio: %u / %u", ebx, eax);
            printk("\n");
        }
    }

    if ( c->cpuid_level >= 0x16 )
    {
        cpuid(0x16, &eax, &ebx, &ecx, &edx);
        if ( ecx | eax | ebx )
        {
            printk("CPU%u:", smp_processor_id());
            if ( ecx )
                printk(" bus: %u MHz", ecx);
            if ( eax )
                printk(" base: %u MHz", eax);
            if ( ebx )
                printk(" max: %u MHz", ebx);
            printk("\n");
        }
    }

    switch ( c->x86 )
    {
        static const unsigned short core_factors[] =
            { 26667, 13333, 20000, 16667, 33333, 10000, 40000 };

    case 6:
        if ( rdmsr_safe(MSR_INTEL_PLATFORM_INFO, msrval) )
            return;
        max_ratio = msrval >> 8;
        min_ratio = msrval >> 40;
        if ( !max_ratio )
            return;

        switch ( c->x86_model )
        {
        case 0x0e: /* Core */
        case 0x0f: case 0x16: case 0x17: case 0x1d: /* Core2 */
            /*
             * PLATFORM_INFO, while not documented for these, appears to exist
             * in at least some cases, but what it holds doesn't match the
             * scheme used by newer CPUs.  At a guess, the min and max fields
             * look to be reversed, while the scaling factor is encoded in
             * FSB_FREQ.
             */
            if ( min_ratio > max_ratio )
                SWAP(min_ratio, max_ratio);
            if ( rdmsr_safe(MSR_FSB_FREQ, msrval) ||
                 (msrval &= 7) >= ARRAY_SIZE(core_factors) )
                return;
            factor = core_factors[msrval];
            break;

        case 0x1a: case 0x1e: case 0x1f: case 0x2e: /* Nehalem */
        case 0x25: case 0x2c: case 0x2f: /* Westmere */
            factor = 13333;
            break;

        default:
            factor = 10000;
            break;
        }
        break;

    case 0xf:
        if ( rdmsr_safe(MSR_IA32_EBC_FREQUENCY_ID, msrval) )
            return;
        max_ratio = msrval >> 24;
        min_ratio = 0;
        msrval >>= 16;
        if ( (msrval &= 7) > 4 )
            return;
        factor = core_factors[msrval];
        break;

    default:
        return;
    }

    printk("CPU%u: ", smp_processor_id());
    if ( min_ratio )
        printk("%u ... ", (factor * min_ratio + 50) / 100);
    printk("%u MHz\n", (factor * max_ratio + 50) / 100);
}

static void init_intel_perf(struct cpuinfo_x86 *c)
{
    uint64_t val;
    unsigned int eax, ver, nr_cnt;

    if ( c->cpuid_level <= 9 ||
         ({  rdmsrl(MSR_IA32_MISC_ENABLE, val);
             !(val & MSR_IA32_MISC_ENABLE_PERF_AVAIL); }) )
        return;

    eax = cpuid_eax(10);
    ver = eax & 0xff;
    nr_cnt = (eax >> 8) & 0xff;

    if ( ver && nr_cnt > 1 && nr_cnt <= 32 )
    {
        unsigned int cnt_mask = (1UL << nr_cnt) - 1;

        /*
         * On (some?) Sapphire/Emerald Rapids platforms each package-BSP
         * starts with all the enable bits for the general-purpose PMCs
         * cleared.  Adjust so counters can be enabled from EVNTSEL.
         */
        rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, val);

        if ( (val & cnt_mask) != cnt_mask )
        {
            printk("FIRMWARE BUG: CPU%u invalid PERF_GLOBAL_CTRL: %#"PRIx64" adjusting to %#"PRIx64"\n",
                   smp_processor_id(), val, val | cnt_mask);
            wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, val | cnt_mask);
        }

        __set_bit(X86_FEATURE_ARCH_PERFMON, c->x86_capability);
    }
}

static void cf_check init_intel(struct cpuinfo_x86 *c)
{
	/* Detect the extended topology information if available */
	detect_extended_topology(c);

	init_intel_cacheinfo(c);
	init_intel_perf(c);

	if ( !cpu_has(c, X86_FEATURE_XTOPOLOGY) )
	{
		c->x86_max_cores = num_cpu_cores(c);
		detect_ht(c);
	}

	/* Work around errata */
	Intel_errata_workarounds(c);

	if ((c->x86 == 0xf && c->x86_model >= 0x03) ||
		(c->x86 == 0x6 && c->x86_model >= 0x0e))
		__set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
	if (cpu_has(c, X86_FEATURE_ITSC)) {
		__set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
		__set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
		__set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
	}
	if ( opt_arat &&
	     ( c->cpuid_level >= 0x00000006 ) &&
	     ( cpuid_eax(0x00000006) & (1u<<2) ) )
		__set_bit(X86_FEATURE_ARAT, c->x86_capability);

	if ((opt_cpu_info && !(c->apicid & (c->x86_num_siblings - 1))) ||
	    c == &boot_cpu_data )
		intel_log_freq(c);

	/*
	 * The Gather Data Sampling microcode mitigation (August 2023) has an
	 * adverse performance impact on the CLWB instruction on SKX/CLX/CPX.
	 *
	 * On this model, CLWB has equivalent behaviour to CLFLUSHOPT but the
	 * latter is not impacted.  Hide CLWB to cause Xen to fall back to
	 * using CLFLUSHOPT instead.
	 */
	if (c == &boot_cpu_data &&
	    c->x86 == 6 && c->x86_model == INTEL_FAM6_SKYLAKE_X)
		setup_clear_cpu_cap(X86_FEATURE_CLWB);
}

const struct cpu_dev __initconst_cf_clobber intel_cpu_dev = {
	.c_early_init	= early_init_intel,
	.c_init		= init_intel,
};
