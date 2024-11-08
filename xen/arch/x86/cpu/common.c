#include <xen/init.h>
#include <xen/string.h>
#include <xen/delay.h>
#include <xen/param.h>
#include <xen/smp.h>

#include <asm/amd.h>
#include <asm/cpu-policy.h>
#include <asm/current.h>
#include <asm/debugreg.h>
#include <asm/processor.h>
#include <asm/xstate.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/prot-key.h>
#include <asm/random.h>
#include <asm/setup.h>
#include <asm/shstk.h>
#include <public/sysctl.h> /* for XEN_INVALID_{SOCKET,CORE}_ID */

#include "cpu.h"
#include "mcheck/x86_mca.h"

bool __read_mostly opt_dom0_cpuid_faulting = true;

bool opt_arat = true;
boolean_param("arat", opt_arat);

unsigned int opt_cpuid_mask_ecx = ~0u;
integer_param("cpuid_mask_ecx", opt_cpuid_mask_ecx);
unsigned int opt_cpuid_mask_edx = ~0u;
integer_param("cpuid_mask_edx", opt_cpuid_mask_edx);

unsigned int opt_cpuid_mask_xsave_eax = ~0u;
integer_param("cpuid_mask_xsave_eax", opt_cpuid_mask_xsave_eax);

unsigned int opt_cpuid_mask_ext_ecx = ~0u;
integer_param("cpuid_mask_ext_ecx", opt_cpuid_mask_ext_ecx);
unsigned int opt_cpuid_mask_ext_edx = ~0u;
integer_param("cpuid_mask_ext_edx", opt_cpuid_mask_ext_edx);

unsigned int __initdata expected_levelling_cap;
unsigned int __read_mostly levelling_caps;

DEFINE_PER_CPU(struct cpuidmasks, cpuidmasks);
struct cpuidmasks __read_mostly cpuidmask_defaults;

unsigned int paddr_bits __read_mostly = 36;
unsigned int hap_paddr_bits __read_mostly = 36;
unsigned int vaddr_bits __read_mostly = VADDR_BITS;

static unsigned int cleared_caps[NCAPINTS];
static unsigned int forced_caps[NCAPINTS];

DEFINE_PER_CPU(bool, full_gdt_loaded);

DEFINE_PER_CPU(uint32_t, pkrs);

void __init setup_clear_cpu_cap(unsigned int cap)
{
	const uint32_t *dfs;
	unsigned int i;

	if (__test_and_set_bit(cap, cleared_caps))
		return;

	if (test_bit(cap, forced_caps))
		printk("%pS clearing previously forced feature %#x\n",
		       __builtin_return_address(0), cap);

	__clear_bit(cap, boot_cpu_data.x86_capability);
	dfs = x86_cpu_policy_lookup_deep_deps(cap);

	if (!dfs)
		return;

	for (i = 0; i < FSCAPINTS; ++i) {
		cleared_caps[i] |= dfs[i];
		boot_cpu_data.x86_capability[i] &= ~dfs[i];
		if (!(forced_caps[i] & dfs[i]))
			continue;
		printk("%pS implicitly clearing previously forced feature(s) %u:%#x\n",
		       __builtin_return_address(0),
		       i, forced_caps[i] & dfs[i]);
	}
}

void __init setup_force_cpu_cap(unsigned int cap)
{
	if (__test_and_set_bit(cap, forced_caps))
		return;

	if (test_bit(cap, cleared_caps)) {
		printk("%pS tries to force previously cleared feature %#x\n",
		       __builtin_return_address(0), cap);
		return;
	}

	__set_bit(cap, boot_cpu_data.x86_capability);
}

bool __init is_forced_cpu_cap(unsigned int cap)
{
	return test_bit(cap, forced_caps);
}

static void cf_check default_init(struct cpuinfo_x86 * c)
{
	/* Not much we can do here... */
	__clear_bit(X86_FEATURE_SEP, c->x86_capability);
}

static const struct cpu_dev __initconst_cf_clobber __used default_cpu = {
	.c_init	= default_init,
};
static struct cpu_dev __ro_after_init actual_cpu;

static DEFINE_PER_CPU(uint64_t, msr_misc_features);
void (* __ro_after_init ctxt_switch_masking)(const struct vcpu *next);

bool __init probe_cpuid_faulting(void)
{
	uint64_t val;
	int rc;

	if ((rc = rdmsr_safe(MSR_INTEL_PLATFORM_INFO, val)) == 0)
		raw_cpu_policy.platform_info.cpuid_faulting =
			val & MSR_PLATFORM_INFO_CPUID_FAULTING;

	if (rc ||
	    !(val & MSR_PLATFORM_INFO_CPUID_FAULTING) ||
	    rdmsr_safe(MSR_INTEL_MISC_FEATURES_ENABLES,
		       this_cpu(msr_misc_features)))
	{
		setup_clear_cpu_cap(X86_FEATURE_CPUID_FAULTING);
		return false;
	}

	setup_force_cpu_cap(X86_FEATURE_CPUID_FAULTING);

	return true;
}

static void set_cpuid_faulting(bool enable)
{
	uint64_t *this_misc_features = &this_cpu(msr_misc_features);
	uint64_t val = *this_misc_features;

	if (!!(val & MSR_MISC_FEATURES_CPUID_FAULTING) == enable)
		return;

	val ^= MSR_MISC_FEATURES_CPUID_FAULTING;

	wrmsrl(MSR_INTEL_MISC_FEATURES_ENABLES, val);
	*this_misc_features = val;
}

void ctxt_switch_levelling(const struct vcpu *next)
{
	const struct domain *nextd = next ? next->domain : NULL;
	bool enable_cpuid_faulting;

	if (cpu_has_cpuid_faulting ||
	    boot_cpu_has(X86_FEATURE_CPUID_USER_DIS)) {
		/*
		 * No need to alter the faulting setting if we are switching
		 * to idle; it won't affect any code running in idle context.
		 */
		if (nextd && is_idle_domain(nextd))
			return;
		/*
		 * We *should* be enabling faulting for PV control domains.
		 *
		 * The domain builder has now been updated to not depend on
		 * seeing host CPUID values.  This makes it compatible with
		 * PVH toolstack domains, and lets us enable faulting by
		 * default for all PV domains.
		 *
		 * However, as PV control domains have never had faulting
		 * enforced on them before, there might plausibly be other
		 * dependenices on host CPUID data.  Therefore, we have left
		 * an interim escape hatch in the form of
		 * `dom0=no-cpuid-faulting` to restore the older behaviour.
		 */
		enable_cpuid_faulting = nextd && (opt_dom0_cpuid_faulting ||
		                                  !is_control_domain(nextd) ||
		                                  !is_pv_domain(nextd)) &&
		                        (is_pv_domain(nextd) ||
		                         next->arch.msrs->
		                         misc_features_enables.cpuid_faulting);

		if (cpu_has_cpuid_faulting)
			set_cpuid_faulting(enable_cpuid_faulting);
		else
			amd_set_cpuid_user_dis(enable_cpuid_faulting);

		return;
	}

	if (ctxt_switch_masking)
		alternative_vcall(ctxt_switch_masking, next);
}

static void setup_doitm(void)
{
    uint64_t msr;

    if ( !cpu_has_doitm )
        return;

    /*
     * We don't currently enumerate DOITM to guests.  As a conseqeuence, guest
     * kernels will believe they're safe even when they are not.
     *
     * For now, set it unilaterally.  This prevents otherwise-correct crypto
     * code from becoming vulnerable to timing sidechannels.
     */

    rdmsrl(MSR_UARCH_MISC_CTRL, msr);
    msr |= UARCH_CTRL_DOITM;
    if ( !opt_dit )
        msr &= ~UARCH_CTRL_DOITM;
    wrmsrl(MSR_UARCH_MISC_CTRL, msr);
}

bool opt_cpu_info;
boolean_param("cpuinfo", opt_cpu_info);

int get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;
	char *p, *q;

	if (c->extended_cpuid_level < 0x80000004)
		return 0;

	v = (unsigned int *) c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;

	/* Intel chips right-justify this string for some dumb reason;
	   undo that brain damage */
	p = q = &c->x86_model_id[0];
	while ( *p == ' ' )
	     p++;
	if ( p != q ) {
	     while ( *p )
		  *q++ = *p++;
	     while ( q <= &c->x86_model_id[48] )
		  *q++ = '\0';	/* Zero-pad the rest */
	}

	return 1;
}


void display_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int dummy, ecx, edx, size;

	if (c->extended_cpuid_level >= 0x80000005) {
		cpuid(0x80000005, &dummy, &dummy, &ecx, &edx);
		if ((edx | ecx) >> 24) {
			if (opt_cpu_info)
				printk("CPU: L1 I cache %uK (%u bytes/line),"
				              " D cache %uK (%u bytes/line)\n",
				       edx >> 24, edx & 0xFF, ecx >> 24, ecx & 0xFF);
			c->x86_cache_size = (ecx >> 24) + (edx >> 24);
		}
	}

	if (c->extended_cpuid_level < 0x80000006)	/* Some chips just has a large L1. */
		return;

	cpuid(0x80000006, &dummy, &dummy, &ecx, &edx);

	size = ecx >> 16;
	if (size) {
		c->x86_cache_size = size;

		if (opt_cpu_info)
			printk("CPU: L2 Cache: %uK (%u bytes/line)\n",
			       size, ecx & 0xFF);
	}

	size = edx >> 18;
	if (size) {
		c->x86_cache_size = size * 512;

		if (opt_cpu_info)
			printk("CPU: L3 Cache: %uM (%u bytes/line)\n",
			       (size + (size & 1)) >> 1, edx & 0xFF);
	}
}

static inline u32 _phys_pkg_id(u32 cpuid_apic, int index_msb)
{
	return cpuid_apic >> index_msb;
}

/*
 * cpuid returns the value latched in the HW at reset, not the APIC ID
 * register's value.  For any box whose BIOS changes APIC IDs, like
 * clustered APIC systems, we must use get_apic_id().
 *
 * See Intel's IA-32 SW Dev's Manual Vol2 under CPUID.
 */
static inline u32 phys_pkg_id(u32 cpuid_apic, int index_msb)
{
	return _phys_pkg_id(get_apic_id(), index_msb);
}

/* Do minimum CPU detection early.
   Fields really needed: vendor, cpuid_level, family, model, mask, cache alignment.
   The others are not touched to avoid unwanted side effects.

   WARNING: this function is only called on the BP.  Don't add code here
   that is supposed to run on all CPUs. */
void __init early_cpu_init(bool verbose)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	u32 eax, ebx, ecx, edx;

	c->x86_cache_alignment = 32;

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level, &ebx, &ecx, &edx);
	*(u32 *)&c->x86_vendor_id[0] = ebx;
	*(u32 *)&c->x86_vendor_id[8] = ecx;
	*(u32 *)&c->x86_vendor_id[4] = edx;

	c->x86_vendor = x86_cpuid_lookup_vendor(ebx, ecx, edx);
	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:    intel_unlock_cpuid_leaves(c);
				  actual_cpu = intel_cpu_dev;    break;
	case X86_VENDOR_AMD:      actual_cpu = amd_cpu_dev;      break;
	case X86_VENDOR_CENTAUR:  actual_cpu = centaur_cpu_dev;  break;
	case X86_VENDOR_SHANGHAI: actual_cpu = shanghai_cpu_dev; break;
	case X86_VENDOR_HYGON:    actual_cpu = hygon_cpu_dev;    break;
	default:
		actual_cpu = default_cpu;
		if (!verbose)
			break;
		printk(XENLOG_ERR
		       "Unrecognised or unsupported CPU vendor '%.12s'\n",
		       c->x86_vendor_id);
	}

	cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
	c->x86 = get_cpu_family(eax, &c->x86_model, &c->x86_mask);

	edx &= ~cleared_caps[FEATURESET_1d];
	ecx &= ~cleared_caps[FEATURESET_1c];
	if (edx & cpufeat_mask(X86_FEATURE_CLFLUSH))
		c->x86_cache_alignment = ((ebx >> 8) & 0xff) * 8;
	/* Leaf 0x1 capabilities filled in early for Xen. */
	c->x86_capability[FEATURESET_1d] = edx;
	c->x86_capability[FEATURESET_1c] = ecx;

	if (verbose)
		printk(XENLOG_INFO
		       "CPU Vendor: %s, Family %u (%#x), "
		       "Model %u (%#x), Stepping %u (raw %08x)\n",
		       x86_cpuid_vendor_to_str(c->x86_vendor), c->x86,
		       c->x86, c->x86_model, c->x86_model, c->x86_mask,
		       eax);

	if (c->cpuid_level >= 7) {
		uint32_t max_subleaf;

		cpuid_count(7, 0, &max_subleaf, &ebx,
			    &c->x86_capability[FEATURESET_7c0],
			    &c->x86_capability[FEATURESET_7d0]);

		if (test_bit(X86_FEATURE_ARCH_CAPS, c->x86_capability))
			rdmsr(MSR_ARCH_CAPABILITIES,
			      c->x86_capability[FEATURESET_m10Al],
			      c->x86_capability[FEATURESET_m10Ah]);

		if (max_subleaf >= 1)
			cpuid_count(7, 1, &eax, &ebx, &ecx,
				    &c->x86_capability[FEATURESET_7d1]);
	}

	eax = cpuid_eax(0x80000000);
	if ((eax >> 16) == 0x8000 && eax >= 0x80000008) {
		ebx = eax >= 0x8000001f ? cpuid_ebx(0x8000001f) : 0;
		eax = cpuid_eax(0x80000008);

		paddr_bits = eax & 0xff;
		if (paddr_bits > PADDR_BITS)
			paddr_bits = PADDR_BITS;

		vaddr_bits = (eax >> 8) & 0xff;
		if (vaddr_bits > VADDR_BITS)
			vaddr_bits = VADDR_BITS;

		hap_paddr_bits = ((eax >> 16) & 0xff) ?: paddr_bits;
		if (hap_paddr_bits > PADDR_BITS)
			hap_paddr_bits = PADDR_BITS;

		/* Account for SME's physical address space reduction. */
		paddr_bits -= (ebx >> 6) & 0x3f;
	}

	if (!(c->x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON)))
		park_offline_cpus = opt_mce;

	initialize_cpu_data(0);
}

static void generic_identify(struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx, tmp;

	/* Get vendor name */
	cpuid(0, &c->cpuid_level, &ebx, &ecx, &edx);
	*(u32 *)&c->x86_vendor_id[0] = ebx;
	*(u32 *)&c->x86_vendor_id[8] = ecx;
	*(u32 *)&c->x86_vendor_id[4] = edx;

	c->x86_vendor = x86_cpuid_lookup_vendor(ebx, ecx, edx);
	if (boot_cpu_data.x86_vendor != c->x86_vendor)
		printk(XENLOG_ERR "CPU%u vendor %u mismatch against BSP %u\n",
		       smp_processor_id(), c->x86_vendor,
		       boot_cpu_data.x86_vendor);

	/* Initialize the standard set of capabilities */
	/* Note that the vendor-specific code below might override */

	/* Model and family information. */
	cpuid(1, &eax, &ebx, &ecx, &edx);
	c->x86 = get_cpu_family(eax, &c->x86_model, &c->x86_mask);
	c->apicid = phys_pkg_id((ebx >> 24) & 0xFF, 0);
	c->phys_proc_id = c->apicid;

	eax = cpuid_eax(0x80000000);
	if ((eax >> 16) == 0x8000)
		c->extended_cpuid_level = eax;

	/*
	 * These AMD-defined flags are out of place, but we need
	 * them early for the CPUID faulting probe code
	 */
	if (c->extended_cpuid_level >= 0x80000021)
		c->x86_capability[FEATURESET_e21a] = cpuid_eax(0x80000021);

	if (actual_cpu.c_early_init)
		alternative_vcall(actual_cpu.c_early_init, c);

	/* c_early_init() may have adjusted cpuid levels/features.  Reread. */
	c->cpuid_level = cpuid_eax(0);
	cpuid(1, &eax, &ebx,
	      &c->x86_capability[FEATURESET_1c],
	      &c->x86_capability[FEATURESET_1d]);

	if ( cpu_has(c, X86_FEATURE_CLFLUSH) )
		c->x86_clflush_size = ((ebx >> 8) & 0xff) * 8;

	if ( (c->cpuid_level >= CPUID_PM_LEAF) &&
	     (cpuid_ecx(CPUID_PM_LEAF) & CPUID6_ECX_APERFMPERF_CAPABILITY) )
		__set_bit(X86_FEATURE_APERFMPERF, c->x86_capability);

	/* AMD-defined flags: level 0x80000001 */
	if (c->extended_cpuid_level >= 0x80000001)
		cpuid(0x80000001, &tmp, &tmp,
		      &c->x86_capability[FEATURESET_e1c],
		      &c->x86_capability[FEATURESET_e1d]);

	if (c->extended_cpuid_level >= 0x80000004)
		get_model_name(c); /* Default name */
	if (c->extended_cpuid_level >= 0x80000007)
		c->x86_capability[FEATURESET_e7d] = cpuid_edx(0x80000007);
	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_capability[FEATURESET_e8b] = cpuid_ebx(0x80000008);
	if (c->extended_cpuid_level >= 0x80000021)
		c->x86_capability[FEATURESET_e21a] = cpuid_eax(0x80000021);

	/* Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 7) {
		uint32_t max_subleaf;

		cpuid_count(7, 0, &max_subleaf,
			    &c->x86_capability[FEATURESET_7b0],
			    &c->x86_capability[FEATURESET_7c0],
			    &c->x86_capability[FEATURESET_7d0]);
		if (max_subleaf >= 1)
			cpuid_count(7, 1,
				    &c->x86_capability[FEATURESET_7a1],
				    &c->x86_capability[FEATURESET_7b1],
				    &c->x86_capability[FEATURESET_7c1],
				    &c->x86_capability[FEATURESET_7d1]);
		if (max_subleaf >= 2)
			cpuid_count(7, 2,
				    &tmp, &tmp, &tmp,
				    &c->x86_capability[FEATURESET_7d2]);
	}

	if (c->cpuid_level >= 0xd)
		cpuid_count(0xd, 1,
			    &c->x86_capability[FEATURESET_Da1],
			    &tmp, &tmp, &tmp);

	if (test_bit(X86_FEATURE_ARCH_CAPS, c->x86_capability))
		rdmsr(MSR_ARCH_CAPABILITIES,
		      c->x86_capability[FEATURESET_m10Al],
		      c->x86_capability[FEATURESET_m10Ah]);
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void identify_cpu(struct cpuinfo_x86 *c)
{
	int i;

	c->x86_cache_size = -1;
	c->x86_model = c->x86_mask = 0;	/* So far unknown... */
	c->x86_model_id[0] = '\0';  /* Unset */
	c->x86_max_cores = 1;
	c->x86_num_siblings = 1;
	c->x86_clflush_size = 0;
	c->cpu_core_id = XEN_INVALID_CORE_ID;
	c->compute_unit_id = INVALID_CUID;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	generic_identify(c);

#ifdef NOISY_CAPS
	printk(KERN_DEBUG "CPU: After vendor identify, caps:");
	for (i = 0; i < NCAPINTS; i++)
		printk(" %08x", c->x86_capability[i]);
	printk("\n");
#endif

	/*
	 * Vendor-specific initialization.  In this section we
	 * canonicalize the feature flags, meaning if there are
	 * features a certain CPU supports which CPUID doesn't
	 * tell us, CPUID claiming incorrect flags, or other bugs,
	 * we handle them here.
	 *
	 * At the end of this section, c->x86_capability better
	 * indicate the features this CPU genuinely supports!
	 */
	if (actual_cpu.c_init)
		alternative_vcall(actual_cpu.c_init, c);

	/*
	 * The vendor-specific functions might have changed features.  Now
	 * we do "generic changes."
	 */
	for (i = 0; i < FSCAPINTS; ++i)
		c->x86_capability[i] &= known_features[i];

	for (i = 0 ; i < NCAPINTS ; ++i) {
		c->x86_capability[i] |= forced_caps[i];
		c->x86_capability[i] &= ~cleared_caps[i];
	}

	/* If the model name is still unset, do table lookup. */
	if ( !c->x86_model_id[0] ) {
		/* Last resort... */
		snprintf(c->x86_model_id, sizeof(c->x86_model_id),
			"%02x/%02x", c->x86_vendor, c->x86_model);
	}

	/* Now the feature flags better reflect actual CPU features! */

	xstate_init(c);

#ifdef NOISY_CAPS
	printk(KERN_DEBUG "CPU: After all inits, caps:");
	for (i = 0; i < NCAPINTS; i++)
		printk(" %08x", c->x86_capability[i]);
	printk("\n");
#endif

	/*
	 * If RDRAND is available, make an attempt to check that it actually
	 * (still) works.
	 */
	if (cpu_has(c, X86_FEATURE_RDRAND)) {
		unsigned int prev = 0;

		for (i = 0; i < 5; ++i)
		{
			unsigned int cur = arch_get_random();

			if (prev && cur != prev)
				break;
			prev = cur;
		}

		if (i >= 5)
			printk(XENLOG_WARNING "CPU%u: RDRAND appears to not work\n",
			       smp_processor_id());
	}

	if (system_state == SYS_STATE_resume)
		return;

	/*
	 * On SMP, boot_cpu_data holds the common feature set between
	 * all CPUs; so make sure that we indicate which features are
	 * common between the CPUs.  The first time this routine gets
	 * executed, c == &boot_cpu_data.
	 */
	if ( c != &boot_cpu_data ) {
		/* AND the already accumulated flags with these */
		for ( i = 0 ; i < NCAPINTS ; i++ )
			boot_cpu_data.x86_capability[i] &= c->x86_capability[i];

		mcheck_init(c, false);
	} else {
		mcheck_init(c, true);

		mtrr_bp_init();
	}

	setup_doitm();
}

/* leaf 0xb SMT level */
#define SMT_LEVEL       0

/* leaf 0xb sub-leaf types */
#define INVALID_TYPE    0
#define SMT_TYPE        1
#define CORE_TYPE       2

#define LEAFB_SUBTYPE(ecx)          (((ecx) >> 8) & 0xff)
#define BITS_SHIFT_NEXT_LEVEL(eax)  ((eax) & 0x1f)
#define LEVEL_MAX_SIBLINGS(ebx)     ((ebx) & 0xffff)

/*
 * Check for extended topology enumeration cpuid leaf 0xb and if it
 * exists, use it for cpu topology detection.
 */
bool detect_extended_topology(struct cpuinfo_x86 *c)
{
	unsigned int eax, ebx, ecx, edx, sub_index;
	unsigned int ht_mask_width, core_plus_mask_width;
	unsigned int core_select_mask, core_level_siblings;
	unsigned int initial_apicid;

	if ( c->cpuid_level < 0xb )
		return false;

	cpuid_count(0xb, SMT_LEVEL, &eax, &ebx, &ecx, &edx);

	/* Check if the cpuid leaf 0xb is actually implemented */
	if ( ebx == 0 || (LEAFB_SUBTYPE(ecx) != SMT_TYPE) )
		return false;

	__set_bit(X86_FEATURE_XTOPOLOGY, c->x86_capability);

	initial_apicid = edx;

	/* Populate HT related information from sub-leaf level 0 */
	core_plus_mask_width = ht_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);
	core_level_siblings = c->x86_num_siblings = 1u << ht_mask_width;

	sub_index = 1;
	do {
		cpuid_count(0xb, sub_index, &eax, &ebx, &ecx, &edx);

		/* Check for the Core type in the implemented sub leaves */
		if ( LEAFB_SUBTYPE(ecx) == CORE_TYPE ) {
			core_plus_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);
			core_level_siblings = 1u << core_plus_mask_width;
			break;
		}

		sub_index++;
	} while ( LEAFB_SUBTYPE(ecx) != INVALID_TYPE );

	core_select_mask = (~(~0u << core_plus_mask_width)) >> ht_mask_width;

	c->cpu_core_id = phys_pkg_id(initial_apicid, ht_mask_width)
		& core_select_mask;
	c->phys_proc_id = phys_pkg_id(initial_apicid, core_plus_mask_width);

	c->apicid = phys_pkg_id(initial_apicid, 0);
	c->x86_max_cores = (core_level_siblings / c->x86_num_siblings);

	if ( opt_cpu_info )
	{
		printk("CPU: Physical Processor ID: %d\n",
		       c->phys_proc_id);
		if ( c->x86_max_cores > 1 )
			printk("CPU: Processor Core ID: %d\n",
			       c->cpu_core_id);
	}

	return true;
}

void detect_ht(struct cpuinfo_x86 *c)
{
	u32 	eax, ebx, ecx, edx;
	int 	index_msb, core_bits;

	if (!cpu_has(c, X86_FEATURE_HTT) ||
	    cpu_has(c, X86_FEATURE_CMP_LEGACY) ||
	    cpu_has(c, X86_FEATURE_XTOPOLOGY))
		return;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	c->x86_num_siblings = (ebx & 0xff0000) >> 16;

	if (c->x86_num_siblings == 1) {
		printk(KERN_INFO  "CPU: Hyper-Threading is disabled\n");
	} else if (c->x86_num_siblings > 1 ) {
		index_msb = get_count_order(c->x86_num_siblings);
		c->phys_proc_id = phys_pkg_id((ebx >> 24) & 0xFF, index_msb);

		if (opt_cpu_info)
			printk("CPU: Physical Processor ID: %d\n",
			       c->phys_proc_id);

		c->x86_num_siblings = c->x86_num_siblings / c->x86_max_cores;

		index_msb = get_count_order(c->x86_num_siblings) ;

		core_bits = get_count_order(c->x86_max_cores);

		c->cpu_core_id = phys_pkg_id((ebx >> 24) & 0xFF, index_msb) &
					       ((1 << core_bits) - 1);

		if (opt_cpu_info && c->x86_max_cores > 1)
			printk("CPU: Processor Core ID: %d\n",
			       c->cpu_core_id);
	}
}

unsigned int __init apicid_to_socket(unsigned int apicid)
{
	unsigned int dummy;

	if (boot_cpu_has(X86_FEATURE_XTOPOLOGY)) {
		unsigned int eax, ecx, sub_index = 1, core_plus_mask_width;

		cpuid_count(0xb, SMT_LEVEL, &eax, &dummy, &dummy, &dummy);
		core_plus_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);
		do {
			cpuid_count(0xb, sub_index, &eax, &dummy, &ecx,
			            &dummy);

			if (LEAFB_SUBTYPE(ecx) == CORE_TYPE) {
				core_plus_mask_width =
					BITS_SHIFT_NEXT_LEVEL(eax);
				break;
			}

			sub_index++;
		} while (LEAFB_SUBTYPE(ecx) != INVALID_TYPE);

		return _phys_pkg_id(apicid, core_plus_mask_width);
	}

	if (boot_cpu_has(X86_FEATURE_HTT) &&
	    !boot_cpu_has(X86_FEATURE_CMP_LEGACY)) {
		unsigned int num_siblings = (cpuid_ebx(1) & 0xff0000) >> 16;

		if (num_siblings)
			return _phys_pkg_id(apicid,
			                    get_count_order(num_siblings));
	}

	return apicid;
}

void print_cpu_info(unsigned int cpu)
{
	const struct cpuinfo_x86 *c = cpu_data + cpu;
	const char *vendor = NULL;

	if (!opt_cpu_info)
		return;

	printk("CPU%u: ", cpu);

	vendor = x86_cpuid_vendor_to_str(c->x86_vendor);
	if (strncmp(c->x86_model_id, vendor, strlen(vendor)))
		printk("%s ", vendor);

	if (!c->x86_model_id[0])
		printk("%d86", c->x86);
	else
		printk("%s", c->x86_model_id);

	printk(" stepping %02x\n", c->x86_mask);
}

static cpumask_t cpu_initialized;

/*
 * Sets up system tables and descriptors.
 *
 * - Sets up TSS with stack pointers, including ISTs
 * - Inserts TSS selector into regular and compat GDTs
 * - Loads GDT, IDT, TR then null LDT
 * - Sets up IST references in the IDT
 */
void load_system_tables(void)
{
	unsigned int i, cpu = smp_processor_id();
	unsigned long stack_bottom = get_stack_bottom(),
		stack_top = stack_bottom & ~(STACK_SIZE - 1);
	/*
	 * NB: define tss_page as a local variable because clang 3.5 doesn't
	 * support using ARRAY_SIZE against per-cpu variables.
	 */
	struct tss_page *tss_page = &this_cpu(tss_page);

	/* The TSS may be live.	 Disuade any clever optimisations. */
	volatile struct tss64 *tss = &tss_page->tss;
	seg_desc_t *gdt =
		this_cpu(gdt) - FIRST_RESERVED_GDT_ENTRY;

	const struct desc_ptr gdtr = {
		.base = (unsigned long)gdt,
		.limit = LAST_RESERVED_GDT_BYTE,
	};
	const struct desc_ptr idtr = {
		.base = (unsigned long)idt_tables[cpu],
		.limit = (IDT_ENTRIES * sizeof(idt_entry_t)) - 1,
	};

	/*
	 * Set up the TSS.  Warning - may be live, and the NMI/#MC must remain
	 * valid on every instruction boundary.  (Note: these are all
	 * semantically ACCESS_ONCE() due to tss's volatile qualifier.)
	 *
	 * rsp0 refers to the primary stack.  #MC, NMI, #DB and #DF handlers
	 * each get their own stacks.  No IO Bitmap.
	 */
	tss->rsp0 = stack_bottom;
	tss->ist[IST_MCE - 1] = stack_top + (1 + IST_MCE) * PAGE_SIZE;
	tss->ist[IST_NMI - 1] = stack_top + (1 + IST_NMI) * PAGE_SIZE;
	tss->ist[IST_DB  - 1] = stack_top + (1 + IST_DB)  * PAGE_SIZE;
	/*
	 * Gross bodge.  The #DF handler uses the vm86 fields of cpu_user_regs
	 * beyond the hardware frame.  Adjust the stack entrypoint so this
	 * doesn't manifest as an OoB write which hits the guard page.
	 */
	tss->ist[IST_DF  - 1] = stack_top + (1 + IST_DF)  * PAGE_SIZE -
		(sizeof(struct cpu_user_regs) - offsetof(struct cpu_user_regs, es));
	tss->bitmap = IOBMP_INVALID_OFFSET;

	/* All other stack pointers poisioned. */
	for ( i = IST_MAX; i < ARRAY_SIZE(tss->ist); ++i )
		tss->ist[i] = 0x8600111111111111ul;
	tss->rsp1 = 0x8600111111111111ul;
	tss->rsp2 = 0x8600111111111111ul;

	/*
	 * Set up the shadow stack IST.  Used entries must point at the
	 * supervisor stack token.  Unused entries are poisoned.
	 *
	 * This IST Table may be live, and the NMI/#MC entries must
	 * remain valid on every instruction boundary, hence the
	 * volatile qualifier.
	 */
	if (cpu_has_xen_shstk) {
		volatile uint64_t *ist_ssp = tss_page->ist_ssp;
		unsigned long
			mce_ssp = stack_top + (IST_MCE * IST_SHSTK_SIZE) - 8,
			nmi_ssp = stack_top + (IST_NMI * IST_SHSTK_SIZE) - 8,
			db_ssp  = stack_top + (IST_DB  * IST_SHSTK_SIZE) - 8,
			df_ssp  = stack_top + (IST_DF  * IST_SHSTK_SIZE) - 8;

		ist_ssp[0] = 0x8600111111111111ul;
		ist_ssp[IST_MCE] = mce_ssp;
		ist_ssp[IST_NMI] = nmi_ssp;
		ist_ssp[IST_DB]	 = db_ssp;
		ist_ssp[IST_DF]	 = df_ssp;
		for ( i = IST_DF + 1; i < ARRAY_SIZE(tss_page->ist_ssp); ++i )
			ist_ssp[i] = 0x8600111111111111ul;

		if (IS_ENABLED(CONFIG_XEN_SHSTK) && rdssp() != SSP_NO_SHSTK) {
			/*
			 * Rewrite supervisor tokens when shadow stacks are
			 * active.  This resets any busy bits left across S3.
			 */
			wrss(mce_ssp, _p(mce_ssp));
			wrss(nmi_ssp, _p(nmi_ssp));
			wrss(db_ssp,  _p(db_ssp));
			wrss(df_ssp,  _p(df_ssp));
		}

		wrmsrl(MSR_INTERRUPT_SSP_TABLE, (unsigned long)ist_ssp);
	}

	BUILD_BUG_ON(sizeof(*tss) <= 0x67); /* Mandated by the architecture. */

	_set_tssldt_desc(gdt + TSS_ENTRY, (unsigned long)tss,
			 sizeof(*tss) - 1, SYS_DESC_tss_avail);
	if ( IS_ENABLED(CONFIG_PV32) )
		_set_tssldt_desc(
			this_cpu(compat_gdt) - FIRST_RESERVED_GDT_ENTRY + TSS_ENTRY,
			(unsigned long)tss, sizeof(*tss) - 1, SYS_DESC_tss_busy);

	per_cpu(full_gdt_loaded, cpu) = false;
	lgdt(&gdtr);
	lidt(&idtr);
	ltr(TSS_SELECTOR);
	lldt(0);

	enable_each_ist(idt_tables[cpu]);

	/*
	 * Bottom-of-stack must be 16-byte aligned!
	 *
	 * Defer checks until exception support is sufficiently set up.
	 */
	BUILD_BUG_ON((sizeof(struct cpu_info) -
		      offsetof(struct cpu_info, guest_cpu_user_regs.es)) & 0xf);
	BUG_ON(system_state != SYS_STATE_early_boot && (stack_bottom & 0xf));
}

static void skinit_enable_intr(void)
{
	uint64_t val;

	/*
	 * If the platform is performing a Secure Launch via SKINIT
	 * INIT_REDIRECTION flag will be active.
	 */
	if ( !cpu_has_skinit || rdmsr_safe(MSR_K8_VM_CR, val) ||
	     !(val & VM_CR_INIT_REDIRECTION) )
		return;

	ap_boot_method = AP_BOOT_SKINIT;

	/*
	 * We don't yet handle #SX.  Disable INIT_REDIRECTION first, before
	 * enabling GIF, so a pending INIT resets us, rather than causing a
	 * panic due to an unknown exception.
	 */
	wrmsrl(MSR_K8_VM_CR, val & ~VM_CR_INIT_REDIRECTION);
	asm volatile ( "stgi" ::: "memory" );
}

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void cpu_init(void)
{
	int cpu = smp_processor_id();

	if (cpumask_test_and_set_cpu(cpu, &cpu_initialized)) {
		printk(KERN_WARNING "CPU#%d already initialized!\n", cpu);
		for (;;) local_irq_enable();
	}
	if (opt_cpu_info)
		printk("Initializing CPU#%d\n", cpu);

	/* Install correct page table. */
	write_ptbase(current);

	/* Ensure FPU gets initialised for each domain. */
	stts();

	/* Reset debug registers: */
	write_debugreg(0, 0);
	write_debugreg(1, 0);
	write_debugreg(2, 0);
	write_debugreg(3, 0);
	write_debugreg(6, X86_DR6_DEFAULT);
	write_debugreg(7, X86_DR7_DEFAULT);

	if (cpu_has_pku)
		wrpkru(0);

	/*
	 * If the platform is performing a Secure Launch via SKINIT, GIF is
	 * clear to prevent external interrupts interfering with Secure
	 * Startup.  Re-enable all interrupts now that we are suitably set up.
	 *
	 * Refer to AMD APM Vol2 15.27 "Secure Startup with SKINIT".
	 */
	skinit_enable_intr();

	/* Enable NMIs.  Our loader (e.g. Tboot) may have left them disabled. */
	enable_nmis();
}

void cpu_uninit(unsigned int cpu)
{
	cpumask_clear_cpu(cpu, &cpu_initialized);
}

/*
 * x86_match_cpu - match the current CPU against an array of
 * x86_cpu_ids
 * @match: Pointer to array of x86_cpu_ids. Last entry terminated with
 *         {}.
 * Return the entry if the current CPU matches the entries in the
 * passed x86_cpu_id match table. Otherwise NULL.  The match table
 * contains vendor (X86_VENDOR_*), family, model and feature bits or
 * respective wildcard entries.
 *
 * A typical table entry would be to match a specific CPU
 * { X86_VENDOR_INTEL, 6, 0x12 }
 * or to match a specific CPU feature
 * { X86_FEATURE_MATCH(X86_FEATURE_FOOBAR) }
 *
 * This always matches against the boot cpu, assuming models and
features are
 * consistent over all CPUs.
 */
const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id table[])
{
	const struct x86_cpu_id *m;
	const struct cpuinfo_x86 *c = &boot_cpu_data;

	for (m = table; m->vendor | m->family | m->model | m->feature; m++) {
		if (c->x86_vendor != m->vendor)
			continue;
		if (c->x86 != m->family)
			continue;
		if (c->x86_model != m->model)
			continue;
		if (!cpu_has(c, m->feature))
			continue;
		return m;
	}
	return NULL;
}
