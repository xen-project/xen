#include <xen/config.h>
#include <xen/init.h>
#include <xen/bitops.h>
#include <xen/mm.h>
#include <xen/smp.h>
#include <xen/pci.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/amd.h>
#include <asm/hvm/support.h>
#include <asm/setup.h> /* amd_init_cpu */
#include <asm/acpi.h>
#include <asm/apic.h>

#include "cpu.h"

/*
 * Pre-canned values for overriding the CPUID features 
 * and extended features masks.
 *
 * Currently supported processors:
 * 
 * "fam_0f_rev_c"
 * "fam_0f_rev_d"
 * "fam_0f_rev_e"
 * "fam_0f_rev_f"
 * "fam_0f_rev_g"
 * "fam_10_rev_b"
 * "fam_10_rev_c"
 * "fam_11_rev_b"
 */
static char __initdata opt_famrev[14];
string_param("cpuid_mask_cpu", opt_famrev);

static unsigned int __initdata opt_cpuid_mask_l7s0_eax = ~0u;
integer_param("cpuid_mask_l7s0_eax", opt_cpuid_mask_l7s0_eax);
static unsigned int __initdata opt_cpuid_mask_l7s0_ebx = ~0u;
integer_param("cpuid_mask_l7s0_ebx", opt_cpuid_mask_l7s0_ebx);

static unsigned int __initdata opt_cpuid_mask_thermal_ecx = ~0u;
integer_param("cpuid_mask_thermal_ecx", opt_cpuid_mask_thermal_ecx);

/* 1 = allow, 0 = don't allow guest creation, -1 = don't allow boot */
s8 __read_mostly opt_allow_unsafe;
boolean_param("allow_unsafe", opt_allow_unsafe);

static inline int rdmsr_amd_safe(unsigned int msr, unsigned int *lo,
				 unsigned int *hi)
{
	int err;

	asm volatile("1: rdmsr\n2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3: movl %6,%2\n"
		     "   jmp 2b\n"
		     ".previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : "=a" (*lo), "=d" (*hi), "=r" (err)
		     : "c" (msr), "D" (0x9c5a203a), "2" (0), "i" (-EFAULT));

	return err;
}

static inline int wrmsr_amd_safe(unsigned int msr, unsigned int lo,
				 unsigned int hi)
{
	int err;

	asm volatile("1: wrmsr\n2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3: movl %6,%0\n"
		     "   jmp 2b\n"
		     ".previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : "=r" (err)
		     : "c" (msr), "a" (lo), "d" (hi), "D" (0x9c5a203a),
		       "0" (0), "i" (-EFAULT));

	return err;
}

static const struct cpuidmask {
	uint16_t fam;
	char rev[2];
	unsigned int ecx, edx, ext_ecx, ext_edx;
} pre_canned[] __initconst = {
#define CAN(fam, id, rev) { \
		fam, #rev, \
		AMD_FEATURES_##id##_REV_##rev##_ECX, \
		AMD_FEATURES_##id##_REV_##rev##_EDX, \
		AMD_EXTFEATURES_##id##_REV_##rev##_ECX, \
		AMD_EXTFEATURES_##id##_REV_##rev##_EDX \
	}
#define CAN_FAM(fam, rev) CAN(0x##fam, FAM##fam##h, rev)
#define CAN_K8(rev)       CAN(0x0f,    K8,          rev)
	CAN_FAM(11, B),
	CAN_FAM(10, C),
	CAN_FAM(10, B),
	CAN_K8(G),
	CAN_K8(F),
	CAN_K8(E),
	CAN_K8(D),
	CAN_K8(C)
#undef CAN
};

static const struct cpuidmask *__init noinline get_cpuidmask(const char *opt)
{
	unsigned long fam;
	char rev;
	unsigned int i;

	if (strncmp(opt, "fam_", 4))
		return NULL;
	fam = simple_strtoul(opt + 4, &opt, 16);
	if (strncmp(opt, "_rev_", 5) || !opt[5] || opt[6])
		return NULL;
	rev = toupper(opt[5]);

	for (i = 0; i < ARRAY_SIZE(pre_canned); ++i)
		if (fam == pre_canned[i].fam && rev == *pre_canned[i].rev)
			return &pre_canned[i];

	return NULL;
}

/*
 * Mask the features and extended features returned by CPUID.  Parameters are
 * set from the boot line via two methods:
 *
 *   1) Specific processor revision string
 *   2) User-defined masks
 *
 * The processor revision string parameter has precedene.
 */
static void __devinit set_cpuidmask(const struct cpuinfo_x86 *c)
{
	static unsigned int feat_ecx, feat_edx;
	static unsigned int extfeat_ecx, extfeat_edx;
	static unsigned int l7s0_eax, l7s0_ebx;
	static unsigned int thermal_ecx;
	static bool_t skip_feat, skip_extfeat;
	static bool_t skip_l7s0_eax_ebx, skip_thermal_ecx;
	static enum { not_parsed, no_mask, set_mask } status;
	unsigned int eax, ebx, ecx, edx;

	if (status == no_mask)
		return;

	if (status == set_mask)
		goto setmask;

	ASSERT((status == not_parsed) && (c == &boot_cpu_data));
	status = no_mask;

	/* Fam11 doesn't support masking at all. */
	if (c->x86 == 0x11)
		return;

	if (~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx &
	      opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx &
	      opt_cpuid_mask_l7s0_eax & opt_cpuid_mask_l7s0_ebx &
	      opt_cpuid_mask_thermal_ecx)) {
		feat_ecx = opt_cpuid_mask_ecx;
		feat_edx = opt_cpuid_mask_edx;
		extfeat_ecx = opt_cpuid_mask_ext_ecx;
		extfeat_edx = opt_cpuid_mask_ext_edx;
		l7s0_eax = opt_cpuid_mask_l7s0_eax;
		l7s0_ebx = opt_cpuid_mask_l7s0_ebx;
		thermal_ecx = opt_cpuid_mask_thermal_ecx;
	} else if (*opt_famrev == '\0') {
		return;
	} else {
		const struct cpuidmask *m = get_cpuidmask(opt_famrev);

		if (!m) {
			printk("Invalid processor string: %s\n", opt_famrev);
			printk("CPUID will not be masked\n");
			return;
		}
		feat_ecx = m->ecx;
		feat_edx = m->edx;
		extfeat_ecx = m->ext_ecx;
		extfeat_edx = m->ext_edx;
	}

        /* Setting bits in the CPUID mask MSR that are not set in the
         * unmasked CPUID response can cause those bits to be set in the
         * masked response.  Avoid that by explicitly masking in software. */
        feat_ecx &= cpuid_ecx(0x00000001);
        feat_edx &= cpuid_edx(0x00000001);
        extfeat_ecx &= cpuid_ecx(0x80000001);
        extfeat_edx &= cpuid_edx(0x80000001);

	status = set_mask;
	printk("Writing CPUID feature mask ECX:EDX -> %08Xh:%08Xh\n", 
	       feat_ecx, feat_edx);
	printk("Writing CPUID extended feature mask ECX:EDX -> %08Xh:%08Xh\n", 
	       extfeat_ecx, extfeat_edx);

	if (c->cpuid_level >= 7)
		cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
	else
		ebx = eax = 0;
	if ((eax | ebx) && ~(l7s0_eax & l7s0_ebx)) {
		if (l7s0_eax > eax)
			l7s0_eax = eax;
		l7s0_ebx &= ebx;
		printk("Writing CPUID leaf 7 subleaf 0 feature mask EAX:EBX -> %08Xh:%08Xh\n",
		       l7s0_eax, l7s0_ebx);
	} else
		skip_l7s0_eax_ebx = 1;

	/* Only Fam15 has the respective MSR. */
	ecx = c->x86 == 0x15 && c->cpuid_level >= 6 ? cpuid_ecx(6) : 0;
	if (ecx && ~thermal_ecx) {
		thermal_ecx &= ecx;
		printk("Writing CPUID thermal/power feature mask ECX -> %08Xh\n",
		       thermal_ecx);
	} else
		skip_thermal_ecx = 1;

 setmask:
	/* AMD processors prior to family 10h required a 32-bit password */
	if (!skip_feat &&
	    wrmsr_amd_safe(MSR_K8_FEATURE_MASK, feat_edx, feat_ecx)) {
		skip_feat = 1;
		printk("Failed to set CPUID feature mask\n");
	}

	if (!skip_extfeat &&
	    wrmsr_amd_safe(MSR_K8_EXT_FEATURE_MASK, extfeat_edx, extfeat_ecx)) {
		skip_extfeat = 1;
		printk("Failed to set CPUID extended feature mask\n");
	}

	if (!skip_l7s0_eax_ebx &&
	    wrmsr_amd_safe(MSR_AMD_L7S0_FEATURE_MASK, l7s0_ebx, l7s0_eax)) {
		skip_l7s0_eax_ebx = 1;
		printk("Failed to set CPUID leaf 7 subleaf 0 feature mask\n");
	}

	if (!skip_thermal_ecx &&
	    (rdmsr_amd_safe(MSR_AMD_THRM_FEATURE_MASK, &eax, &edx) ||
	     wrmsr_amd_safe(MSR_AMD_THRM_FEATURE_MASK, thermal_ecx, edx))){
		skip_thermal_ecx = 1;
		printk("Failed to set CPUID thermal/power feature mask\n");
	}
}

/*
 * Check for the presence of an AMD erratum. Arguments are defined in amd.h 
 * for each known erratum. Return 1 if erratum is found.
 */
int cpu_has_amd_erratum(const struct cpuinfo_x86 *cpu, int osvw_id, ...)
{
	va_list ap;
	u32 range;
	u32 ms;
	
	if (cpu->x86_vendor != X86_VENDOR_AMD)
		return 0;

	if (osvw_id >= 0 && cpu_has(cpu, X86_FEATURE_OSVW)) {
		u64 osvw_len;

		rdmsrl(MSR_AMD_OSVW_ID_LENGTH, osvw_len);

		if (osvw_id < osvw_len) {
			u64 osvw_bits;

			rdmsrl(MSR_AMD_OSVW_STATUS + (osvw_id >> 6),
			       osvw_bits);

			return (osvw_bits >> (osvw_id & 0x3f)) & 1;
		}
	}

	/* OSVW unavailable or ID unknown, match family-model-stepping range */
	va_start(ap, osvw_id);

	ms = (cpu->x86_model << 4) | cpu->x86_mask;
	while ((range = va_arg(ap, int))) {
		if ((cpu->x86 == AMD_MODEL_RANGE_FAMILY(range)) &&
		    (ms >= AMD_MODEL_RANGE_START(range)) &&
		    (ms <= AMD_MODEL_RANGE_END(range))) {
			va_end(ap);
			return 1;
		}
	}

	va_end(ap);
	return 0;
}

/* Can this system suffer from TSC drift due to C1 clock ramping? */
static int c1_ramping_may_cause_clock_drift(struct cpuinfo_x86 *c) 
{ 
	if (cpuid_edx(0x80000007) & (1<<8)) {
		/*
		 * CPUID.AdvPowerMgmtInfo.TscInvariant
		 * EDX bit 8, 8000_0007
		 * Invariant TSC on 8th Gen or newer, use it
		 * (assume all cores have invariant TSC)
		 */
		return 0;
	}
	return 1;
}

/*
 * Disable C1-Clock ramping if enabled in PMM7.CpuLowPwrEnh on 8th-generation
 * cores only. Assume BIOS has setup all Northbridges equivalently.
 */
static void disable_c1_ramping(void) 
{
	u8 pmm7;
	int node, nr_nodes;

	/* Read the number of nodes from the first Northbridge. */
	nr_nodes = ((pci_conf_read32(0, 0, 0x18, 0x0, 0x60)>>4)&0x07)+1;
	for (node = 0; node < nr_nodes; node++) {
		/* PMM7: bus=0, dev=0x18+node, function=0x3, register=0x87. */
		pmm7 = pci_conf_read8(0, 0, 0x18+node, 0x3, 0x87);
		/* Invalid read means we've updated every Northbridge. */
		if (pmm7 == 0xFF)
			break;
		pmm7 &= 0xFC; /* clear pmm7[1:0] */
		pci_conf_write8(0, 0, 0x18+node, 0x3, 0x87, pmm7);
		printk ("AMD: Disabling C1 Clock Ramping Node #%x\n", node);
	}
}

int force_mwait __cpuinitdata;

static void disable_c1e(void *unused)
{
	uint64_t msr_content;

	/*
	 * Disable C1E mode, as the APIC timer stops in that mode.
	 * The MSR does not exist in all FamilyF CPUs (only Rev F and above),
	 * but we safely catch the #GP in that case.
	 */
	if ((rdmsr_safe(MSR_K8_ENABLE_C1E, msr_content) == 0) &&
	    (msr_content & (3ULL << 27)) &&
	    (wrmsr_safe(MSR_K8_ENABLE_C1E, msr_content & ~(3ULL << 27)) != 0))
		printk(KERN_ERR "Failed to disable C1E on CPU#%u (%16"PRIx64")\n",
		       smp_processor_id(), msr_content);
}

static void check_disable_c1e(unsigned int port, u8 value)
{
	/* C1E is sometimes enabled during entry to ACPI mode. */
	if ((port == acpi_smi_cmd) && (value == acpi_enable_value))
		on_each_cpu(disable_c1e, NULL, 1);
}

/*
 * BIOS is expected to clear MtrrFixDramModEn bit. According to AMD BKDG : 
 * "The MtrrFixDramModEn bit should be set to 1 during BIOS initalization of 
 * the fixed MTRRs, then cleared to 0 for operation."
 */
static void check_syscfg_dram_mod_en(void)
{
	uint64_t syscfg;
	static bool_t printed = 0;

	if (!((boot_cpu_data.x86_vendor == X86_VENDOR_AMD) &&
		(boot_cpu_data.x86 >= 0x0f)))
		return;

	rdmsrl(MSR_K8_SYSCFG, syscfg);
	if (!(syscfg & K8_MTRRFIXRANGE_DRAM_MODIFY))
		return;

	if (!test_and_set_bool(printed))
		printk(KERN_ERR "MTRR: SYSCFG[MtrrFixDramModEn] not "
			"cleared by BIOS, clearing this bit\n");

	syscfg &= ~K8_MTRRFIXRANGE_DRAM_MODIFY;
	wrmsrl(MSR_K8_SYSCFG, syscfg);
}

static void __devinit amd_get_topology(struct cpuinfo_x86 *c)
{
        int cpu;
        unsigned bits;

        if (c->x86_max_cores <= 1)
                return;
        /*
         * On a AMD multi core setup the lower bits of the APIC id
         * distingush the cores.
         */
        cpu = smp_processor_id();
        bits = (cpuid_ecx(0x80000008) >> 12) & 0xf;

        if (bits == 0) {
                while ((1 << bits) < c->x86_max_cores)
                        bits++;
        }

        /* Low order bits define the core id */
        c->cpu_core_id = c->phys_proc_id & ((1<<bits)-1);
        /* Convert local APIC ID into the socket ID */
        c->phys_proc_id >>= bits;
        /* Collect compute unit ID if available */
        if (cpu_has(c, X86_FEATURE_TOPOEXT)) {
                u32 eax, ebx, ecx, edx;

                cpuid(0x8000001e, &eax, &ebx, &ecx, &edx);
                c->compute_unit_id = ebx & 0xFF;
                c->x86_num_siblings = ((ebx >> 8) & 0x3) + 1;
        }
        
        if (opt_cpu_info)
                printk("CPU %d(%d) -> Processor %d, %s %d\n",
                       cpu, c->x86_max_cores, c->phys_proc_id,
                       cpu_has(c, X86_FEATURE_TOPOEXT) ? "Compute Unit" : 
                                                         "Core",
                       cpu_has(c, X86_FEATURE_TOPOEXT) ? c->compute_unit_id :
                                                         c->cpu_core_id);
}

static void __devinit init_amd(struct cpuinfo_x86 *c)
{
	u32 l, h;

	unsigned long long value;

	/* Disable TLB flush filter by setting HWCR.FFDIS on K8
	 * bit 6 of msr C001_0015
	 *
	 * Errata 63 for SH-B3 steppings
	 * Errata 122 for all steppings (F+ have it disabled by default)
	 */
	if (c->x86 == 15) {
		rdmsrl(MSR_K7_HWCR, value);
		value |= 1 << 6;
		wrmsrl(MSR_K7_HWCR, value);
	}

	/*
	 *	FIXME: We should handle the K5 here. Set up the write
	 *	range and also turn on MSR 83 bits 4 and 31 (write alloc,
	 *	no bus pipeline)
	 */

	/* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
	   3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
	clear_bit(0*32+31, c->x86_capability);
	
	if (c->x86 == 0xf && c->x86_model < 0x14
	    && cpu_has(c, X86_FEATURE_LAHF_LM)) {
		/*
		 * Some BIOSes incorrectly force this feature, but only K8
		 * revision D (model = 0x14) and later actually support it.
		 * (AMD Erratum #110, docId: 25759).
		 */
		clear_bit(X86_FEATURE_LAHF_LM, c->x86_capability);
		if (!rdmsr_amd_safe(0xc001100d, &l, &h))
			wrmsr_amd_safe(0xc001100d, l, h & ~1);
	}

	switch(c->x86)
	{
	case 0xf ... 0x17:
		disable_c1e(NULL);
		if (acpi_smi_cmd && (acpi_enable_value | acpi_disable_value))
			pv_post_outb_hook = check_disable_c1e;
		break;
	}

	display_cacheinfo(c);

	if (c->extended_cpuid_level >= 0x80000008) {
		c->x86_max_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;
	}

	if (c->extended_cpuid_level >= 0x80000007) {
		c->x86_power = cpuid_edx(0x80000007);
		if (c->x86_power & (1<<8)) {
			set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
			set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
			if (c->x86 != 0x11)
				set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
		}
	}

	/* re-enable TopologyExtensions if switched off by BIOS */
	if ((c->x86 == 0x15) &&
	    (c->x86_model >= 0x10) && (c->x86_model <= 0x1f) &&
	    !cpu_has(c, X86_FEATURE_TOPOEXT) &&
	    !rdmsr_safe(MSR_K8_EXT_FEATURE_MASK, value)) {
		value |= 1ULL << 54;
		wrmsr_safe(MSR_K8_EXT_FEATURE_MASK, value);
		rdmsrl(MSR_K8_EXT_FEATURE_MASK, value);
		if (value & (1ULL << 54)) {
			set_bit(X86_FEATURE_TOPOEXT, c->x86_capability);
			printk(KERN_INFO "CPU: Re-enabling disabled "
			       "Topology Extensions Support\n");
		}
	}

	/*
	 * The way access filter has a performance penalty on some workloads.
	 * Disable it on the affected CPUs.
	 */
	if (c->x86 == 0x15 && c->x86_model >= 0x02 && c->x86_model < 0x20 &&
	    !rdmsr_safe(MSR_AMD64_IC_CFG, value) && (value & 0x1e) != 0x1e)
		wrmsr_safe(MSR_AMD64_IC_CFG, value | 0x1e);

        amd_get_topology(c);

	/* Pointless to use MWAIT on Family10 as it does not deep sleep. */
	if (c->x86 >= 0x10 && !force_mwait)
		clear_bit(X86_FEATURE_MWAIT, c->x86_capability);

	if (!cpu_has_amd_erratum(c, AMD_ERRATUM_121))
		opt_allow_unsafe = 1;
	else if (opt_allow_unsafe < 0)
		panic("Xen will not boot on this CPU for security reasons"
		      "Pass \"allow_unsafe\" if you're trusting all your"
		      " (PV) guest kernels.\n");
	else if (!opt_allow_unsafe && c == &boot_cpu_data)
		printk(KERN_WARNING
		       "*** Xen will not allow creation of DomU-s on"
		       " this CPU for security reasons. ***\n"
		       KERN_WARNING
		       "*** Pass \"allow_unsafe\" if you're trusting"
		       " all your (PV) guest kernels. ***\n");

	if (c->x86 == 0x16 && c->x86_model <= 0xf) {
		if (c == &boot_cpu_data) {
			l = pci_conf_read32(0, 0, 0x18, 0x3, 0x58);
			h = pci_conf_read32(0, 0, 0x18, 0x3, 0x5c);
			if ((l & 0x1f) | (h & 0x1))
				printk(KERN_WARNING
				       "Applying workaround for erratum 792: %s%s%s\n",
				       (l & 0x1f) ? "clearing D18F3x58[4:0]" : "",
				       ((l & 0x1f) && (h & 0x1)) ? " and " : "",
				       (h & 0x1) ? "clearing D18F3x5C[0]" : "");

			if (l & 0x1f)
				pci_conf_write32(0, 0, 0x18, 0x3, 0x58,
						 l & ~0x1f);

			if (h & 0x1)
				pci_conf_write32(0, 0, 0x18, 0x3, 0x5c,
						 h & ~0x1);
		}

		rdmsrl(MSR_AMD64_LS_CFG, value);
		if (!(value & (1 << 15))) {
			static bool_t warned;

			if (c == &boot_cpu_data || opt_cpu_info ||
			    !test_and_set_bool(warned))
				printk(KERN_WARNING
				       "CPU%u: Applying workaround for erratum 793\n",
				       smp_processor_id());
			wrmsrl(MSR_AMD64_LS_CFG, value | (1 << 15));
		}
	}

	/* AMD CPUs do not support SYSENTER outside of legacy mode. */
	clear_bit(X86_FEATURE_SEP, c->x86_capability);

	if (c->x86 == 0x10) {
		/* do this for boot cpu */
		if (c == &boot_cpu_data)
			check_enable_amd_mmconf_dmi();

		fam10h_check_enable_mmcfg();

		/*
		 * On family 10h BIOS may not have properly enabled WC+
		 * support, causing it to be converted to CD memtype. This may
		 * result in performance degradation for certain nested-paging
		 * guests. Prevent this conversion by clearing bit 24 in
		 * MSR_F10_BU_CFG2.
		 */
		rdmsrl(MSR_F10_BU_CFG2, value);
		value &= ~(1ULL << 24);
		wrmsrl(MSR_F10_BU_CFG2, value);
	}

	/*
	 * Family 0x12 and above processors have APIC timer
	 * running in deep C states.
	 */
	if ( opt_arat && c->x86 > 0x11 )
		set_bit(X86_FEATURE_ARAT, c->x86_capability);

	/*
	 * Prior to Family 0x14, perf counters are not reset during warm reboot.
	 * We have to reset them manually.
	 */
	if (nmi_watchdog != NMI_LOCAL_APIC && c->x86 < 0x14) {
		wrmsrl(MSR_K7_PERFCTR0, 0);
		wrmsrl(MSR_K7_PERFCTR1, 0);
		wrmsrl(MSR_K7_PERFCTR2, 0);
		wrmsrl(MSR_K7_PERFCTR3, 0);
	}

	if (cpuid_edx(0x80000007) & (1 << 10)) {
		rdmsr(MSR_K7_HWCR, l, h);
		l |= (1 << 27); /* Enable read-only APERF/MPERF bit */
		wrmsr(MSR_K7_HWCR, l, h);
	}

	/* Prevent TSC drift in non single-processor, single-core platforms. */
	if ((smp_processor_id() == 1) && c1_ramping_may_cause_clock_drift(c))
		disable_c1_ramping();

	set_cpuidmask(c);

	check_syscfg_dram_mod_en();
}

static const struct cpu_dev amd_cpu_dev = {
	.c_vendor	= "AMD",
	.c_ident 	= { "AuthenticAMD" },
	.c_init		= init_amd,
};

int __init amd_init_cpu(void)
{
	cpu_devs[X86_VENDOR_AMD] = &amd_cpu_dev;
	return 0;
}
