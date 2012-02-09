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
static char opt_famrev[14];
string_param("cpuid_mask_cpu", opt_famrev);

static inline void wrmsr_amd(unsigned int index, unsigned int lo, 
		unsigned int hi)
{
	asm volatile (
		"wrmsr"
		: /* No outputs */
		: "c" (index), "a" (lo), 
		"d" (hi), "D" (0x9c5a203a)
	);
}

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
	static enum { not_parsed, no_mask, set_mask } status;

	if (status == no_mask)
		return;

	if (status == set_mask)
		goto setmask;

	ASSERT((status == not_parsed) && (smp_processor_id() == 0));
	status = no_mask;

	if (~(opt_cpuid_mask_ecx & opt_cpuid_mask_edx &
	      opt_cpuid_mask_ext_ecx & opt_cpuid_mask_ext_edx)) {
		feat_ecx = opt_cpuid_mask_ecx;
		feat_edx = opt_cpuid_mask_edx;
		extfeat_ecx = opt_cpuid_mask_ext_ecx;
		extfeat_edx = opt_cpuid_mask_ext_edx;
	} else if (*opt_famrev == '\0') {
		return;
	} else if (!strcmp(opt_famrev, "fam_0f_rev_c")) {
		feat_ecx = AMD_FEATURES_K8_REV_C_ECX;
		feat_edx = AMD_FEATURES_K8_REV_C_EDX;
		extfeat_ecx = AMD_EXTFEATURES_K8_REV_C_ECX;
		extfeat_edx = AMD_EXTFEATURES_K8_REV_C_EDX;
	} else if (!strcmp(opt_famrev, "fam_0f_rev_d")) {
		feat_ecx = AMD_FEATURES_K8_REV_D_ECX;
		feat_edx = AMD_FEATURES_K8_REV_D_EDX;
		extfeat_ecx = AMD_EXTFEATURES_K8_REV_D_ECX;
		extfeat_edx = AMD_EXTFEATURES_K8_REV_D_EDX;
	} else if (!strcmp(opt_famrev, "fam_0f_rev_e")) {
		feat_ecx = AMD_FEATURES_K8_REV_E_ECX;
		feat_edx = AMD_FEATURES_K8_REV_E_EDX;
		extfeat_ecx = AMD_EXTFEATURES_K8_REV_E_ECX;
		extfeat_edx = AMD_EXTFEATURES_K8_REV_E_EDX;
	} else if (!strcmp(opt_famrev, "fam_0f_rev_f")) {
		feat_ecx = AMD_FEATURES_K8_REV_F_ECX;
		feat_edx = AMD_FEATURES_K8_REV_F_EDX;
		extfeat_ecx = AMD_EXTFEATURES_K8_REV_F_ECX;
		extfeat_edx = AMD_EXTFEATURES_K8_REV_F_EDX;
	} else if (!strcmp(opt_famrev, "fam_0f_rev_g")) {
		feat_ecx = AMD_FEATURES_K8_REV_G_ECX;
		feat_edx = AMD_FEATURES_K8_REV_G_EDX;
		extfeat_ecx = AMD_EXTFEATURES_K8_REV_G_ECX;
		extfeat_edx = AMD_EXTFEATURES_K8_REV_G_EDX;
	} else if (!strcmp(opt_famrev, "fam_10_rev_b")) {
		feat_ecx = AMD_FEATURES_FAM10h_REV_B_ECX;
		feat_edx = AMD_FEATURES_FAM10h_REV_B_EDX;
		extfeat_ecx = AMD_EXTFEATURES_FAM10h_REV_B_ECX;
		extfeat_edx = AMD_EXTFEATURES_FAM10h_REV_B_EDX;
	} else if (!strcmp(opt_famrev, "fam_10_rev_c")) {
		feat_ecx = AMD_FEATURES_FAM10h_REV_C_ECX;
		feat_edx = AMD_FEATURES_FAM10h_REV_C_EDX;
		extfeat_ecx = AMD_EXTFEATURES_FAM10h_REV_C_ECX;
		extfeat_edx = AMD_EXTFEATURES_FAM10h_REV_C_EDX;
	} else if (!strcmp(opt_famrev, "fam_11_rev_b")) {
		feat_ecx = AMD_FEATURES_FAM11h_REV_B_ECX;
		feat_edx = AMD_FEATURES_FAM11h_REV_B_EDX;
		extfeat_ecx = AMD_EXTFEATURES_FAM11h_REV_B_ECX;
		extfeat_edx = AMD_EXTFEATURES_FAM11h_REV_B_EDX;
	} else {
		printk("Invalid processor string: %s\n", opt_famrev);
		printk("CPUID will not be masked\n");
		return;
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

 setmask:
	/* FIXME check if processor supports CPUID masking */
	/* AMD processors prior to family 10h required a 32-bit password */
	if (c->x86 >= 0x10) {
		wrmsr(MSR_K8_FEATURE_MASK, feat_edx, feat_ecx);
		wrmsr(MSR_K8_EXT_FEATURE_MASK, extfeat_edx, extfeat_ecx);
	} else if (c->x86 == 0x0f) {
		wrmsr_amd(MSR_K8_FEATURE_MASK, feat_edx, feat_ecx);
		wrmsr_amd(MSR_K8_EXT_FEATURE_MASK, extfeat_edx, extfeat_ecx);
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
	if (c->x86 < 0xf) {
		/*
		 * TSC drift doesn't exist on 7th Gen or less
		 * However, OS still needs to consider effects
		 * of P-state changes on TSC
		 */
		return 0;
	} else if (cpuid_edx(0x80000007) & (1<<8)) {
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
#ifdef CONFIG_X86_HT
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
#endif
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
	
#ifdef CONFIG_X86_64
	if (c->x86 == 0xf && c->x86_model < 0x14
	    && cpu_has(c, X86_FEATURE_LAHF_LM)) {
		/*
		 * Some BIOSes incorrectly force this feature, but only K8
		 * revision D (model = 0x14) and later actually support it.
		 * (AMD Erratum #110, docId: 25759).
		 */
		unsigned int lo, hi;

		clear_bit(X86_FEATURE_LAHF_LM, c->x86_capability);
		if (!rdmsr_amd_safe(0xc001100d, &lo, &hi)) {
			hi &= ~1;
			wrmsr_amd_safe(0xc001100d, lo, hi);
		}
	}
#endif

	switch(c->x86)
	{
	case 6: /* An Athlon/Duron */
 
		/* Bit 15 of Athlon specific MSR 15, needs to be 0
		 * to enable SSE on Palomino/Morgan/Barton CPU's.
		 * If the BIOS didn't enable it already, enable it here.
		 */
		if (c->x86_model >= 6 && c->x86_model <= 10) {
			if (!cpu_has(c, X86_FEATURE_XMM)) {
				printk(KERN_INFO "Enabling disabled K7/SSE Support.\n");
				rdmsr(MSR_K7_HWCR, l, h);
				l &= ~0x00008000;
				wrmsr(MSR_K7_HWCR, l, h);
				set_bit(X86_FEATURE_XMM, c->x86_capability);
			}
		}

		/* It's been determined by AMD that Athlons since model 8 stepping 1
		 * are more robust with CLK_CTL set to 200xxxxx instead of 600xxxxx
		 * As per AMD technical note 27212 0.2
		 */
		if ((c->x86_model == 8 && c->x86_mask>=1) || (c->x86_model > 8)) {
			rdmsr(MSR_K7_CLK_CTL, l, h);
			if ((l & 0xfff00000) != 0x20000000) {
				printk ("CPU: CLK_CTL MSR was %x. Reprogramming to %x\n", l,
					((l & 0x000fffff)|0x20000000));
				wrmsr(MSR_K7_CLK_CTL, (l & 0x000fffff)|0x20000000, h);
			}
		}
		set_bit(X86_FEATURE_K7, c->x86_capability);
		break;

	case 0xf:
	/* Use K8 tuning for Fam10h and Fam11h */
	case 0x10 ... 0x17:
		set_bit(X86_FEATURE_K8, c->x86_capability);
		disable_c1e(NULL);
		if (acpi_smi_cmd && (acpi_enable_value | acpi_disable_value))
			pv_post_outb_hook = check_disable_c1e;
		break;
	}

	display_cacheinfo(c);

	if (cpuid_eax(0x80000000) >= 0x80000008) {
		c->x86_max_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;
	}

	if (cpuid_eax(0x80000000) >= 0x80000007) {
		c->x86_power = cpuid_edx(0x80000007);
		if (c->x86_power & (1<<8)) {
			set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
			set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
			if (c->x86 != 0x11)
				set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
		}
	}

        amd_get_topology(c);

	/* Pointless to use MWAIT on Family10 as it does not deep sleep. */
	if (c->x86 >= 0x10 && !force_mwait)
		clear_bit(X86_FEATURE_MWAIT, c->x86_capability);

#ifdef __x86_64__
	/* AMD CPUs do not support SYSENTER outside of legacy mode. */
	clear_bit(X86_FEATURE_SEP, c->x86_capability);

	if (c->x86 == 0x10) {
		/* do this for boot cpu */
		if (c == &boot_cpu_data)
			check_enable_amd_mmconf_dmi();

		fam10h_check_enable_mmcfg();
	}
#endif

	/*
	 * Family 0x12 and above processors have APIC timer
	 * running in deep C states.
	 */
	if (c->x86 > 0x11)
		set_bit(X86_FEATURE_ARAT, c->x86_capability);

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

static struct cpu_dev amd_cpu_dev __cpuinitdata = {
	.c_vendor	= "AMD",
	.c_ident 	= { "AuthenticAMD" },
	.c_init		= init_amd,
	.c_identify	= generic_identify,
};

int __init amd_init_cpu(void)
{
	cpu_devs[X86_VENDOR_AMD] = &amd_cpu_dev;
	return 0;
}
