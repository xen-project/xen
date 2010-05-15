#include <xen/config.h>
#include <xen/init.h>
#include <xen/bitops.h>
#include <xen/mm.h>
#include <xen/smp.h>
#include <xen/pci.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/setup.h> /* amd_init_cpu */

#include "cpu.h"
#include "amd.h"

void start_svm(struct cpuinfo_x86 *c);

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

/* Finer-grained CPUID feature control. */
static unsigned int opt_cpuid_mask_ecx, opt_cpuid_mask_edx;
integer_param("cpuid_mask_ecx", opt_cpuid_mask_ecx);
integer_param("cpuid_mask_edx", opt_cpuid_mask_edx);
static unsigned int opt_cpuid_mask_ext_ecx, opt_cpuid_mask_ext_edx;
integer_param("cpuid_mask_ext_ecx", opt_cpuid_mask_ext_ecx);
integer_param("cpuid_mask_ext_edx", opt_cpuid_mask_ext_edx);

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

/*
 * Mask the features and extended features returned by CPUID.  Parameters are
 * set from the boot line via two methods:
 *
 *   1) Specific processor revision string
 *   2) User-defined masks
 *
 * The processor revision string parameter has precedene.
 */
static void __devinit set_cpuidmask(struct cpuinfo_x86 *c)
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

	if (opt_cpuid_mask_ecx | opt_cpuid_mask_edx |
	    opt_cpuid_mask_ext_ecx | opt_cpuid_mask_ext_edx) {
		feat_ecx = opt_cpuid_mask_ecx ? : ~0U;
		feat_edx = opt_cpuid_mask_edx ? : ~0U;
		extfeat_ecx = opt_cpuid_mask_ext_ecx ? : ~0U;
		extfeat_edx = opt_cpuid_mask_ext_edx ? : ~0U;
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
 * amd_flush_filter={on,off}. Forcibly Enable or disable the TLB flush
 * filter on AMD 64-bit processors.
 */
static int flush_filter_force;
static void flush_filter(char *s)
{
	if (!strcmp(s, "off"))
		flush_filter_force = -1;
	if (!strcmp(s, "on"))
		flush_filter_force = 1;
}
custom_param("amd_flush_filter", flush_filter);

#define num_physpages 0

/*
 *	B step AMD K6 before B 9730xxxx have hardware bugs that can cause
 *	misexecution of code under Linux. Owners of such processors should
 *	contact AMD for precise details and a CPU swap.
 *
 *	See	http://www.multimania.com/poulot/k6bug.html
 *		http://www.amd.com/K6/k6docs/revgd.html
 *
 *	The following test is erm.. interesting. AMD neglected to up
 *	the chip setting when fixing the bug but they also tweaked some
 *	performance at the same time..
 */
 
extern void vide(void);
__asm__(".text\n.align 4\nvide: ret");

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
	nr_nodes = ((pci_conf_read32(0, 0x18, 0x0, 0x60)>>4)&0x07)+1;
	for (node = 0; node < nr_nodes; node++) {
		/* PMM7: bus=0, dev=0x18+node, function=0x3, register=0x87. */
		pmm7 = pci_conf_read8(0, 0x18+node, 0x3, 0x87);
		/* Invalid read means we've updated every Northbridge. */
		if (pmm7 == 0xFF)
			break;
		pmm7 &= 0xFC; /* clear pmm7[1:0] */
		pci_conf_write8(0, 0x18+node, 0x3, 0x87, pmm7);
		printk ("AMD: Disabling C1 Clock Ramping Node #%x\n", node);
	}
}

int force_mwait __cpuinitdata;

static void disable_c1e(void *unused)
{
	u32 lo, hi;

	/*
	 * Disable C1E mode, as the APIC timer stops in that mode.
	 * The MSR does not exist in all FamilyF CPUs (only Rev F and above),
	 * but we safely catch the #GP in that case.
	 */
	if ((rdmsr_safe(MSR_K8_ENABLE_C1E, lo, hi) == 0) &&
	    (lo & (3u << 27)) &&
	    (wrmsr_safe(MSR_K8_ENABLE_C1E, lo & ~(3u << 27), hi) != 0))
		printk(KERN_ERR "Failed to disable C1E on CPU#%u (%08x)\n",
		       smp_processor_id(), lo);
}

static void check_disable_c1e(unsigned int port, u8 value)
{
	/* C1E is sometimes enabled during entry to ACPI mode. */
	if ((port == acpi_smi_cmd) && (value == acpi_enable_value))
		on_each_cpu(disable_c1e, NULL, 1);
}

static void __devinit init_amd(struct cpuinfo_x86 *c)
{
	u32 l, h;
	int mbytes = num_physpages >> (20-PAGE_SHIFT);
	int r;

#ifdef CONFIG_SMP
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
#endif

	/*
	 *	FIXME: We should handle the K5 here. Set up the write
	 *	range and also turn on MSR 83 bits 4 and 31 (write alloc,
	 *	no bus pipeline)
	 */

	/* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
	   3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
	clear_bit(0*32+31, c->x86_capability);
	
	r = get_model_name(c);

	switch(c->x86)
	{
		case 4:
		/*
		 * General Systems BIOSen alias the cpu frequency registers
		 * of the Elan at 0x000df000. Unfortuantly, one of the Linux
		 * drivers subsequently pokes it, and changes the CPU speed.
		 * Workaround : Remove the unneeded alias.
		 */
#define CBAR		(0xfffc) /* Configuration Base Address  (32-bit) */
#define CBAR_ENB	(0x80000000)
#define CBAR_KEY	(0X000000CB)
			if (c->x86_model==9 || c->x86_model == 10) {
				if (inl (CBAR) & CBAR_ENB)
					outl (0 | CBAR_KEY, CBAR);
			}
			break;
		case 5:
			if( c->x86_model < 6 )
			{
				/* Based on AMD doc 20734R - June 2000 */
				if ( c->x86_model == 0 ) {
					clear_bit(X86_FEATURE_APIC, c->x86_capability);
					set_bit(X86_FEATURE_PGE, c->x86_capability);
				}
				break;
			}
			
			if ( c->x86_model == 6 && c->x86_mask == 1 ) {
				const int K6_BUG_LOOP = 1000000;
				int n;
				void (*f_vide)(void);
				unsigned long d, d2;
				
				printk(KERN_INFO "AMD K6 stepping B detected - ");
				
				/*
				 * It looks like AMD fixed the 2.6.2 bug and improved indirect 
				 * calls at the same time.
				 */

				n = K6_BUG_LOOP;
				f_vide = vide;
				rdtscl(d);
				while (n--) 
					f_vide();
				rdtscl(d2);
				d = d2-d;

				if (d > 20*K6_BUG_LOOP) 
					printk("system stability may be impaired when more than 32 MB are used.\n");
				else 
					printk("probably OK (after B9730xxxx).\n");
				printk(KERN_INFO "Please see http://membres.lycos.fr/poulot/k6bug.html\n");
			}

			/* K6 with old style WHCR */
			if (c->x86_model < 8 ||
			   (c->x86_model== 8 && c->x86_mask < 8)) {
				/* We can only write allocate on the low 508Mb */
				if(mbytes>508)
					mbytes=508;

				rdmsr(MSR_K6_WHCR, l, h);
				if ((l&0x0000FFFF)==0) {
					unsigned long flags;
					l=(1<<0)|((mbytes/4)<<1);
					local_irq_save(flags);
					wbinvd();
					wrmsr(MSR_K6_WHCR, l, h);
					local_irq_restore(flags);
					printk(KERN_INFO "Enabling old style K6 write allocation for %d Mb\n",
						mbytes);
				}
				break;
			}

			if ((c->x86_model == 8 && c->x86_mask >7) ||
			     c->x86_model == 9 || c->x86_model == 13) {
				/* The more serious chips .. */

				if(mbytes>4092)
					mbytes=4092;

				rdmsr(MSR_K6_WHCR, l, h);
				if ((l&0xFFFF0000)==0) {
					unsigned long flags;
					l=((mbytes>>2)<<22)|(1<<16);
					local_irq_save(flags);
					wbinvd();
					wrmsr(MSR_K6_WHCR, l, h);
					local_irq_restore(flags);
					printk(KERN_INFO "Enabling new style K6 write allocation for %d Mb\n",
						mbytes);
				}

				/*  Set MTRR capability flag if appropriate */
				if (c->x86_model == 13 || c->x86_model == 9 ||
				   (c->x86_model == 8 && c->x86_mask >= 8))
					set_bit(X86_FEATURE_K6_MTRR, c->x86_capability);
				break;
			}

			if (c->x86_model == 10) {
				/* AMD Geode LX is model 10 */
				/* placeholder for any needed mods */
				break;
			}
			break;
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
			break;
	}

	switch (c->x86) {
	case 0xf:
	/* Use K8 tuning for Fam10h and Fam11h */
	case 0x10 ... 0x17:
		set_bit(X86_FEATURE_K8, c->x86_capability);
		disable_c1e(NULL);
		if (acpi_smi_cmd && (acpi_enable_value | acpi_disable_value))
			pv_post_outb_hook = check_disable_c1e;
		break;
	case 6:
		set_bit(X86_FEATURE_K7, c->x86_capability);
		break;
	}

	if (c->x86 == 15) {
		rdmsr(MSR_K7_HWCR, l, h);
		printk(KERN_INFO "CPU%d: AMD Flush Filter %sabled",
		       smp_processor_id(), (l & (1<<6)) ? "dis" : "en");
		if ((flush_filter_force > 0) && (l & (1<<6))) {
			l &= ~(1<<6);
			printk(" -> Forcibly enabled");
		} else if ((flush_filter_force < 0) && !(l & (1<<6))) {
			l |= 1<<6;
			printk(" -> Forcibly disabled");
		}
		wrmsr(MSR_K7_HWCR, l, h);
		printk("\n");
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

#ifdef CONFIG_X86_HT
	/*
	 * On a AMD multi core setup the lower bits of the APIC id
	 * distingush the cores.
	 */
	if (c->x86_max_cores > 1) {
		int cpu = smp_processor_id();
		unsigned bits = (cpuid_ecx(0x80000008) >> 12) & 0xf;

		if (bits == 0) {
			while ((1 << bits) < c->x86_max_cores)
				bits++;
		}
		cpu_core_id[cpu] = phys_proc_id[cpu] & ((1<<bits)-1);
		phys_proc_id[cpu] >>= bits;
		if (opt_cpu_info)
			printk("CPU %d(%d) -> Core %d\n",
			       cpu, c->x86_max_cores, cpu_core_id[cpu]);
	}
#endif

	/* Pointless to use MWAIT on Family10 as it does not deep sleep. */
	if (c->x86 >= 0x10 && !force_mwait)
		clear_bit(X86_FEATURE_MWAIT, c->x86_capability);

	/* K6s reports MCEs but don't actually have all the MSRs */
	if (c->x86 < 6)
		clear_bit(X86_FEATURE_MCE, c->x86_capability);

#ifdef __x86_64__
	/* AMD CPUs do not support SYSENTER outside of legacy mode. */
	clear_bit(X86_FEATURE_SEP, c->x86_capability);
#endif

	/* Prevent TSC drift in non single-processor, single-core platforms. */
	if ((smp_processor_id() == 1) && c1_ramping_may_cause_clock_drift(c))
		disable_c1_ramping();

	set_cpuidmask(c);

	start_svm(c);
}

static unsigned int __cpuinit amd_size_cache(struct cpuinfo_x86 * c, unsigned int size)
{
	/* AMD errata T13 (order #21922) */
	if ((c->x86 == 6)) {
		if (c->x86_model == 3 && c->x86_mask == 0)	/* Duron Rev A0 */
			size = 64;
		if (c->x86_model == 4 &&
		    (c->x86_mask==0 || c->x86_mask==1))	/* Tbird rev A1/A2 */
			size = 256;
	}
	return size;
}

static struct cpu_dev amd_cpu_dev __cpuinitdata = {
	.c_vendor	= "AMD",
	.c_ident 	= { "AuthenticAMD" },
	.c_models = {
		{ .vendor = X86_VENDOR_AMD, .family = 4, .model_names =
		  {
			  [3] = "486 DX/2",
			  [7] = "486 DX/2-WB",
			  [8] = "486 DX/4", 
			  [9] = "486 DX/4-WB", 
			  [14] = "Am5x86-WT",
			  [15] = "Am5x86-WB" 
		  }
		},
	},
	.c_init		= init_amd,
	.c_identify	= generic_identify,
	.c_size_cache	= amd_size_cache,
};

int __init amd_init_cpu(void)
{
	cpu_devs[X86_VENDOR_AMD] = &amd_cpu_dev;
	return 0;
}
