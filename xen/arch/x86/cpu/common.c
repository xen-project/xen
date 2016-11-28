#include <xen/config.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/delay.h>
#include <xen/smp.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/xstate.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <mach_apic.h>
#include <asm/setup.h>
#include <public/sysctl.h> /* for XEN_INVALID_{SOCKET,CORE}_ID */

#include "cpu.h"

bool_t opt_arat = 1;
boolean_param("arat", opt_arat);

/* pku: Flag to enable Memory Protection Keys (default on). */
static bool_t opt_pku = 1;
boolean_param("pku", opt_pku);

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

const struct cpu_dev *__read_mostly cpu_devs[X86_VENDOR_NUM] = {};

unsigned int paddr_bits __read_mostly = 36;
unsigned int hap_paddr_bits __read_mostly = 36;
unsigned int vaddr_bits __read_mostly = VADDR_BITS;

/*
 * Default host IA32_CR_PAT value to cover all memory types.
 * BIOS usually sets it to 0x07040600070406.
 */
u64 host_pat = 0x050100070406;

static unsigned int cleared_caps[NCAPINTS];

void __init setup_clear_cpu_cap(unsigned int cap)
{
	const uint32_t *dfs;
	unsigned int i;

	if (__test_and_set_bit(cap, cleared_caps))
		return;

	__clear_bit(cap, boot_cpu_data.x86_capability);
	dfs = lookup_deep_deps(cap);

	if (!dfs)
		return;

	for (i = 0; i < FSCAPINTS; ++i) {
		cleared_caps[i] |= dfs[i];
		boot_cpu_data.x86_capability[i] &= ~dfs[i];
	}
}

static void default_init(struct cpuinfo_x86 * c)
{
	/* Not much we can do here... */
	/* Check if at least it has cpuid */
	BUG_ON(c->cpuid_level == -1);
	__clear_bit(X86_FEATURE_SEP, c->x86_capability);
}

static const struct cpu_dev default_cpu = {
	.c_init	= default_init,
	.c_vendor = "Unknown",
};
static const struct cpu_dev *this_cpu = &default_cpu;

static void default_ctxt_switch_levelling(const struct vcpu *next)
{
	/* Nop */
}
void (* __read_mostly ctxt_switch_levelling)(const struct vcpu *next) =
	default_ctxt_switch_levelling;

bool_t opt_cpu_info;
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
	unsigned int dummy, ecx, edx, l2size;

	if (c->extended_cpuid_level >= 0x80000005) {
		cpuid(0x80000005, &dummy, &dummy, &ecx, &edx);
		if (opt_cpu_info)
			printk("CPU: L1 I cache %dK (%d bytes/line),"
			              " D cache %dK (%d bytes/line)\n",
			       edx>>24, edx&0xFF, ecx>>24, ecx&0xFF);
		c->x86_cache_size=(ecx>>24)+(edx>>24);	
	}

	if (c->extended_cpuid_level < 0x80000006)	/* Some chips just has a large L1. */
		return;

	ecx = cpuid_ecx(0x80000006);
	l2size = ecx >> 16;
	
	c->x86_cache_size = l2size;

	if (opt_cpu_info)
		printk("CPU: L2 Cache: %dK (%d bytes/line)\n",
		       l2size, ecx & 0xFF);
}

int get_cpu_vendor(const char v[], enum get_cpu_vendor mode)
{
	int i;
	static int printed;

	for (i = 0; i < X86_VENDOR_NUM; i++) {
		if (cpu_devs[i]) {
			if (!strcmp(v,cpu_devs[i]->c_ident[0]) ||
			    (cpu_devs[i]->c_ident[1] && 
			     !strcmp(v,cpu_devs[i]->c_ident[1]))) {
				this_cpu = cpu_devs[i];
				return i;
			}
		}
	}
	if (mode == gcv_guest)
		return X86_VENDOR_UNKNOWN;
	if (!printed) {
		printed++;
		printk(KERN_ERR "CPU: Vendor unknown, using generic init.\n");
		printk(KERN_ERR "CPU: Your system may be unstable.\n");
	}
	this_cpu = &default_cpu;

	return X86_VENDOR_UNKNOWN;
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
static void __init early_cpu_detect(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	u32 eax, ebx, ecx, edx;

	c->x86_cache_alignment = 32;

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);

	c->x86_vendor = get_cpu_vendor(c->x86_vendor_id, gcv_host);

	cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
	c->x86 = (eax >> 8) & 15;
	c->x86_model = (eax >> 4) & 15;
	if (c->x86 == 0xf)
		c->x86 += (eax >> 20) & 0xff;
	if (c->x86 >= 0x6)
		c->x86_model += ((eax >> 16) & 0xF) << 4;
	c->x86_mask = eax & 15;
	edx &= ~cleared_caps[cpufeat_word(X86_FEATURE_FPU)];
	ecx &= ~cleared_caps[cpufeat_word(X86_FEATURE_SSE3)];
	if (edx & cpufeat_mask(X86_FEATURE_CLFLUSH))
		c->x86_cache_alignment = ((ebx >> 8) & 0xff) * 8;
	/* Leaf 0x1 capabilities filled in early for Xen. */
	c->x86_capability[cpufeat_word(X86_FEATURE_FPU)] = edx;
	c->x86_capability[cpufeat_word(X86_FEATURE_SSE3)] = ecx;

	printk(XENLOG_INFO
	       "CPU Vendor: %s, Family %u (%#x), Model %u (%#x), Stepping %u (raw %08x)\n",
	       this_cpu->c_vendor, c->x86, c->x86,
	       c->x86_model, c->x86_model, c->x86_mask, eax);

	eax = cpuid_eax(0x80000000);
	if ((eax >> 16) == 0x8000 && eax >= 0x80000008) {
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
	}
}

static void generic_identify(struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx, tmp;

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);

	c->x86_vendor = get_cpu_vendor(c->x86_vendor_id, gcv_host);
	/* Initialize the standard set of capabilities */
	/* Note that the vendor-specific code below might override */

	/* Model and family information. */
	cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
	c->x86 = (eax >> 8) & 15;
	c->x86_model = (eax >> 4) & 15;
	if (c->x86 == 0xf)
		c->x86 += (eax >> 20) & 0xff;
	if (c->x86 >= 0x6)
		c->x86_model += ((eax >> 16) & 0xF) << 4;
	c->x86_mask = eax & 15;
	c->apicid = phys_pkg_id((ebx >> 24) & 0xFF, 0);
	c->phys_proc_id = c->apicid;

	if (this_cpu->c_early_init)
		this_cpu->c_early_init(c);

	/* c_early_init() may have adjusted cpuid levels/features.  Reread. */
	c->cpuid_level = cpuid_eax(0);
	cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
	c->x86_capability[cpufeat_word(X86_FEATURE_FPU)] = edx;
	c->x86_capability[cpufeat_word(X86_FEATURE_SSE3)] = ecx;

	if ( cpu_has(c, X86_FEATURE_CLFLUSH) )
		c->x86_clflush_size = ((ebx >> 8) & 0xff) * 8;

	if ( (c->cpuid_level >= CPUID_PM_LEAF) &&
	     (cpuid_ecx(CPUID_PM_LEAF) & CPUID6_ECX_APERFMPERF_CAPABILITY) )
		set_bit(X86_FEATURE_APERFMPERF, c->x86_capability);

	/* AMD-defined flags: level 0x80000001 */
	c->extended_cpuid_level = cpuid_eax(0x80000000);
	if ((c->extended_cpuid_level >> 16) != 0x8000)
		c->extended_cpuid_level = 0;
	if (c->extended_cpuid_level > 0x80000000)
		cpuid(0x80000001, &tmp, &tmp,
		      &c->x86_capability[cpufeat_word(X86_FEATURE_LAHF_LM)],
		      &c->x86_capability[cpufeat_word(X86_FEATURE_SYSCALL)]);
	if (c == &boot_cpu_data)
		bootsym(cpuid_ext_features) =
			c->x86_capability[cpufeat_word(X86_FEATURE_NX)];

	if (c->extended_cpuid_level >= 0x80000004)
		get_model_name(c); /* Default name */
	if (c->extended_cpuid_level >= 0x80000007)
		c->x86_capability[cpufeat_word(X86_FEATURE_ITSC)]
			= cpuid_edx(0x80000007);
	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_capability[cpufeat_word(X86_FEATURE_CLZERO)]
			= cpuid_ebx(0x80000008);

	/* Intel-defined flags: level 0x00000007 */
	if ( c->cpuid_level >= 0x00000007 )
		cpuid_count(0x00000007, 0, &tmp,
			    &c->x86_capability[cpufeat_word(X86_FEATURE_FSGSBASE)],
			    &c->x86_capability[cpufeat_word(X86_FEATURE_PKU)],
			    &tmp);
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void identify_cpu(struct cpuinfo_x86 *c)
{
	int i;

	c->x86_cache_size = -1;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->cpuid_level = -1;	/* CPUID not detected */
	c->x86_model = c->x86_mask = 0;	/* So far unknown... */
	c->x86_vendor_id[0] = '\0'; /* Unset */
	c->x86_model_id[0] = '\0';  /* Unset */
	c->x86_max_cores = 1;
	c->x86_num_siblings = 1;
	c->x86_clflush_size = 0;
	c->phys_proc_id = XEN_INVALID_SOCKET_ID;
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
	if (this_cpu->c_init)
		this_cpu->c_init(c);


   	if ( !opt_pku )
		setup_clear_cpu_cap(X86_FEATURE_PKU);

	/*
	 * The vendor-specific functions might have changed features.  Now
	 * we do "generic changes."
	 */
	for (i = 0; i < FSCAPINTS; ++i)
		c->x86_capability[i] &= known_features[i];

	for (i = 0 ; i < NCAPINTS ; ++i)
		c->x86_capability[i] &= ~cleared_caps[i];

	/* If the model name is still unset, do table lookup. */
	if ( !c->x86_model_id[0] ) {
		/* Last resort... */
		snprintf(c->x86_model_id, sizeof(c->x86_model_id),
			"%02x/%02x", c->x86_vendor, c->x86_model);
	}

	/* Now the feature flags better reflect actual CPU features! */

	if ( cpu_has_xsave )
		xstate_init(c);

#ifdef NOISY_CAPS
	printk(KERN_DEBUG "CPU: After all inits, caps:");
	for (i = 0; i < NCAPINTS; i++)
		printk(" %08x", c->x86_capability[i]);
	printk("\n");
#endif

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

		mcheck_init(c, 0);
	} else {
		mcheck_init(c, 1);

		mtrr_bp_init();
	}
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
void detect_extended_topology(struct cpuinfo_x86 *c)
{
	unsigned int eax, ebx, ecx, edx, sub_index;
	unsigned int ht_mask_width, core_plus_mask_width;
	unsigned int core_select_mask, core_level_siblings;
	unsigned int initial_apicid;

	if ( c->cpuid_level < 0xb )
		return;

	cpuid_count(0xb, SMT_LEVEL, &eax, &ebx, &ecx, &edx);

	/* Check if the cpuid leaf 0xb is actually implemented */
	if ( ebx == 0 || (LEAFB_SUBTYPE(ecx) != SMT_TYPE) )
		return;

	__set_bit(X86_FEATURE_XTOPOLOGY, c->x86_capability);

	initial_apicid = edx;

	/* Populate HT related information from sub-leaf level 0 */
	core_level_siblings = c->x86_num_siblings = LEVEL_MAX_SIBLINGS(ebx);
	core_plus_mask_width = ht_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);

	sub_index = 1;
	do {
		cpuid_count(0xb, sub_index, &eax, &ebx, &ecx, &edx);

		/* Check for the Core type in the implemented sub leaves */
		if ( LEAFB_SUBTYPE(ecx) == CORE_TYPE ) {
			core_level_siblings = LEVEL_MAX_SIBLINGS(ebx);
			core_plus_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);
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

	if (c->x86_vendor < X86_VENDOR_NUM)
		vendor = this_cpu->c_vendor;
	else
		vendor = c->x86_vendor_id;

	if (vendor && strncmp(c->x86_model_id, vendor, strlen(vendor)))
		printk("%s ", vendor);

	if (!c->x86_model_id[0])
		printk("%d86", c->x86);
	else
		printk("%s", c->x86_model_id);

	printk(" stepping %02x\n", c->x86_mask);
}

static cpumask_t cpu_initialized;

/* This is hacky. :)
 * We're emulating future behavior.
 * In the future, the cpu-specific init functions will be called implicitly
 * via the magic of initcalls.
 * They will insert themselves into the cpu_devs structure.
 * Then, when cpu_init() is called, we can just iterate over that array.
 */

void __init early_cpu_init(void)
{
	intel_cpu_init();
	amd_init_cpu();
	centaur_init_cpu();
	early_cpu_detect();
}

/*
 * Sets up system tables and descriptors.
 *
 * - Sets up TSS with stack pointers, including ISTs
 * - Inserts TSS selector into regular and compat GDTs
 * - Loads GDT, IDT, TR then null LDT
 */
void load_system_tables(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned long stack_bottom = get_stack_bottom(),
		stack_top = stack_bottom & ~(STACK_SIZE - 1);

	struct tss_struct *tss = &this_cpu(init_tss);
	struct desc_struct *gdt =
		this_cpu(gdt_table) - FIRST_RESERVED_GDT_ENTRY;
	struct desc_struct *compat_gdt =
		this_cpu(compat_gdt_table) - FIRST_RESERVED_GDT_ENTRY;

	const struct desc_ptr gdtr = {
		.base = (unsigned long)gdt,
		.limit = LAST_RESERVED_GDT_BYTE,
	};
	const struct desc_ptr idtr = {
		.base = (unsigned long)idt_tables[cpu],
		.limit = (IDT_ENTRIES * sizeof(idt_entry_t)) - 1,
	};

	/* Main stack for interrupts/exceptions. */
	tss->rsp0 = stack_bottom;
	tss->bitmap = IOBMP_INVALID_OFFSET;

	/* MCE, NMI and Double Fault handlers get their own stacks. */
	tss->ist[IST_MCE - 1] = stack_top + IST_MCE * PAGE_SIZE;
	tss->ist[IST_DF  - 1] = stack_top + IST_DF  * PAGE_SIZE;
	tss->ist[IST_NMI - 1] = stack_top + IST_NMI * PAGE_SIZE;

	_set_tssldt_desc(
		gdt + TSS_ENTRY,
		(unsigned long)tss,
		offsetof(struct tss_struct, __cacheline_filler) - 1,
		SYS_DESC_tss_avail);
	_set_tssldt_desc(
		compat_gdt + TSS_ENTRY,
		(unsigned long)tss,
		offsetof(struct tss_struct, __cacheline_filler) - 1,
		SYS_DESC_tss_busy);

	asm volatile ("lgdt %0"  : : "m"  (gdtr) );
	asm volatile ("lidt %0"  : : "m"  (idtr) );
	asm volatile ("ltr  %w0" : : "rm" (TSS_ENTRY << 3) );
	asm volatile ("lldt %w0" : : "rm" (0) );

	/*
	 * Bottom-of-stack must be 16-byte aligned!
	 *
	 * Defer checks until exception support is sufficiently set up.
	 */
	BUILD_BUG_ON((sizeof(struct cpu_info) -
		      offsetof(struct cpu_info, guest_cpu_user_regs.es)) & 0xf);
	BUG_ON(system_state != SYS_STATE_early_boot && (stack_bottom & 0xf));
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

	if (cpu_has_pat)
		wrmsrl(MSR_IA32_CR_PAT, host_pat);

	/* Install correct page table. */
	write_ptbase(current);

	/* Ensure FPU gets initialised for each domain. */
	stts();

	/* Clear all 6 debug registers: */
#define CD(register) asm volatile ( "mov %0,%%db" #register : : "r"(0UL) );
	CD(0); CD(1); CD(2); CD(3); /* no db4 and db5 */; CD(6); CD(7);
#undef CD
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
