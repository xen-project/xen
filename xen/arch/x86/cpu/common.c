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

#include "cpu.h"

static bool_t __cpuinitdata use_xsave = 1;
boolean_param("xsave", use_xsave);

bool_t __devinitdata opt_arat = 1;
boolean_param("arat", opt_arat);

unsigned int __devinitdata opt_cpuid_mask_ecx = ~0u;
integer_param("cpuid_mask_ecx", opt_cpuid_mask_ecx);
unsigned int __devinitdata opt_cpuid_mask_edx = ~0u;
integer_param("cpuid_mask_edx", opt_cpuid_mask_edx);

unsigned int __devinitdata opt_cpuid_mask_xsave_eax = ~0u;
integer_param("cpuid_mask_xsave_eax", opt_cpuid_mask_xsave_eax);

unsigned int __devinitdata opt_cpuid_mask_ext_ecx = ~0u;
integer_param("cpuid_mask_ext_ecx", opt_cpuid_mask_ext_ecx);
unsigned int __devinitdata opt_cpuid_mask_ext_edx = ~0u;
integer_param("cpuid_mask_ext_edx", opt_cpuid_mask_ext_edx);

struct cpu_dev * cpu_devs[X86_VENDOR_NUM] = {};

unsigned int paddr_bits __read_mostly = 36;
unsigned int hap_paddr_bits __read_mostly = 36;

/*
 * Default host IA32_CR_PAT value to cover all memory types.
 * BIOS usually sets it to 0x07040600070406.
 */
u64 host_pat = 0x050100070406;

static unsigned int __cpuinitdata cleared_caps[NCAPINTS];

void __init setup_clear_cpu_cap(unsigned int cap)
{
	__clear_bit(cap, boot_cpu_data.x86_capability);
	__set_bit(cap, cleared_caps);
}

static void default_init(struct cpuinfo_x86 * c)
{
	/* Not much we can do here... */
	/* Check if at least it has cpuid */
	BUG_ON(c->cpuid_level == -1);
	__clear_bit(X86_FEATURE_SEP, c->x86_capability);
}

static struct cpu_dev default_cpu = {
	.c_init	= default_init,
	.c_vendor = "Unknown",
};
static struct cpu_dev * this_cpu = &default_cpu;

bool_t opt_cpu_info;
boolean_param("cpuinfo", opt_cpu_info);

int __cpuinit get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;
	char *p, *q;

	if (cpuid_eax(0x80000000) < 0x80000004)
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


void __cpuinit display_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int n, dummy, ecx, edx, l2size;

	n = cpuid_eax(0x80000000);

	if (n >= 0x80000005) {
		cpuid(0x80000005, &dummy, &dummy, &ecx, &edx);
		if (opt_cpu_info)
			printk("CPU: L1 I cache %dK (%d bytes/line),"
			              " D cache %dK (%d bytes/line)\n",
			       edx>>24, edx&0xFF, ecx>>24, ecx&0xFF);
		c->x86_cache_size=(ecx>>24)+(edx>>24);	
	}

	if (n < 0x80000006)	/* Some chips just has a large L1. */
		return;

	ecx = cpuid_ecx(0x80000006);
	l2size = ecx >> 16;
	
	c->x86_cache_size = l2size;

	if (opt_cpu_info)
		printk("CPU: L2 Cache: %dK (%d bytes/line)\n",
		       l2size, ecx & 0xFF);
}

static void __cpuinit get_cpu_vendor(struct cpuinfo_x86 *c, int early)
{
	char *v = c->x86_vendor_id;
	int i;
	static int printed;

	for (i = 0; i < X86_VENDOR_NUM; i++) {
		if (cpu_devs[i]) {
			if (!strcmp(v,cpu_devs[i]->c_ident[0]) ||
			    (cpu_devs[i]->c_ident[1] && 
			     !strcmp(v,cpu_devs[i]->c_ident[1]))) {
				c->x86_vendor = i;
				if (!early)
					this_cpu = cpu_devs[i];
				return;
			}
		}
	}
	if (!printed) {
		printed++;
		printk(KERN_ERR "CPU: Vendor unknown, using generic init.\n");
		printk(KERN_ERR "CPU: Your system may be unstable.\n");
	}
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	this_cpu = &default_cpu;
}


/* Do minimum CPU detection early.
   Fields really needed: vendor, cpuid_level, family, model, mask, cache alignment.
   The others are not touched to avoid unwanted side effects.

   WARNING: this function is only called on the BP.  Don't add code here
   that is supposed to run on all CPUs. */
static void __init early_cpu_detect(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	u32 cap4, tfms, cap0, misc;

	c->x86_cache_alignment = 32;

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);

	get_cpu_vendor(c, 1);

	cpuid(0x00000001, &tfms, &misc, &cap4, &cap0);
	c->x86 = (tfms >> 8) & 15;
	c->x86_model = (tfms >> 4) & 15;
	if (c->x86 == 0xf)
		c->x86 += (tfms >> 20) & 0xff;
	if (c->x86 >= 0x6)
		c->x86_model += ((tfms >> 16) & 0xF) << 4;
	c->x86_mask = tfms & 15;
	cap0 &= ~cleared_caps[0];
	cap4 &= ~cleared_caps[4];
	if (cap0 & (1<<19))
		c->x86_cache_alignment = ((misc >> 8) & 0xff) * 8;
	/* Leaf 0x1 capabilities filled in early for Xen. */
	c->x86_capability[0] = cap0;
	c->x86_capability[4] = cap4;
}

static void __cpuinit generic_identify(struct cpuinfo_x86 *c)
{
	u32 tfms, xlvl, capability, excap, eax, ebx;

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);
		
	get_cpu_vendor(c, 0);
	/* Initialize the standard set of capabilities */
	/* Note that the vendor-specific code below might override */
	
	/* Intel-defined flags: level 0x00000001 */
	cpuid(0x00000001, &tfms, &ebx, &excap, &capability);
	c->x86_capability[0] = capability;
	c->x86_capability[4] = excap;
	c->x86 = (tfms >> 8) & 15;
	c->x86_model = (tfms >> 4) & 15;
	if (c->x86 == 0xf)
		c->x86 += (tfms >> 20) & 0xff;
	if (c->x86 >= 0x6)
		c->x86_model += ((tfms >> 16) & 0xF) << 4;
	c->x86_mask = tfms & 15;
	if ( cpu_has(c, X86_FEATURE_CLFLSH) )
		c->x86_clflush_size = ((ebx >> 8) & 0xff) * 8;

	/* AMD-defined flags: level 0x80000001 */
	xlvl = cpuid_eax(0x80000000);
	if ( (xlvl & 0xffff0000) == 0x80000000 ) {
		if ( xlvl >= 0x80000001 ) {
			c->x86_capability[1] = cpuid_edx(0x80000001);
			c->x86_capability[6] = cpuid_ecx(0x80000001);
		}
		if ( xlvl >= 0x80000004 )
			get_model_name(c); /* Default name */
		if ( xlvl >= 0x80000008 ) {
			eax = cpuid_eax(0x80000008);
			paddr_bits = eax & 0xff;
			hap_paddr_bits = ((eax >> 16) & 0xff) ?: paddr_bits;
		}
	}

	/* Might lift BIOS max_leaf=3 limit. */
	early_intel_workaround(c);

	/* Intel-defined flags: level 0x00000007 */
	if ( c->cpuid_level >= 0x00000007 ) {
		u32 dummy;
		cpuid_count(0x00000007, 0, &dummy, &ebx, &dummy, &dummy);
		c->x86_capability[X86_FEATURE_FSGSBASE / 32] = ebx;
	}

#ifdef CONFIG_X86_HT
	c->phys_proc_id = (cpuid_ebx(1) >> 24) & 0xff;
#endif
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void __cpuinit identify_cpu(struct cpuinfo_x86 *c)
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
	c->phys_proc_id = BAD_APICID;
	c->cpu_core_id = BAD_APICID;
	c->compute_unit_id = BAD_APICID;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	generic_identify(c);

#ifdef NOISY_CAPS
	printk(KERN_DEBUG "CPU: After generic identify, caps:");
	for (i = 0; i < NCAPINTS; i++)
		printk(" %08x", c->x86_capability[i]);
	printk("\n");
#endif

	if (this_cpu->c_identify) {
		this_cpu->c_identify(c);

#ifdef NOISY_CAPS
		printk(KERN_DEBUG "CPU: After vendor identify, caps:");
		for (i = 0; i < NCAPINTS; i++)
			printk(" %08x", c->x86_capability[i]);
		printk("\n");
#endif
	}

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

        /* Initialize xsave/xrstor features */
	if ( !use_xsave )
		clear_bit(X86_FEATURE_XSAVE, boot_cpu_data.x86_capability);

	if ( cpu_has_xsave )
		xstate_init(c == &boot_cpu_data);

	/*
	 * The vendor-specific functions might have changed features.  Now
	 * we do "generic changes."
	 */

	for (i = 0 ; i < NCAPINTS ; ++i)
		c->x86_capability[i] &= ~cleared_caps[i];

	/* If the model name is still unset, do table lookup. */
	if ( !c->x86_model_id[0] ) {
		/* Last resort... */
		snprintf(c->x86_model_id, sizeof(c->x86_model_id),
			"%02x/%02x", c->x86_vendor, c->x86_model);
	}

	/* Now the feature flags better reflect actual CPU features! */

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

/* cpuid returns the value latched in the HW at reset, not the APIC ID
 * register's value.  For any box whose BIOS changes APIC IDs, like
 * clustered APIC systems, we must use hard_smp_processor_id.
 *
 * See Intel's IA-32 SW Dev's Manual Vol2 under CPUID.
 */
static inline u32 phys_pkg_id(u32 cpuid_apic, int index_msb)
{
	return hard_smp_processor_id() >> index_msb;
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
void __cpuinit detect_extended_topology(struct cpuinfo_x86 *c)
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

	set_bit(X86_FEATURE_XTOPOLOGY, c->x86_capability);

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

	core_select_mask = (~(-1 << core_plus_mask_width)) >> ht_mask_width;

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

#ifdef CONFIG_X86_HT
void __cpuinit detect_ht(struct cpuinfo_x86 *c)
{
	u32 	eax, ebx, ecx, edx;
	int 	index_msb, core_bits;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	c->apicid = phys_pkg_id((ebx >> 24) & 0xFF, 0);

	if (!cpu_has(c, X86_FEATURE_HT) || cpu_has(c, X86_FEATURE_CMP_LEGACY)
        || cpu_has(c, X86_FEATURE_XTOPOLOGY))
		return;

	c->x86_num_siblings = (ebx & 0xff0000) >> 16;

	if (c->x86_num_siblings == 1) {
		printk(KERN_INFO  "CPU: Hyper-Threading is disabled\n");
	} else if (c->x86_num_siblings > 1 ) {

		if (c->x86_num_siblings > nr_cpu_ids) {
			printk(KERN_WARNING "CPU: Unsupported number of the siblings %d", c->x86_num_siblings);
			c->x86_num_siblings = 1;
			return;
		}

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
#endif

void __cpuinit print_cpu_info(unsigned int cpu)
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
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void __cpuinit cpu_init(void)
{
	int cpu = smp_processor_id();
	struct tss_struct *t = &this_cpu(init_tss);
	struct desc_ptr gdt_desc = {
		.base = (unsigned long)(this_cpu(gdt_table) - FIRST_RESERVED_GDT_ENTRY),
		.limit = LAST_RESERVED_GDT_BYTE
	};

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

	asm volatile ( "lgdt %0" : : "m" (gdt_desc) );

	/* No nested task. */
	asm volatile ("pushf ; andw $0xbfff,(%"__OP"sp) ; popf" );

	/* Ensure FPU gets initialised for each domain. */
	stts();

	/* Set up and load the per-CPU TSS and LDT. */
	t->bitmap = IOBMP_INVALID_OFFSET;
	/* Bottom-of-stack must be 16-byte aligned! */
	BUG_ON((get_stack_bottom() & 15) != 0);
	t->rsp0 = get_stack_bottom();
	load_TR();
	asm volatile ( "lldt %%ax" : : "a" (0) );

	/* Clear all 6 debug registers: */
#define CD(register) asm volatile ( "mov %0,%%db" #register : : "r"(0UL) );
	CD(0); CD(1); CD(2); CD(3); /* no db4 and db5 */; CD(6); CD(7);
#undef CD
}

void cpu_uninit(unsigned int cpu)
{
	cpumask_clear_cpu(cpu, &cpu_initialized);
}
