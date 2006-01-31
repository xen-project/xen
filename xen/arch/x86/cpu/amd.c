#include <xen/config.h>
#include <xen/init.h>
#include <xen/bitops.h>
#include <xen/mm.h>
#include <xen/smp.h>
#include <xen/sched.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/hvm/vcpu.h>
#include <asm/hvm/support.h>


#include "cpu.h"


#define		AMD_C1_CLOCK_RAMP			0x80000084
#define		AMD_ADVPM_TSC_INVARIANT		0x80000007

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


/*
 *	Check if C1-Clock ramping enabled in  PMM7.CpuLowPwrEnh
 *	On 8th-Generation cores only. Assume BIOS has setup
 *	all Northbridges equivalently.
 */

static int c1_ramp_8gen(void) 
{
	u32 l;

	/*	Read dev=0x18, function = 3, offset=0x87  */
	l = AMD_C1_CLOCK_RAMP;
	/*	fill in dev (18) + function (3) */
	/*	direct cfc/cf8 should be safe here */
	l += (((0x18) << 3) + 0x3) << 8; 
	outl(l, 0xcf8);
	return (1 & (inl(0xcfc) >> 24));
}

/*
 * returns TRUE if ok to use TSC
 */

static int use_amd_tsc(struct cpuinfo_x86 *c) 
{ 
	if (c->x86 < 0xf) {
		/*
		 *	TSC drift doesn't exist on 7th Gen or less
		 *	However, OS still needs to consider effects
		 *	of P-state changes on TSC
		*/
		return 1;
	} else if ( cpuid_edx(AMD_ADVPM_TSC_INVARIANT) & 0x100 ) {
		/*
		 *	CPUID.AdvPowerMgmtInfo.TscInvariant
		 *	EDX bit 8, 8000_0007
		 *	Invariant TSC on 8th Gen or newer, use it
		 *	(assume all cores have invariant TSC)
		*/
		return 1;
	} else if ((mp_get_num_processors() == 1) && (c->x86_num_cores == 1)) {
		/*
		 *	OK to use TSC on uni-processor-uni-core
		 *	However, OS still needs to consider effects
		 *	of P-state changes on TSC
		*/
		return 1;
	} else if ( (mp_get_num_processors() == 1) && (c->x86 == 0x0f) 
				&& !c1_ramp_8gen()) {
		/*
		 *	Use TSC on 8th Gen uni-proc with C1_ramp off 
		 *	However, OS still needs to consider effects
		 *	of P-state changes on TSC
		*/
		return 1;
	} else { 
		return 0;
	}
}

/*
 *	Disable C1-Clock ramping if enabled in PMM7.CpuLowPwrEnh
 *	On 8th-Generation cores only. Assume BIOS has setup
 *	all Northbridges equivalently.
 */

static void amd_disable_c1_ramping(void) 
{
	u32 l, h;
	int i;

	for (i=0; i < NR_CPUS;i++) {
		/* Read from the Northbridge for Node x. until we get invalid data */
		/* fill in dev (18 + cpu#) + function (3) */
		l = AMD_C1_CLOCK_RAMP + ((((0x18 + i) << 3) + 0x3) << 8);
		/*	direct cfc/cf8 should be safe here */
		outl(l, 0xcf8);
		h = inl(0xcfc);
		if (h != 0xFFFFFFFF) {
			h &= 0xFCFFFFFF; /* clears pmm7[1:0]  */
			outl(l, 0xcf8);
			outl(h, 0xcfc);
			printk ("AMD: Disabling C1 Clock Ramping Node #%x\n",i);
		}
		else {
			i = NR_CPUS;
		}
			
	}
	return;
}

static void __init init_amd(struct cpuinfo_x86 *c)
{
	u32 l, h;
	int mbytes = num_physpages >> (20-PAGE_SHIFT);
	int r;

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
				
				/* Knock these two lines out if it debugs out ok */
				printk(KERN_INFO "AMD K6 stepping B detected - ");
				/* -- cut here -- */
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
	case 15:
		set_bit(X86_FEATURE_K8, c->x86_capability);
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
		c->x86_num_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;
		if (c->x86_num_cores & (c->x86_num_cores - 1))
			c->x86_num_cores = 1;
	}

#ifdef CONFIG_X86_HT
	/*
	 * On a AMD dual core setup the lower bits of the APIC id
	 * distingush the cores.  Assumes number of cores is a power
	 * of two.
	 */
	if (c->x86_num_cores > 1) {
		int cpu = smp_processor_id();
		unsigned bits = 0;
		while ((1 << bits) < c->x86_num_cores)
			bits++;
		cpu_core_id[cpu] = phys_proc_id[cpu] & ((1<<bits)-1);
		phys_proc_id[cpu] >>= bits;
		printk(KERN_INFO "CPU %d(%d) -> Core %d\n",
		       cpu, c->x86_num_cores, cpu_core_id[cpu]);
	}
#endif
	/*
	 * Prevent TSC drift in non single-processor, single-core platforms
	 */
	if ( !use_amd_tsc(c) && (c->x86 == 0x0f) && c1_ramp_8gen() && 
			(smp_processor_id() == 0)) {
		/* Disable c1 Clock Ramping on all cores */
		amd_disable_c1_ramping();
	}

#ifdef CONFIG_SVM
	start_svm();
#endif
}

static unsigned int amd_size_cache(struct cpuinfo_x86 * c, unsigned int size)
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

static struct cpu_dev amd_cpu_dev __initdata = {
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

//early_arch_initcall(amd_init_cpu);
