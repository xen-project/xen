#include <xen/config.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/bitops.h>
#include <xen/delay.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "cpu.h"

/*
 * Read NSC/Cyrix DEVID registers (DIR) to get more detailed info. about the CPU
 */
void __init do_cyrix_devid(unsigned char *dir0, unsigned char *dir1)
{
	unsigned char ccr3;
	unsigned long flags;
	
	/* we test for DEVID by checking whether CCR3 is writable */
	local_irq_save(flags);
	ccr3 = getCx86(CX86_CCR3);
	setCx86(CX86_CCR3, ccr3 ^ 0x80);
	getCx86(0xc0);   /* dummy to change bus */

	if (getCx86(CX86_CCR3) == ccr3)       /* no DEVID regs. */
		BUG();
	else {
		setCx86(CX86_CCR3, ccr3);  /* restore CCR3 */

		/* read DIR0 and DIR1 CPU registers */
		*dir0 = getCx86(CX86_DIR0);
		*dir1 = getCx86(CX86_DIR1);
	}
	local_irq_restore(flags);
}

/*
 * Cx86_dir0_msb is a HACK needed by check_cx686_cpuid/slop in bugs.h in
 * order to identify the Cyrix CPU model after we're out of setup.c
 *
 * Actually since bugs.h doesn't even reference this perhaps someone should
 * fix the documentation ???
 */
static unsigned char Cx86_dir0_msb __initdata = 0;

static char Cx86_model[][9] __initdata = {
	"Cx486", "Cx486", "5x86 ", "6x86", "MediaGX ", "6x86MX ",
	"M II ", "Unknown"
};
static char Cx86_cb[] __initdata = "?.5x Core/Bus Clock";
static char cyrix_model_mult1[] __initdata = "12??43";
static char cyrix_model_mult2[] __initdata = "12233445";

/*
 * Reset the slow-loop (SLOP) bit on the 686(L) which is set by some old
 * BIOSes for compatibility with DOS games.  This makes the udelay loop
 * work correctly, and improves performance.
 *
 * FIXME: our newer udelay uses the tsc. We don't need to frob with SLOP
 */

static void __init check_cx686_slop(struct cpuinfo_x86 *c)
{
	unsigned long flags;
	
	if (Cx86_dir0_msb == 3) {
		unsigned char ccr3, ccr5;

		local_irq_save(flags);
		ccr3 = getCx86(CX86_CCR3);
		setCx86(CX86_CCR3, (ccr3 & 0x0f) | 0x10); /* enable MAPEN  */
		ccr5 = getCx86(CX86_CCR5);
		if (ccr5 & 2)
			setCx86(CX86_CCR5, ccr5 & 0xfd);  /* reset SLOP */
		setCx86(CX86_CCR3, ccr3);                 /* disable MAPEN */
		local_irq_restore(flags);
	}
}


static void __init set_cx86_reorder(void)
{
	u8 ccr3;

	printk(KERN_INFO "Enable Memory access reorder on Cyrix/NSC processor.\n");
	ccr3 = getCx86(CX86_CCR3);
	setCx86(CX86_CCR3, (ccr3 & 0x0f) | 0x10); /* enable MAPEN  */

	/* Load/Store Serialize to mem access disable (=reorder it)  */
	setCx86(CX86_PCR0, getCx86(CX86_PCR0) & ~0x80);
	/* set load/store serialize from 1GB to 4GB */
	ccr3 |= 0xe0;
	setCx86(CX86_CCR3, ccr3);
}

static void __init set_cx86_memwb(void)
{
	u32 cr0;

	printk(KERN_INFO "Enable Memory-Write-back mode on Cyrix/NSC processor.\n");

	/* CCR2 bit 2: unlock NW bit */
	setCx86(CX86_CCR2, getCx86(CX86_CCR2) & ~0x04);
	/* set 'Not Write-through' */
	cr0 = 0x20000000;
	__asm__("movl %%cr0,%%eax\n\t"
		"orl %0,%%eax\n\t"
		"movl %%eax,%%cr0\n"
		: : "r" (cr0)
		:"ax");
	/* CCR2 bit 2: lock NW bit and set WT1 */
	setCx86(CX86_CCR2, getCx86(CX86_CCR2) | 0x14 );
}

static void __init set_cx86_inc(void)
{
	unsigned char ccr3;

	printk(KERN_INFO "Enable Incrementor on Cyrix/NSC processor.\n");

	ccr3 = getCx86(CX86_CCR3);
	setCx86(CX86_CCR3, (ccr3 & 0x0f) | 0x10); /* enable MAPEN  */
	/* PCR1 -- Performance Control */
	/* Incrementor on, whatever that is */
	setCx86(CX86_PCR1, getCx86(CX86_PCR1) | 0x02);
	/* PCR0 -- Performance Control */
	/* Incrementor Margin 10 */
	setCx86(CX86_PCR0, getCx86(CX86_PCR0) | 0x04);
	setCx86(CX86_CCR3, ccr3);	/* disable MAPEN */
}

/*
 *	Configure later MediaGX and/or Geode processor.
 */

static void __init geode_configure(void)
{
	unsigned long flags;
	u8 ccr3, ccr4;
	local_irq_save(flags);

	/* Suspend on halt power saving and enable #SUSP pin */
	setCx86(CX86_CCR2, getCx86(CX86_CCR2) | 0x88);

	ccr3 = getCx86(CX86_CCR3);
	setCx86(CX86_CCR3, (ccr3 & 0x0f) | 0x10);	/* Enable */
	
	ccr4 = getCx86(CX86_CCR4);
	ccr4 |= 0x38;		/* FPU fast, DTE cache, Mem bypass */
	
	setCx86(CX86_CCR3, ccr3);
	
	set_cx86_memwb();
	set_cx86_reorder();	
	set_cx86_inc();
	
	local_irq_restore(flags);
}


static void __init init_cyrix(struct cpuinfo_x86 *c)
{
	unsigned char dir0, dir0_msn, dir0_lsn, dir1 = 0;
	const char *p = NULL;

	/* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
	   3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
	clear_bit(0*32+31, c->x86_capability);

	/* Cyrix used bit 24 in extended (AMD) CPUID for Cyrix MMX extensions */
	if ( test_bit(1*32+24, c->x86_capability) ) {
		clear_bit(1*32+24, c->x86_capability);
		set_bit(X86_FEATURE_CXMMX, c->x86_capability);
	}

	do_cyrix_devid(&dir0, &dir1);

	check_cx686_slop(c);

	Cx86_dir0_msb = dir0_msn = dir0 >> 4; /* identifies CPU "family"   */
	dir0_lsn = dir0 & 0xf;                /* model or clock multiplier */

	/* common case step number/rev -- exceptions handled below */
	c->x86_model = (dir1 >> 4) + 1;
	c->x86_mask = dir1 & 0xf;

	/* Now cook; the original recipe is by Channing Corn, from Cyrix.
	 * We do the same thing for each generation: we work out
	 * the model, multiplier and stepping.  Black magic included,
	 * to make the silicon step/rev numbers match the printed ones.
	 */
	 
	switch (dir0_msn) {
		unsigned char tmp;

	case 3: /* 6x86/6x86L */
		Cx86_cb[1] = ' ';
		Cx86_cb[2] = cyrix_model_mult1[dir0_lsn & 5];
		if (dir1 > 0x21) { /* 686L */
			Cx86_cb[0] = 'L';
			p = Cx86_cb;
			(c->x86_model)++;
		} else             /* 686 */
			p = Cx86_cb+1;
		/* Emulate MTRRs using Cyrix's ARRs. */
		set_bit(X86_FEATURE_CYRIX_ARR, c->x86_capability);
		/* 6x86's contain this bug */
		/*c->coma_bug = 1;*/
		break;

	case 4: /* MediaGX/GXm or Geode GXM/GXLV/GX1 */
		c->x86_cache_size=16;	/* Yep 16K integrated cache thats it */
 
		/* GXm supports extended cpuid levels 'ala' AMD */
		if (c->cpuid_level == 2) {
			/* Enable cxMMX extensions (GX1 Datasheet 54) */
			setCx86(CX86_CCR7, getCx86(CX86_CCR7)|1);
			
			/* GXlv/GXm/GX1 */
			if((dir1 >= 0x50 && dir1 <= 0x54) || dir1 >= 0x63)
				geode_configure();
			get_model_name(c);  /* get CPU marketing name */
			return;
		}
		else {  /* MediaGX */
			Cx86_cb[2] = (dir0_lsn & 1) ? '3' : '4';
			p = Cx86_cb+2;
			c->x86_model = (dir1 & 0x20) ? 1 : 2;
		}
		break;

        case 5: /* 6x86MX/M II */
		if (dir1 > 7)
		{
			dir0_msn++;  /* M II */
			/* Enable MMX extensions (App note 108) */
			setCx86(CX86_CCR7, getCx86(CX86_CCR7)|1);
		}
		else
		{
			/*c->coma_bug = 1;*/      /* 6x86MX, it has the bug. */
		}
		tmp = (!(dir0_lsn & 7) || dir0_lsn & 1) ? 2 : 0;
		Cx86_cb[tmp] = cyrix_model_mult2[dir0_lsn & 7];
		p = Cx86_cb+tmp;
        	if (((dir1 & 0x0f) > 4) || ((dir1 & 0xf0) == 0x20))
			(c->x86_model)++;
		/* Emulate MTRRs using Cyrix's ARRs. */
		set_bit(X86_FEATURE_CYRIX_ARR, c->x86_capability);
		break;

	default:  /* unknown (shouldn't happen, we know everyone ;-) */
		dir0_msn = 7;
		break;
	}
	safe_strcpy(c->x86_model_id, Cx86_model[dir0_msn & 7]);
	if (p) safe_strcat(c->x86_model_id, p);

	if (cpu_has_cyrix_arr)
		paddr_bits = 32;
}

/*
 * Cyrix CPUs without cpuid or with cpuid not yet enabled can be detected
 * by the fact that they preserve the flags across the division of 5/2.
 * PII and PPro exhibit this behavior too, but they have cpuid available.
 */
 
/*
 * Perform the Cyrix 5/2 test. A Cyrix won't change
 * the flags, while other 486 chips will.
 */
static inline int test_cyrix_52div(void)
{
	unsigned int test;

	__asm__ __volatile__(
	     "sahf\n\t"		/* clear flags (%eax = 0x0005) */
	     "div %b2\n\t"	/* divide 5 by 2 */
	     "lahf"		/* store flags into %ah */
	     : "=a" (test)
	     : "0" (5), "q" (2)
	     : "cc");

	/* AH is 0x02 on Cyrix after the divide.. */
	return (unsigned char) (test >> 8) == 0x02;
}

static struct cpu_dev cyrix_cpu_dev __cpuinitdata = {
	.c_vendor	= "Cyrix",
	.c_ident 	= { "CyrixInstead" },
	.c_init		= init_cyrix,
};

int __init cyrix_init_cpu(void)
{
	cpu_devs[X86_VENDOR_CYRIX] = &cyrix_cpu_dev;
	return 0;
}

//early_arch_initcall(cyrix_init_cpu);

static struct cpu_dev nsc_cpu_dev __cpuinitdata = {
	.c_vendor	= "NSC",
	.c_ident 	= { "Geode by NSC" },
	.c_init		= init_cyrix,
};

int __init nsc_init_cpu(void)
{
	cpu_devs[X86_VENDOR_NSC] = &nsc_cpu_dev;
	return 0;
}

//early_arch_initcall(nsc_init_cpu);
