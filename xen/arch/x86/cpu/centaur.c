#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/bitops.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/e820.h>
#include "cpu.h"

#define ACE_PRESENT	(1 << 6)
#define ACE_ENABLED	(1 << 7)
#define ACE_FCR		(1 << 28)	/* MSR_VIA_FCR */

#define RNG_PRESENT	(1 << 2)
#define RNG_ENABLED	(1 << 3)
#define RNG_ENABLE	(1 << 6)	/* MSR_VIA_RNG */

static void __init init_c3(struct cpuinfo_x86 *c)
{
	uint64_t msr_content;

	/* Test for Centaur Extended Feature Flags presence */
	if (cpuid_eax(0xC0000000) >= 0xC0000001) {
		u32 tmp = cpuid_edx(0xC0000001);

		/* enable ACE unit, if present and disabled */
		if ((tmp & (ACE_PRESENT | ACE_ENABLED)) == ACE_PRESENT) {
			rdmsrl(MSR_VIA_FCR, msr_content);
			/* enable ACE unit */
			wrmsrl(MSR_VIA_FCR, msr_content | ACE_FCR);
			printk(KERN_INFO "CPU: Enabled ACE h/w crypto\n");
		}

		/* enable RNG unit, if present and disabled */
		if ((tmp & (RNG_PRESENT | RNG_ENABLED)) == RNG_PRESENT) {
			rdmsrl(MSR_VIA_RNG, msr_content);
			/* enable RNG unit */
			wrmsrl(MSR_VIA_RNG, msr_content | RNG_ENABLE);
			printk(KERN_INFO "CPU: Enabled h/w RNG\n");
		}

		/* store Centaur Extended Feature Flags as
		 * word 5 of the CPU capability bit array
		 */
		c->x86_capability[5] = cpuid_edx(0xC0000001);
	}

	/* Cyrix III family needs CX8 & PGE explicity enabled. */
	if (c->x86_model >=6 && c->x86_model <= 9) {
		rdmsrl(MSR_VIA_FCR, msr_content);
		wrmsrl(MSR_VIA_FCR, msr_content | (1ULL << 1 | 1ULL << 7));
		set_bit(X86_FEATURE_CX8, c->x86_capability);
	}

	/* Before Nehemiah, the C3's had 3dNOW! */
	if (c->x86_model >=6 && c->x86_model <9)
		set_bit(X86_FEATURE_3DNOW, c->x86_capability);

	if (cpuid_eax(0x80000000) < 0x80000008)
		paddr_bits = 32;

	get_model_name(c);
	display_cacheinfo(c);
}

static void __init init_centaur(struct cpuinfo_x86 *c)
{
	/* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
	   3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
	clear_bit(0*32+31, c->x86_capability);

	if (c->x86 == 6)
		init_c3(c);
}

static unsigned int centaur_size_cache(struct cpuinfo_x86 * c, unsigned int size)
{
	/* VIA C3 CPUs (670-68F) need further shifting. */
	if ((c->x86 == 6) && ((c->x86_model == 7) || (c->x86_model == 8)))
		size >>= 8;

	/* VIA also screwed up Nehemiah stepping 1, and made
	   it return '65KB' instead of '64KB'
	   - Note, it seems this may only be in engineering samples. */
	if ((c->x86==6) && (c->x86_model==9) && (c->x86_mask==1) && (size==65))
		size -=1;

	return size;
}

static struct cpu_dev centaur_cpu_dev __cpuinitdata = {
	.c_vendor	= "Centaur",
	.c_ident	= { "CentaurHauls" },
	.c_init		= init_centaur,
	.c_size_cache	= centaur_size_cache,
};

int __init centaur_init_cpu(void)
{
	cpu_devs[X86_VENDOR_CENTAUR] = &centaur_cpu_dev;
	return 0;
}

//early_arch_initcall(centaur_init_cpu);
