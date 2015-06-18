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

	if (c->x86 == 0x6 && c->x86_model >= 0xf) {
		c->x86_cache_alignment = c->x86_clflush_size * 2;
		set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
	}

	get_model_name(c);
	display_cacheinfo(c);
}

static void __init init_centaur(struct cpuinfo_x86 *c)
{
	if (c->x86 == 6)
		init_c3(c);
}

static const struct cpu_dev centaur_cpu_dev = {
	.c_vendor	= "Centaur",
	.c_ident	= { "CentaurHauls" },
	.c_init		= init_centaur,
};

int __init centaur_init_cpu(void)
{
	cpu_devs[X86_VENDOR_CENTAUR] = &centaur_cpu_dev;
	return 0;
}
