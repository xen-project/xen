#include <xen/init.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/spec_ctrl.h>

#include "cpu.h"

#define APICID_SOCKET_ID_BIT 6

static void hygon_get_topology(struct cpuinfo_x86 *c)
{
	unsigned int ebx;

	if (c->x86_max_cores <= 1)
		return;

	/* Socket ID is ApicId[6] for Hygon processors. */
	c->phys_proc_id >>= APICID_SOCKET_ID_BIT;

	ebx = cpuid_ebx(0x8000001e);
	c->x86_num_siblings = ((ebx >> 8) & 0x3) + 1;
	c->x86_max_cores /= c->x86_num_siblings;
	c->cpu_core_id = ebx & 0xff;

	if (opt_cpu_info)
	        printk("CPU %d(%d) -> Processor %d, Core %d\n",
	                smp_processor_id(), c->x86_max_cores,
	                        c->phys_proc_id, c->cpu_core_id);
}

static void init_hygon(struct cpuinfo_x86 *c)
{
	unsigned long long value;

	/*
	 * Attempt to set lfence to be Dispatch Serialising.  This MSR almost
	 * certainly isn't virtualised (and Xen at least will leak the real
	 * value in but silently discard writes), as well as being per-core
	 * rather than per-thread, so do a full safe read/write/readback cycle
	 * in the worst case.
	 */
	if (rdmsr_safe(MSR_AMD64_DE_CFG, value))
		/* Unable to read.  Assume the safer default. */
		__clear_bit(X86_FEATURE_LFENCE_DISPATCH,
			    c->x86_capability);
	else if (value & AMD64_DE_CFG_LFENCE_SERIALISE)
		/* Already dispatch serialising. */
		__set_bit(X86_FEATURE_LFENCE_DISPATCH,
			  c->x86_capability);
	else if (wrmsr_safe(MSR_AMD64_DE_CFG,
			    value | AMD64_DE_CFG_LFENCE_SERIALISE) ||
		 rdmsr_safe(MSR_AMD64_DE_CFG, value) ||
		 !(value & AMD64_DE_CFG_LFENCE_SERIALISE))
		/* Attempt to set failed.  Assume the safer default. */
		__clear_bit(X86_FEATURE_LFENCE_DISPATCH,
			    c->x86_capability);
	else
		/* Successfully enabled! */
		__set_bit(X86_FEATURE_LFENCE_DISPATCH,
			  c->x86_capability);

	/*
	 * If the user has explicitly chosen to disable Memory Disambiguation
	 * to mitigiate Speculative Store Bypass, poke the appropriate MSR.
	 */
	if (opt_ssbd && !rdmsr_safe(MSR_AMD64_LS_CFG, value)) {
		value |= 1ull << 10;
		wrmsr_safe(MSR_AMD64_LS_CFG, value);
	}

	/* MFENCE stops RDTSC speculation */
	if (!cpu_has_lfence_dispatch)
		__set_bit(X86_FEATURE_MFENCE_RDTSC, c->x86_capability);

	display_cacheinfo(c);

	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_max_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;

	if (c->extended_cpuid_level >= 0x80000007) {
		if (cpu_has(c, X86_FEATURE_ITSC)) {
			__set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
			__set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
			__set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
		}
	}

	hygon_get_topology(c);

	/* Hygon CPUs do not support SYSENTER outside of legacy mode. */
	__clear_bit(X86_FEATURE_SEP, c->x86_capability);

	/* Hygon processors have APIC timer running in deep C states. */
	if (opt_arat)
		__set_bit(X86_FEATURE_ARAT, c->x86_capability);

	if (cpu_has(c, X86_FEATURE_EFRO)) {
		rdmsrl(MSR_K7_HWCR, value);
		value |= (1 << 27); /* Enable read-only APERF/MPERF bit */
		wrmsrl(MSR_K7_HWCR, value);
	}

	amd_log_freq(c);
}

const struct cpu_dev hygon_cpu_dev = {
	.c_early_init	= early_init_amd,
	.c_init		= init_hygon,
};
