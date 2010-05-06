#ifndef XC_CPUID_H
#define XC_CPUID_H

#ifdef XEN_DOMCTL_set_cpuid

#include "xc_cpufeature.h"

#define bitmaskof(idx)      (1u << ((idx) & 31))
#define clear_bit(idx, dst) ((dst) &= ~(1u << ((idx) & 31)))
#define set_bit(idx, dst)   ((dst) |= (1u << ((idx) & 31)))

#define DEF_MAX_BASE 0x00000004u
#define DEF_MAX_EXT  0x80000008u

static void xc_cpuid(uint32_t eax, uint32_t ecx, uint32_t regs[4])
{
	unsigned int realecx = (ecx == XEN_CPUID_INPUT_UNUSED) ? 0 : ecx;
	asm (
#ifdef __i386__
	     "push %%ebx; cpuid; mov %%ebx,%1; pop %%ebx"
#else
	     "push %%rbx; cpuid; mov %%ebx,%1; pop %%rbx"
#endif
	    : "=a" (regs[0]), "=r" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
	    : "0" (eax), "2" (realecx));
}

enum { CPU_BRAND_INTEL, CPU_BRAND_AMD, CPU_BRAND_UNKNOWN };

static int xc_cpuid_brand_get(void)
{
	uint32_t regs[4];
	char str[13];
	uint32_t *istr = (uint32_t *) str;

	xc_cpuid(0, 0, regs);
	istr[0] = regs[1];
	istr[1] = regs[3];
	istr[2] = regs[2];
	str[12] = '\0';
	if      (strcmp(str, "AuthenticAMD") == 0) {
		return CPU_BRAND_AMD;
	} else if (strcmp(str, "GenuineIntel") == 0) {
		return CPU_BRAND_INTEL;
	} else
		return CPU_BRAND_UNKNOWN;
}

static int hypervisor_is_64bit(int xc)
{
	xen_capabilities_info_t xen_caps;
	return ((xc_version(xc, XENVER_capabilities, &xen_caps) == 0) &&
	        (strstr(xen_caps, "x86_64") != NULL));
}

static void do_hvm_cpuid_policy(int xc, int domid, uint32_t input, uint32_t regs[4])
{
	unsigned long is_pae;
	int brand;

	/* pae ? */
	xc_get_hvm_param(xc, domid, HVM_PARAM_PAE_ENABLED, &is_pae);
	is_pae = !!is_pae;

	switch (input) {
	case 0x00000000:
		if (regs[0] > DEF_MAX_BASE)
			regs[0] = DEF_MAX_BASE;
		break;
	case 0x00000001:
		regs[2] &= (bitmaskof(X86_FEATURE_XMM3) |
				bitmaskof(X86_FEATURE_SSSE3) |
				bitmaskof(X86_FEATURE_CX16) |
				bitmaskof(X86_FEATURE_SSE4_1) |
				bitmaskof(X86_FEATURE_SSE4_2) |
				bitmaskof(X86_FEATURE_POPCNT));

                regs[2] |= bitmaskof(X86_FEATURE_HYPERVISOR);

		regs[3] &= (bitmaskof(X86_FEATURE_FPU) |
				bitmaskof(X86_FEATURE_VME) |
				bitmaskof(X86_FEATURE_DE) |
				bitmaskof(X86_FEATURE_PSE) |
				bitmaskof(X86_FEATURE_TSC) |
				bitmaskof(X86_FEATURE_MSR) |
				bitmaskof(X86_FEATURE_PAE) |
				bitmaskof(X86_FEATURE_MCE) |
				bitmaskof(X86_FEATURE_CX8) |
				bitmaskof(X86_FEATURE_APIC) |
				bitmaskof(X86_FEATURE_SEP) |
				bitmaskof(X86_FEATURE_MTRR) |
				bitmaskof(X86_FEATURE_PGE) |
				bitmaskof(X86_FEATURE_MCA) |
				bitmaskof(X86_FEATURE_CMOV) |
				bitmaskof(X86_FEATURE_PAT) |
				bitmaskof(X86_FEATURE_CLFLSH) |
				bitmaskof(X86_FEATURE_MMX) |
				bitmaskof(X86_FEATURE_FXSR) |
				bitmaskof(X86_FEATURE_XMM) |
				bitmaskof(X86_FEATURE_XMM2));
		/* We always support MTRR MSRs. */
		regs[3] |= bitmaskof(X86_FEATURE_MTRR);

		if (!is_pae)
			clear_bit(X86_FEATURE_PAE, regs[3]);
		break;
	case 0x80000000:
		if (regs[0] > DEF_MAX_EXT)
			regs[0] = DEF_MAX_EXT;
		break;
	case 0x80000001:
		if (!is_pae)
			clear_bit(X86_FEATURE_NX, regs[3]);
		break;
	case 0x80000008:
		regs[0] &= 0x0000ffffu;
		regs[1] = regs[2] = regs[3] = 0;
		break;
	case 0x00000002: /* Intel cache info (dumped by AMD policy) */
	case 0x00000004: /* Intel cache info (dumped by AMD policy) */
	case 0x80000002: /* Processor name string */
	case 0x80000003: /* ... continued         */
	case 0x80000004: /* ... continued         */
	case 0x80000005: /* AMD L1 cache/TLB info (dumped by Intel policy) */
	case 0x80000006: /* AMD L2/3 cache/TLB info ; Intel L2 cache features */
		break;
	default:
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
		break;
	}
	
	brand = xc_cpuid_brand_get();
	if (brand == CPU_BRAND_AMD) {
		switch (input) {
		case 0x00000001:
			/* Mask Intel-only features. */
			regs[2] &= ~(bitmaskof(X86_FEATURE_SSSE3) |
					bitmaskof(X86_FEATURE_SSE4_1) |
					bitmaskof(X86_FEATURE_SSE4_2));
			break;

		case 0x00000002:
		case 0x00000004:
			regs[0] = regs[1] = regs[2] = 0;
			break;

		case 0x80000001: {
			int is_64bit = hypervisor_is_64bit(xc) && is_pae;

			if (!is_pae)
				 clear_bit(X86_FEATURE_PAE, regs[3]);
			clear_bit(X86_FEATURE_PSE36, regs[3]);

			/* Filter all other features according to a whitelist. */
			regs[2] &= ((is_64bit ? bitmaskof(X86_FEATURE_LAHF_LM) : 0) |
					 bitmaskof(X86_FEATURE_ALTMOVCR) |
					 bitmaskof(X86_FEATURE_ABM) |
					 bitmaskof(X86_FEATURE_SSE4A) |
					 bitmaskof(X86_FEATURE_MISALIGNSSE) |
					 bitmaskof(X86_FEATURE_3DNOWPF));
			regs[3] &= (0x0183f3ff | /* features shared with 0x00000001:EDX */
					 (is_pae ? bitmaskof(X86_FEATURE_NX) : 0) |
					 (is_64bit ? bitmaskof(X86_FEATURE_LM) : 0) |
					 bitmaskof(X86_FEATURE_SYSCALL) |
					 bitmaskof(X86_FEATURE_MP) |
					 bitmaskof(X86_FEATURE_MMXEXT) |
					 bitmaskof(X86_FEATURE_FFXSR) |
					 bitmaskof(X86_FEATURE_3DNOW) |
					 bitmaskof(X86_FEATURE_3DNOWEXT));
			break;
			}
		}
	} else if (brand == CPU_BRAND_INTEL) {
		switch (input) {
		case 0x00000001:
			/* Mask AMD-only features. */
			regs[2] &= ~(bitmaskof(X86_FEATURE_POPCNT));
			break;

		case 0x00000004:
			regs[0] &= 0x3FF;
			regs[3] &= 0x3FF;
			break;

		case 0x80000001:
			{
			int is_64bit = hypervisor_is_64bit(xc) && is_pae;

			/* Only a few features are advertised in Intel's 0x80000001. */
			regs[2] &= (is_64bit ? bitmaskof(X86_FEATURE_LAHF_LM) : 0);
			regs[3] &= ((is_pae ? bitmaskof(X86_FEATURE_NX) : 0) |
					(is_64bit ? bitmaskof(X86_FEATURE_LM) : 0) |
					(is_64bit ? bitmaskof(X86_FEATURE_SYSCALL) : 0));
			break;
			}
		case 0x80000005:
			{
			regs[0] = regs[1] = regs[2] = 0;
			break;
			}
		}
	}
}

static void do_pv_cpuid_policy(int xc, int domid, uint32_t input, uint32_t regs[4])
{
	int brand;
	int guest_64_bits, xen_64_bits;
	int ret;
	
	ret = xc_domain_get_machine_address_size(xc, domid);
	if (ret < 0)
		return;
	guest_64_bits = (ret == 64);
	xen_64_bits = hypervisor_is_64bit(xc);
	brand = xc_cpuid_brand_get();

	if ((input & 0x7fffffff) == 1) {
		clear_bit(X86_FEATURE_VME, regs[3]);
		clear_bit(X86_FEATURE_PSE, regs[3]);
		clear_bit(X86_FEATURE_PGE, regs[3]);
		clear_bit(X86_FEATURE_MCE, regs[3]);
		clear_bit(X86_FEATURE_MCA, regs[3]);
		clear_bit(X86_FEATURE_MTRR, regs[3]);
		clear_bit(X86_FEATURE_PSE36, regs[3]);
	}

	switch (input) {
	case 1:
		if (!xen_64_bits || brand == CPU_BRAND_AMD)
			clear_bit(X86_FEATURE_SEP, regs[3]);
		clear_bit(X86_FEATURE_DS, regs[3]);
		clear_bit(X86_FEATURE_ACC, regs[3]);
		clear_bit(X86_FEATURE_PBE, regs[3]);

		clear_bit(X86_FEATURE_DTES64, regs[2]);
		clear_bit(X86_FEATURE_MWAIT, regs[2]);
		clear_bit(X86_FEATURE_DSCPL, regs[2]);
		clear_bit(X86_FEATURE_VMXE, regs[2]);
		clear_bit(X86_FEATURE_SMXE, regs[2]);
		clear_bit(X86_FEATURE_EST, regs[2]);
		clear_bit(X86_FEATURE_TM2, regs[2]);
		if (!guest_64_bits)
			clear_bit(X86_FEATURE_CX16, regs[2]);
		clear_bit(X86_FEATURE_XTPR, regs[2]);
		clear_bit(X86_FEATURE_PDCM, regs[2]);
		clear_bit(X86_FEATURE_DCA, regs[2]);
		break;
	case 0x80000001:
		if (!guest_64_bits) {
			clear_bit(X86_FEATURE_LM, regs[3]);
			clear_bit(X86_FEATURE_LAHF_LM, regs[2]);
			if (brand != CPU_BRAND_AMD)
				clear_bit(X86_FEATURE_SYSCALL, regs[3]);
		} else
			set_bit(X86_FEATURE_SYSCALL, regs[3]);
		clear_bit(X86_FEATURE_PAGE1GB, regs[3]);
		clear_bit(X86_FEATURE_RDTSCP, regs[3]);

		clear_bit(X86_FEATURE_SVME, regs[2]);
		clear_bit(X86_FEATURE_OSVW, regs[2]);
		clear_bit(X86_FEATURE_IBS, regs[2]);
		clear_bit(X86_FEATURE_SKINIT, regs[2]);
		clear_bit(X86_FEATURE_WDT, regs[2]);
		break;
	case 5: /* MONITOR/MWAIT */
	case 0xa: /* Architectural Performance Monitor Features */
	case 0x8000000a: /* SVM revision and features */
	case 0x8000001b: /* Instruction Based Sampling */
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
		break;
	}
}

static void do_cpuid_policy(int xc, int domid, int hvm, uint32_t input, uint32_t regs[4])
{
	if (hvm)
		do_hvm_cpuid_policy(xc, domid, input, regs);
	else
		do_pv_cpuid_policy(xc, domid, input, regs);
}

#endif

#endif
