/**
 * machine_specific_memory_setup - Hook for machine specific memory setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

static inline char * __init machine_specific_memory_setup(void)
{
	char *who;
	unsigned long start_pfn, max_pfn;

	who = "Xen";

	start_pfn = 0;
	max_pfn = start_info.nr_pages;

	e820.nr_map = 0;
	add_memory_region(PFN_PHYS(start_pfn), PFN_PHYS(max_pfn) - PFN_PHYS(start_pfn), E820_RAM);

	return who;
}

extern void hypervisor_callback(void);
extern void failsafe_callback(void);

static inline void __init machine_specific_arch_setup(void)
{
	HYPERVISOR_set_callbacks(
	    __KERNEL_CS, (unsigned long)hypervisor_callback,
	    __KERNEL_CS, (unsigned long)failsafe_callback);

	clear_bit(X86_FEATURE_VME, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_DE, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_PSE, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_TSC, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_PGE, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_MTRR, boot_cpu_data.x86_capability);
	clear_bit(X86_FEATURE_FXSR, boot_cpu_data.x86_capability);
}
