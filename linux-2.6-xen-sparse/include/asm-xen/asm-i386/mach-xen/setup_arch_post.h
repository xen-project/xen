/**
 * machine_specific_memory_setup - Hook for machine specific memory setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

static char * __init machine_specific_memory_setup(void)
{
	unsigned long max_pfn = xen_start_info->nr_pages;

	e820.nr_map = 0;
	add_memory_region(0, PFN_PHYS(max_pfn), E820_RAM);

	return "Xen";
}

void __init machine_specific_modify_cpu_capabilities(struct cpuinfo_x86 *c)
{
	clear_bit(X86_FEATURE_VME, c->x86_capability);
	clear_bit(X86_FEATURE_DE, c->x86_capability);
	clear_bit(X86_FEATURE_PSE, c->x86_capability);
	clear_bit(X86_FEATURE_PGE, c->x86_capability);
	clear_bit(X86_FEATURE_SEP, c->x86_capability);
	if (!(xen_start_info->flags & SIF_PRIVILEGED))
		clear_bit(X86_FEATURE_MTRR, c->x86_capability);
}

extern void hypervisor_callback(void);
extern void failsafe_callback(void);

static void __init machine_specific_arch_setup(void)
{
	HYPERVISOR_set_callbacks(
	    __KERNEL_CS, (unsigned long)hypervisor_callback,
	    __KERNEL_CS, (unsigned long)failsafe_callback);

	machine_specific_modify_cpu_capabilities(&boot_cpu_data);
}
