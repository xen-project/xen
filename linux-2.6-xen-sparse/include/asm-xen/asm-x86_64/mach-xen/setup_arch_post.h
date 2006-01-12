/**
 * machine_specific_memory_setup - Hook for machine specific memory setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

static char * __init machine_specific_memory_setup(void)
{
	char *who;
	unsigned long start_pfn, max_pfn;

	who = "Xen";

	start_pfn = 0;
	max_pfn = xen_start_info->nr_pages;

	e820.nr_map = 0;
	add_memory_region(PFN_PHYS(start_pfn), PFN_PHYS(max_pfn) - PFN_PHYS(start_pfn), E820_RAM);

	return who;
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
extern void nmi(void);

static void __init machine_specific_arch_setup(void)
{
	HYPERVISOR_set_callbacks(
                (unsigned long) hypervisor_callback,
                (unsigned long) failsafe_callback,
                (unsigned long) system_call);

#ifdef CONFIG_X86_LOCAL_APIC
	HYPERVISOR_nmi_op(XENNMI_register_callback, (unsigned long)&nmi);
#endif

	machine_specific_modify_cpu_capabilities(&boot_cpu_data);
}
