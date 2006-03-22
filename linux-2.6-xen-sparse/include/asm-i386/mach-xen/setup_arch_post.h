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

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void nmi(void);

static void __init machine_specific_arch_setup(void)
{
	struct xen_platform_parameters pp;
	struct xennmi_callback cb;

	if (xen_feature(XENFEAT_auto_translated_physmap) &&
	    xen_start_info->shared_info < xen_start_info->nr_pages) {
		HYPERVISOR_shared_info =
			(shared_info_t *)__va(xen_start_info->shared_info);
		memset(empty_zero_page, 0, sizeof(empty_zero_page));
	}

	HYPERVISOR_set_callbacks(
	    __KERNEL_CS, (unsigned long)hypervisor_callback,
	    __KERNEL_CS, (unsigned long)failsafe_callback);

	cb.handler_address = (unsigned long)&nmi;
	HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);

	if (HYPERVISOR_xen_version(XENVER_platform_parameters,
				   &pp) == 0)
		set_fixaddr_top(pp.virt_start - PAGE_SIZE);
}
