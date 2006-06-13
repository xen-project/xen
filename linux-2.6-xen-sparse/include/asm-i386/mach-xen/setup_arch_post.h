/**
 * machine_specific_memory_setup - Hook for machine specific memory setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

#include <xen/interface/callback.h>

static char * __init machine_specific_memory_setup(void)
{
	int rc;
	struct xen_memory_map memmap;
	/*
	 * This is rather large for a stack variable but this early in
	 * the boot process we know we have plenty slack space.
	 */
	struct e820entry map[E820MAX];

	memmap.nr_entries = E820MAX;
	set_xen_guest_handle(memmap.buffer, map);

	rc = HYPERVISOR_memory_op(XENMEM_memory_map, &memmap);
	if ( rc == -ENOSYS ) {
		memmap.nr_entries = 1;
		map[0].addr = 0ULL;
		map[0].size = xen_start_info->nr_pages << PAGE_SHIFT;
		/* 8MB slack (to balance backend allocations). */
		map[0].size += 8 << 20;
		map[0].type = E820_RAM;
		rc = 0;
	}
	BUG_ON(rc);

	sanitize_e820_map(map, (char *)&memmap.nr_entries);

	BUG_ON(copy_e820_map(map, (char)memmap.nr_entries) < 0);

	return "Xen";
}

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void nmi(void);

static void __init machine_specific_arch_setup(void)
{
	int ret;
	struct xen_platform_parameters pp;
	struct callback_register event = {
		.type = CALLBACKTYPE_event,
		.address = { __KERNEL_CS, (unsigned long)hypervisor_callback },
	};
	struct callback_register failsafe = {
		.type = CALLBACKTYPE_failsafe,
		.address = { __KERNEL_CS, (unsigned long)failsafe_callback },
	};
	struct callback_register nmi_cb = {
		.type = CALLBACKTYPE_nmi,
		.address = { __KERNEL_CS, (unsigned long)nmi },
	};

	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &event);
	if (ret == 0)
		ret = HYPERVISOR_callback_op(CALLBACKOP_register, &failsafe);
	if (ret == -ENOSYS)
		ret = HYPERVISOR_set_callbacks(
			event.address.cs, event.address.eip,
			failsafe.address.cs, failsafe.address.eip);
	BUG_ON(ret);

	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &nmi_cb);
	if (ret == -ENOSYS) {
		struct xennmi_callback cb;

		cb.handler_address = nmi_cb.address.eip;
		HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);
	}

	if (HYPERVISOR_xen_version(XENVER_platform_parameters,
				   &pp) == 0)
		set_fixaddr_top(pp.virt_start - PAGE_SIZE);
}
