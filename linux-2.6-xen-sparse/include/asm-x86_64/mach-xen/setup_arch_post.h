/**
 * machine_specific_* - Hooks for machine specific setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

#include <xen/interface/callback.h>

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void nmi(void);

static void __init machine_specific_arch_setup(void)
{
	int ret;
	static struct callback_register __initdata event = {
		.type = CALLBACKTYPE_event,
		.address = (unsigned long) hypervisor_callback,
	};
	static struct callback_register __initdata failsafe = {
		.type = CALLBACKTYPE_failsafe,
		.address = (unsigned long)failsafe_callback,
	};
	static struct callback_register __initdata syscall = {
		.type = CALLBACKTYPE_syscall,
		.address = (unsigned long)system_call,
	};
#ifdef CONFIG_X86_LOCAL_APIC
	static struct callback_register __initdata nmi_cb = {
		.type = CALLBACKTYPE_nmi,
		.address = (unsigned long)nmi,
	};
#endif

	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &event);
	if (ret == 0)
		ret = HYPERVISOR_callback_op(CALLBACKOP_register, &failsafe);
	if (ret == 0)
		ret = HYPERVISOR_callback_op(CALLBACKOP_register, &syscall);
#if CONFIG_XEN_COMPAT <= 0x030002
	if (ret == -ENOSYS)
		ret = HYPERVISOR_set_callbacks(
			event.address,
			failsafe.address,
			syscall.address);
#endif
	BUG_ON(ret);

#ifdef CONFIG_X86_LOCAL_APIC
	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &nmi_cb);
#if CONFIG_XEN_COMPAT <= 0x030002
	if (ret == -ENOSYS) {
		static struct xennmi_callback __initdata cb = {
			.handler_address = (unsigned long)nmi
		};

		HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);
	}
#endif
#endif
}
