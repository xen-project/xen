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
	struct callback_register event = {
		.type = CALLBACKTYPE_event,
		.address = (unsigned long) hypervisor_callback,
	};
	struct callback_register failsafe = {
		.type = CALLBACKTYPE_failsafe,
		.address = (unsigned long)failsafe_callback,
	};
	struct callback_register syscall = {
		.type = CALLBACKTYPE_syscall,
		.address = (unsigned long)system_call,
	};
#ifdef CONFIG_X86_LOCAL_APIC
	struct callback_register nmi_cb = {
		.type = CALLBACKTYPE_nmi,
		.address = (unsigned long)nmi,
	};
#endif

	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &event);
	if (ret == 0)
		ret = HYPERVISOR_callback_op(CALLBACKOP_register, &failsafe);
	if (ret == 0)
		ret = HYPERVISOR_callback_op(CALLBACKOP_register, &syscall);
	if (ret == -ENOSYS)
		ret = HYPERVISOR_set_callbacks(
			event.address,
			failsafe.address,
			syscall.address);
	BUG_ON(ret);

#ifdef CONFIG_X86_LOCAL_APIC
	ret = HYPERVISOR_callback_op(CALLBACKOP_register, &nmi_cb);
	if (ret == -ENOSYS) {
		struct xennmi_callback cb;

		cb.handler_address = nmi_cb.address;
		HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);
	}
#endif
}
