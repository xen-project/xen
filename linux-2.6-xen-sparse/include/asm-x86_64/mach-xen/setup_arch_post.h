/**
 * machine_specific_* - Hooks for machine specific setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void nmi(void);

static void __init machine_specific_arch_setup(void)
{
#ifdef CONFIG_X86_LOCAL_APIC
	struct xennmi_callback cb;
#endif

	HYPERVISOR_set_callbacks(
                (unsigned long) hypervisor_callback,
                (unsigned long) failsafe_callback,
                (unsigned long) system_call);

#ifdef CONFIG_X86_LOCAL_APIC
	cb.handler_address = (unsigned long)&nmi;
	HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);
#endif
}
