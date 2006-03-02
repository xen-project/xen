/**
 * machine_specific_* - Hooks for machine specific setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

void __cpuinit machine_specific_modify_cpu_capabilities(struct cpuinfo_x86 *c)
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
