
#include <linux/module.h>
#include <asm-xen/hypervisor.h>

int reboot_thru_bios = 0;	/* for dmi_scan.c */

void machine_restart(char * __unused)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_reboot();
}

EXPORT_SYMBOL(machine_restart);

void machine_halt(void)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	for ( ; ; ) /* loop without wasting cpu cycles */
	{
		HYPERVISOR_shared_info->vcpu_data[0].evtchn_upcall_pending = 0;
		HYPERVISOR_block();
	}
}

EXPORT_SYMBOL(machine_halt);

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_shutdown();
}

EXPORT_SYMBOL(machine_power_off);
