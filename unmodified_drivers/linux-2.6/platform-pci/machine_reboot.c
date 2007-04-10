#include <linux/config.h>
#include <xen/xenbus.h>
#include "platform-pci.h"
#include <asm/hypervisor.h>

int __xen_suspend(int fast_suspend)
{
	int suspend_cancelled;

	xenbus_suspend();
	platform_pci_suspend();

	suspend_cancelled = HYPERVISOR_shutdown(SHUTDOWN_suspend);

	if (suspend_cancelled) {
		platform_pci_suspend_cancel();
		xenbus_suspend_cancel();
	} else {
		platform_pci_resume();
		xenbus_resume();
	}

	return 0;
}
