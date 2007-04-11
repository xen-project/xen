#include <linux/config.h>
#include <linux/stop_machine.h>
#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include "platform-pci.h"
#include <asm/hypervisor.h>

/*
 * Spinning prevents, for example, APs touching grant table entries while
 * the shared grant table is not mapped into the address space imemdiately
 * after resume.
 */
static void ap_suspend(void *_ap_spin)
{
	int *ap_spin = _ap_spin;

	BUG_ON(!irqs_disabled());

	while (*ap_spin) {
		cpu_relax();
		HYPERVISOR_yield();
	}
}

static int bp_suspend(void)
{
	int suspend_cancelled;

	BUG_ON(!irqs_disabled());

	suspend_cancelled = HYPERVISOR_shutdown(SHUTDOWN_suspend);

	if (!suspend_cancelled) {
		platform_pci_resume();
		gnttab_resume();
		irq_resume();
	}

	return suspend_cancelled;
}

int __xen_suspend(int fast_suspend)
{
	int err, suspend_cancelled, ap_spin;

	xenbus_suspend();

	preempt_disable();

	/* Prevent any races with evtchn_interrupt() handler. */
	disable_irq(xen_platform_pdev->irq);

	ap_spin = 1;
	smp_mb();

	err = smp_call_function(ap_suspend, &ap_spin, 0, 0);
	if (err < 0) {
		preempt_enable();
		xenbus_suspend_cancel();
		return err;
	}

	local_irq_disable();
	suspend_cancelled = bp_suspend();
	local_irq_enable();

	smp_mb();
	ap_spin = 0;

	enable_irq(xen_platform_pdev->irq);

	preempt_enable();

	if (!suspend_cancelled)
		xenbus_resume();
	else
		xenbus_suspend_cancel();

	return 0;
}
