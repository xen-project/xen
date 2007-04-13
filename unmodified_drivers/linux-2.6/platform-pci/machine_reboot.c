#include <linux/config.h>
#include <linux/stop_machine.h>
#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include "platform-pci.h"
#include <asm/hypervisor.h>

struct ap_suspend_info {
	int      do_spin;
	atomic_t nr_spinning;
};

/*
 * Spinning prevents, for example, APs touching grant table entries while
 * the shared grant table is not mapped into the address space imemdiately
 * after resume.
 */
static void ap_suspend(void *_info)
{
	struct ap_suspend_info *info = _info;

	BUG_ON(!irqs_disabled());

	atomic_inc(&info->nr_spinning);
	mb();

	while (info->do_spin) {
		cpu_relax();
		HYPERVISOR_yield();
	}

	mb();
	atomic_dec(&info->nr_spinning);
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
	int err, suspend_cancelled, nr_cpus;
	struct ap_suspend_info info;

	xenbus_suspend();

	preempt_disable();

	/* Prevent any races with evtchn_interrupt() handler. */
	disable_irq(xen_platform_pdev->irq);

	info.do_spin = 1;
	atomic_set(&info.nr_spinning, 0);
	smp_mb();

	nr_cpus = num_online_cpus() - 1;

	err = smp_call_function(ap_suspend, &info, 0, 0);
	if (err < 0) {
		preempt_enable();
		xenbus_suspend_cancel();
		return err;
	}

	while (atomic_read(&info.nr_spinning) != nr_cpus)
		cpu_relax();

	local_irq_disable();
	suspend_cancelled = bp_suspend();
	local_irq_enable();

	smp_mb();
	info.do_spin = 0;
	while (atomic_read(&info.nr_spinning) != 0)
		cpu_relax();

	enable_irq(xen_platform_pdev->irq);

	preempt_enable();

	if (!suspend_cancelled)
		xenbus_resume();
	else
		xenbus_suspend_cancel();

	return 0;
}
