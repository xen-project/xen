
#include <stdarg.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/platform.h>
#include <linux/pm.h>


void xen_cpu_idle (void)
{
	// local_irq_disable();
	if (need_resched()) {
		// local_irq_enable();
		return;
	}
	// local_irq_enable();
	HYPERVISOR_yield();
}
