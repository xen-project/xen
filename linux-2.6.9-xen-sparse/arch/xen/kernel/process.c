
#include <stdarg.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/platform.h>
#include <linux/pm.h>
#include <linux/rcupdate.h>

extern int set_timeout_timer(void);

void xen_cpu_idle (void)
{
	struct rcu_data *rdp = &__get_cpu_var(rcu_bh_data);

	local_irq_disable();
	if (need_resched() || rdp->curlist) {
		local_irq_enable();
		return;
	}
	if (set_timeout_timer() == 0) {
		/* NB. Blocking reenable events in a race-free manner. */
		HYPERVISOR_block();
		return;
	}
	local_irq_enable();
	HYPERVISOR_yield();
}
