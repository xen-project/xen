#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <xen/cpu_hotplug.h>
#include <xen/xenbus.h>

/*
 * Set of CPUs that remote admin software will allow us to bring online.
 * Notified to us via xenbus.
 */
static cpumask_t xenbus_allowed_cpumask;

/* Set of CPUs that local admin will allow us to bring online. */
static cpumask_t local_allowed_cpumask = CPU_MASK_ALL;

static int local_cpu_hotplug_request(void)
{
	/*
	 * We assume a CPU hotplug request comes from local admin if it is made
	 * via a userspace process (i.e., one with a real mm_struct).
	 */
	return (current->mm != NULL);
}

static void vcpu_hotplug(unsigned int cpu)
{
	int err;
	char dir[32], state[32];

	if ((cpu >= NR_CPUS) || !cpu_possible(cpu))
		return;

	sprintf(dir, "cpu/%d", cpu);
	err = xenbus_scanf(XBT_NULL, dir, "availability", "%s", state);
	if (err != 1) {
		printk(KERN_ERR "XENBUS: Unable to read cpu state\n");
		return;
	}

	if (strcmp(state, "online") == 0) {
		cpu_set(cpu, xenbus_allowed_cpumask);
		(void)cpu_up(cpu);
	} else if (strcmp(state, "offline") == 0) {
		cpu_clear(cpu, xenbus_allowed_cpumask);
		(void)cpu_down(cpu);
	} else {
		printk(KERN_ERR "XENBUS: unknown state(%s) on CPU%d\n",
		       state, cpu);
	}
}

static void handle_vcpu_hotplug_event(
	struct xenbus_watch *watch, const char **vec, unsigned int len)
{
	int cpu;
	char *cpustr;
	const char *node = vec[XS_WATCH_PATH];

	if ((cpustr = strstr(node, "cpu/")) != NULL) {
		sscanf(cpustr, "cpu/%d", &cpu);
		vcpu_hotplug(cpu);
	}
}

static int smpboot_cpu_notify(struct notifier_block *notifier,
			      unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;

	/*
	 * We do this in a callback notifier rather than __cpu_disable()
	 * because local_cpu_hotplug_request() does not work in the latter
	 * as it's always executed from within a stopmachine kthread.
	 */
	if ((action == CPU_DOWN_PREPARE) && local_cpu_hotplug_request())
		cpu_clear(cpu, local_allowed_cpumask);

	return NOTIFY_OK;
}

static int setup_cpu_watcher(struct notifier_block *notifier,
			      unsigned long event, void *data)
{
	int i;

	static struct xenbus_watch cpu_watch = {
		.node = "cpu",
		.callback = handle_vcpu_hotplug_event,
		.flags = XBWF_new_thread };
	(void)register_xenbus_watch(&cpu_watch);

	if (!(xen_start_info->flags & SIF_INITDOMAIN)) {
		for_each_cpu(i)
			vcpu_hotplug(i);
		printk(KERN_INFO "Brought up %ld CPUs\n",
		       (long)num_online_cpus());
	}

	return NOTIFY_DONE;
}

static int __init setup_vcpu_hotplug_event(void)
{
	static struct notifier_block hotplug_cpu = {
		.notifier_call = smpboot_cpu_notify };
	static struct notifier_block xsn_cpu = {
		.notifier_call = setup_cpu_watcher };

	register_cpu_notifier(&hotplug_cpu);
	register_xenstore_notifier(&xsn_cpu);

	return 0;
}

arch_initcall(setup_vcpu_hotplug_event);

int smp_suspend(void)
{
	int i, err;

	lock_cpu_hotplug();

	/*
	 * Take all other CPUs offline. We hold the hotplug mutex to
	 * avoid other processes bringing up CPUs under our feet.
	 */
	while (num_online_cpus() > 1) {
		unlock_cpu_hotplug();
		for_each_online_cpu(i) {
			if (i == 0)
				continue;
			err = cpu_down(i);
			if (err) {
				printk(KERN_CRIT "Failed to take all CPUs "
				       "down: %d.\n", err);
				for_each_cpu(i)
					vcpu_hotplug(i);
				return err;
			}
		}
		lock_cpu_hotplug();
	}

	return 0;
}

void smp_resume(void)
{
	int cpu;

	for_each_cpu(cpu)
		cpu_initialize_context(cpu);

	unlock_cpu_hotplug();

	for_each_cpu(cpu)
		vcpu_hotplug(cpu);
}

int cpu_up_check(unsigned int cpu)
{
	int rc = 0;

	if (local_cpu_hotplug_request()) {
		cpu_set(cpu, local_allowed_cpumask);
		if (!cpu_isset(cpu, xenbus_allowed_cpumask)) {
			printk("%s: attempt to bring up CPU %u disallowed by "
			       "remote admin.\n", __FUNCTION__, cpu);
			rc = -EBUSY;
		}
	} else if (!cpu_isset(cpu, local_allowed_cpumask) ||
		   !cpu_isset(cpu, xenbus_allowed_cpumask)) {
		rc = -EBUSY;
	}

	return rc;
}

void init_xenbus_allowed_cpumask(void)
{
	xenbus_allowed_cpumask = cpu_present_map;
}
