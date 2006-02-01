#define __KERNEL_SYSCALLS__
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/stringify.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <xen/evtchn.h>
#include <asm/hypervisor.h>
#include <xen/interface/dom0_ops.h>
#include <xen/xenbus.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <xen/xencons.h>

#if defined(__i386__) || defined(__x86_64__)
/*
 * Power off function, if any
 */
void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);
#endif

#define SHUTDOWN_INVALID  -1
#define SHUTDOWN_POWEROFF  0
#define SHUTDOWN_REBOOT    1
#define SHUTDOWN_SUSPEND   2
// Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
// report a crash, not be instructed to crash!
// HALT is the same as POWEROFF, as far as we're concerned.  The tools use
// the distinction when we return the reason code to them.
#define SHUTDOWN_HALT      4

void machine_emergency_restart(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	HYPERVISOR_sched_op(SCHEDOP_shutdown, SHUTDOWN_reboot);
}

void machine_restart(char * __unused)
{
	machine_emergency_restart();
}

void machine_halt(void)
{
	machine_power_off();
}

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	HYPERVISOR_sched_op(SCHEDOP_shutdown, SHUTDOWN_poweroff);
}

int reboot_thru_bios = 0;	/* for dmi_scan.c */
EXPORT_SYMBOL(machine_restart);
EXPORT_SYMBOL(machine_halt);
EXPORT_SYMBOL(machine_power_off);


/******************************************************************************
 * Stop/pickle callback handling.
 */

/* Ignore multiple shutdown requests. */
static int shutting_down = SHUTDOWN_INVALID;
static void __shutdown_handler(void *unused);
static DECLARE_WORK(shutdown_work, __shutdown_handler, NULL);

#ifndef CONFIG_HOTPLUG_CPU
#define cpu_down(x) (-EOPNOTSUPP)
#define cpu_up(x) (-EOPNOTSUPP)
#endif


static int __do_suspend(void *ignore)
{
	int i, j, k, fpp;

	extern int gnttab_suspend(void);
	extern int gnttab_resume(void);

	extern void time_resume(void);
	extern unsigned long max_pfn;
	extern unsigned long *pfn_to_mfn_frame_list_list;
	extern unsigned long *pfn_to_mfn_frame_list[];

#ifdef CONFIG_SMP
	cpumask_t prev_online_cpus;
	int vcpu_prepare(int vcpu);
#endif

	int err = 0;

	BUG_ON(smp_processor_id() != 0);
	BUG_ON(in_interrupt());

	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		printk(KERN_WARNING "Cannot suspend in "
		       "auto_translated_physmap mode.\n");
		return -EOPNOTSUPP;
	}

#if defined(CONFIG_SMP) && !defined(CONFIG_HOTPLUG_CPU)
	if (num_online_cpus() > 1) {
		printk(KERN_WARNING "Can't suspend SMP guests "
		       "without CONFIG_HOTPLUG_CPU\n");
		return -EOPNOTSUPP;
	}
#endif

	xenbus_suspend();

	lock_cpu_hotplug();
#ifdef CONFIG_SMP
	/*
	 * Take all other CPUs offline. We hold the hotplug semaphore to
	 * avoid other processes bringing up CPUs under our feet.
	 */
	cpus_clear(prev_online_cpus);
	while (num_online_cpus() > 1) {
		for_each_online_cpu(i) {
			if (i == 0)
				continue;
			unlock_cpu_hotplug();
			err = cpu_down(i);
			lock_cpu_hotplug();
			if (err != 0) {
				printk(KERN_CRIT "Failed to take all CPUs "
				       "down: %d.\n", err);
				goto out_reenable_cpus;
			}
			cpu_set(i, prev_online_cpus);
		}
	}
#endif

	preempt_disable();

#ifdef __i386__
	kmem_cache_shrink(pgd_cache);
	mm_pin_all();
#endif

	__cli();
	preempt_enable();
	unlock_cpu_hotplug();

	gnttab_suspend();

	HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
	clear_fixmap(FIX_SHARED_INFO);

	xen_start_info->store_mfn = mfn_to_pfn(xen_start_info->store_mfn);
	xen_start_info->console_mfn = mfn_to_pfn(xen_start_info->console_mfn);

	/*
	 * We'll stop somewhere inside this hypercall. When it returns,
	 * we'll start resuming after the restore.
	 */
	HYPERVISOR_suspend(virt_to_mfn(xen_start_info));

	shutting_down = SHUTDOWN_INVALID; 

	set_fixmap(FIX_SHARED_INFO, xen_start_info->shared_info);

	HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);

	memset(empty_zero_page, 0, PAGE_SIZE);
	     
	HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
		virt_to_mfn(pfn_to_mfn_frame_list_list);
  
	fpp = PAGE_SIZE/sizeof(unsigned long);
	for (i = 0, j = 0, k = -1; i < max_pfn; i += fpp, j++) {
		if ((j % fpp) == 0) {
			k++;
			pfn_to_mfn_frame_list_list[k] = 
				virt_to_mfn(pfn_to_mfn_frame_list[k]);
			j = 0;
		}
		pfn_to_mfn_frame_list[k][j] = 
			virt_to_mfn(&phys_to_machine_mapping[i]);
	}
	HYPERVISOR_shared_info->arch.max_pfn = max_pfn;

	gnttab_resume();

	irq_resume();

	time_resume();

	__sti();

	xencons_resume();

#ifdef CONFIG_SMP
	for_each_cpu(i)
		vcpu_prepare(i);

#endif

	/* 
	 * Only resume xenbus /after/ we've prepared our VCPUs; otherwise
	 * the VCPU hotplug callback can race with our vcpu_prepare
	 */
	xenbus_resume();

#ifdef CONFIG_SMP
 out_reenable_cpus:
	for_each_cpu_mask(i, prev_online_cpus) {
		j = cpu_up(i);
		if ((j != 0) && !cpu_online(i)) {
			printk(KERN_CRIT "Failed to bring cpu "
			       "%d back up (%d).\n",
			       i, j);
			err = j;
		}
	}
#endif

	return err;
}

static int shutdown_process(void *__unused)
{
	static char *envp[] = { "HOME=/", "TERM=linux", 
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
	static char *restart_argv[]  = { "/sbin/reboot", NULL };
	static char *poweroff_argv[] = { "/sbin/poweroff", NULL };

	extern asmlinkage long sys_reboot(int magic1, int magic2,
					  unsigned int cmd, void *arg);

	daemonize("shutdown");

	switch (shutting_down) {
	case SHUTDOWN_POWEROFF:
	case SHUTDOWN_HALT:
		if (execve("/sbin/poweroff", poweroff_argv, envp) < 0) {
			sys_reboot(LINUX_REBOOT_MAGIC1,
				   LINUX_REBOOT_MAGIC2,
				   LINUX_REBOOT_CMD_POWER_OFF,
				   NULL);
		}
		break;

	case SHUTDOWN_REBOOT:
		if (execve("/sbin/reboot", restart_argv, envp) < 0) {
			sys_reboot(LINUX_REBOOT_MAGIC1,
				   LINUX_REBOOT_MAGIC2,
				   LINUX_REBOOT_CMD_RESTART,
				   NULL);
		}
		break;
	}

	shutting_down = SHUTDOWN_INVALID; /* could try again */

	return 0;
}

static int kthread_create_on_cpu(int (*f)(void *arg),
				 void *arg,
				 const char *name,
				 int cpu)
{
	struct task_struct *p;
	p = kthread_create(f, arg, name);
	if (IS_ERR(p))
		return PTR_ERR(p);
	kthread_bind(p, cpu);
	wake_up_process(p);
	return 0;
}

static void __shutdown_handler(void *unused)
{
	int err;

	if (shutting_down != SHUTDOWN_SUSPEND)
		err = kernel_thread(shutdown_process, NULL,
				    CLONE_FS | CLONE_FILES);
	else
		err = kthread_create_on_cpu(__do_suspend, NULL, "suspend", 0);

	if ( err < 0 ) {
		printk(KERN_WARNING "Error creating shutdown process (%d): "
		       "retrying...\n", -err);
		schedule_delayed_work(&shutdown_work, HZ/2);
	}
}

static void shutdown_handler(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	char *str;
	xenbus_transaction_t xbt;
	int err;

	if (shutting_down != SHUTDOWN_INVALID)
		return;

 again:
	err = xenbus_transaction_start(&xbt);
	if (err)
		return;
	str = (char *)xenbus_read(xbt, "control", "shutdown", NULL);
	/* Ignore read errors and empty reads. */
	if (XENBUS_IS_ERR_READ(str)) {
		xenbus_transaction_end(xbt, 1);
		return;
	}

	xenbus_write(xbt, "control", "shutdown", "");

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN) {
		kfree(str);
		goto again;
	}

	if (strcmp(str, "poweroff") == 0)
		shutting_down = SHUTDOWN_POWEROFF;
	else if (strcmp(str, "reboot") == 0)
		shutting_down = SHUTDOWN_REBOOT;
	else if (strcmp(str, "suspend") == 0)
		shutting_down = SHUTDOWN_SUSPEND;
	else if (strcmp(str, "halt") == 0)
		shutting_down = SHUTDOWN_HALT;
	else {
		printk("Ignoring shutdown request: %s\n", str);
		shutting_down = SHUTDOWN_INVALID;
	}

	if (shutting_down != SHUTDOWN_INVALID)
		schedule_work(&shutdown_work);

	kfree(str);
}

#ifdef CONFIG_MAGIC_SYSRQ
static void sysrq_handler(struct xenbus_watch *watch, const char **vec,
			  unsigned int len)
{
	char sysrq_key = '\0';
	xenbus_transaction_t xbt;
	int err;

 again:
	err = xenbus_transaction_start(&xbt);
	if (err)
		return;
	if (!xenbus_scanf(xbt, "control", "sysrq", "%c", &sysrq_key)) {
		printk(KERN_ERR "Unable to read sysrq code in "
		       "control/sysrq\n");
		xenbus_transaction_end(xbt, 1);
		return;
	}

	if (sysrq_key != '\0')
		xenbus_printf(xbt, "control", "sysrq", "%c", '\0');

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;

	if (sysrq_key != '\0') {
		handle_sysrq(sysrq_key, NULL, NULL);
	}
}
#endif

static struct xenbus_watch shutdown_watch = {
	.node = "control/shutdown",
	.callback = shutdown_handler
};

#ifdef CONFIG_MAGIC_SYSRQ
static struct xenbus_watch sysrq_watch = {
	.node ="control/sysrq",
	.callback = sysrq_handler
};
#endif

static struct notifier_block xenstore_notifier;

static int setup_shutdown_watcher(struct notifier_block *notifier,
                                  unsigned long event,
                                  void *data)
{
	int err1 = 0;
#ifdef CONFIG_MAGIC_SYSRQ
	int err2 = 0;
#endif

	err1 = register_xenbus_watch(&shutdown_watch);
#ifdef CONFIG_MAGIC_SYSRQ
	err2 = register_xenbus_watch(&sysrq_watch);
#endif

	if (err1) {
		printk(KERN_ERR "Failed to set shutdown watcher\n");
	}
    
#ifdef CONFIG_MAGIC_SYSRQ
	if (err2) {
		printk(KERN_ERR "Failed to set sysrq watcher\n");
	}
#endif

	return NOTIFY_DONE;
}

static int __init setup_shutdown_event(void)
{
    
	xenstore_notifier.notifier_call = setup_shutdown_watcher;

	register_xenstore_notifier(&xenstore_notifier);
    
	return 0;
}

subsys_initcall(setup_shutdown_event);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
