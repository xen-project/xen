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
#include <xen/gnttab.h>
#include <xen/xencons.h>
#include <xen/cpu_hotplug.h>

#if defined(__i386__) || defined(__x86_64__)
/*
 * Power off function, if any
 */
void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);
#endif

extern void ctrl_alt_del(void);

#define SHUTDOWN_INVALID  -1
#define SHUTDOWN_POWEROFF  0
#define SHUTDOWN_SUSPEND   2
/* Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
 * report a crash, not be instructed to crash!
 * HALT is the same as POWEROFF, as far as we're concerned.  The tools use
 * the distinction when we return the reason code to them.
 */
#define SHUTDOWN_HALT      4

void machine_emergency_restart(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	HYPERVISOR_shutdown(SHUTDOWN_reboot);
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
#if defined(__i386__) || defined(__x86_64__)
	if (pm_power_off)
		pm_power_off();
#endif
	HYPERVISOR_shutdown(SHUTDOWN_poweroff);
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

/* Ensure we run on the idle task page tables so that we will
   switch page tables before running user space. This is needed
   on architectures with separate kernel and user page tables
   because the user page table pointer is not saved/restored. */
static void switch_idle_mm(void)
{
	struct mm_struct *mm = current->active_mm;

	if (mm == &init_mm)
		return;

	atomic_inc(&init_mm.mm_count);
	switch_mm(mm, &init_mm, current);
	current->active_mm = &init_mm;
	mmdrop(mm);
}

static int __do_suspend(void *ignore)
{
	int i, j, k, fpp, err;

	extern unsigned long max_pfn;
	extern unsigned long *pfn_to_mfn_frame_list_list;
	extern unsigned long *pfn_to_mfn_frame_list[];

	extern void time_resume(void);

	BUG_ON(smp_processor_id() != 0);
	BUG_ON(in_interrupt());

	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		printk(KERN_WARNING "Cannot suspend in "
		       "auto_translated_physmap mode.\n");
		return -EOPNOTSUPP;
	}

	err = smp_suspend();
	if (err)
		return err;

	xenbus_suspend();

	preempt_disable();

#ifdef __i386__
	kmem_cache_shrink(pgd_cache);
#endif
	mm_pin_all();

	__cli();
	preempt_enable();

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

	switch_idle_mm();

	__sti();

	xencons_resume();

	xenbus_resume();

	smp_resume();

	return err;
}

static int shutdown_process(void *__unused)
{
	static char *envp[] = { "HOME=/", "TERM=linux",
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
	static char *poweroff_argv[] = { "/sbin/poweroff", NULL };

	extern asmlinkage long sys_reboot(int magic1, int magic2,
					  unsigned int cmd, void *arg);

	if ((shutting_down == SHUTDOWN_POWEROFF) ||
	    (shutting_down == SHUTDOWN_HALT)) {
		if (execve("/sbin/poweroff", poweroff_argv, envp) < 0) {
			sys_reboot(LINUX_REBOOT_MAGIC1,
				   LINUX_REBOOT_MAGIC2,
				   LINUX_REBOOT_CMD_POWER_OFF,
				   NULL);
		}
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

	if (err < 0) {
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
		ctrl_alt_del();
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

#ifdef CONFIG_MAGIC_SYSRQ
	if (sysrq_key != '\0')
		handle_sysrq(sysrq_key, NULL, NULL);
#endif
}

static struct xenbus_watch shutdown_watch = {
	.node = "control/shutdown",
	.callback = shutdown_handler
};

static struct xenbus_watch sysrq_watch = {
	.node ="control/sysrq",
	.callback = sysrq_handler
};

static int setup_shutdown_watcher(struct notifier_block *notifier,
                                  unsigned long event,
                                  void *data)
{
	int err;

	err = register_xenbus_watch(&shutdown_watch);
	if (err)
		printk(KERN_ERR "Failed to set shutdown watcher\n");

	err = register_xenbus_watch(&sysrq_watch);
	if (err)
		printk(KERN_ERR "Failed to set sysrq watcher\n");

	return NOTIFY_DONE;
}

static int __init setup_shutdown_event(void)
{
	static struct notifier_block xenstore_notifier = {
		.notifier_call = setup_shutdown_watcher
	};
	register_xenstore_notifier(&xenstore_notifier);
	return 0;
}

subsys_initcall(setup_shutdown_event);
