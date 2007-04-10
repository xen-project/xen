#define __KERNEL_SYSCALLS__
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <linux/kthread.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

MODULE_LICENSE("Dual BSD/GPL");

#define SHUTDOWN_INVALID  -1
#define SHUTDOWN_POWEROFF  0
#define SHUTDOWN_SUSPEND   2
/* Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
 * report a crash, not be instructed to crash!
 * HALT is the same as POWEROFF, as far as we're concerned.  The tools use
 * the distinction when we return the reason code to them.
 */
#define SHUTDOWN_HALT      4

/* Ignore multiple shutdown requests. */
static int shutting_down = SHUTDOWN_INVALID;

/* Can we leave APs online when we suspend? */
static int fast_suspend;

static void __shutdown_handler(void *unused);
static DECLARE_WORK(shutdown_work, __shutdown_handler, NULL);

int __xen_suspend(int fast_suspend);

static int shutdown_process(void *__unused)
{
	static char *envp[] = { "HOME=/", "TERM=linux",
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
	static char *poweroff_argv[] = { "/sbin/poweroff", NULL };

	extern asmlinkage long sys_reboot(int magic1, int magic2,
					  unsigned int cmd, void *arg);

	if ((shutting_down == SHUTDOWN_POWEROFF) ||
	    (shutting_down == SHUTDOWN_HALT)) {
		if (call_usermodehelper("/sbin/poweroff", poweroff_argv,
					envp, 0) < 0) {
#ifdef CONFIG_XEN
			sys_reboot(LINUX_REBOOT_MAGIC1,
				   LINUX_REBOOT_MAGIC2,
				   LINUX_REBOOT_CMD_POWER_OFF,
				   NULL);
#endif /* CONFIG_XEN */
		}
	}

	shutting_down = SHUTDOWN_INVALID; /* could try again */

	return 0;
}

static int xen_suspend(void *__unused)
{
	int err = __xen_suspend(fast_suspend);
	if (err)
		printk(KERN_ERR "Xen suspend failed (%d)\n", err);
	shutting_down = SHUTDOWN_INVALID;
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
		err = kthread_create_on_cpu(xen_suspend, NULL, "suspend", 0);

	if (err < 0) {
		printk(KERN_WARNING "Error creating shutdown process (%d): "
		       "retrying...\n", -err);
		schedule_delayed_work(&shutdown_work, HZ/2);
	}
}

static void shutdown_handler(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	extern void ctrl_alt_del(void);
	char *str;
	struct xenbus_transaction xbt;
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
	struct xenbus_transaction xbt;
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
	.node = "control/sysrq",
	.callback = sysrq_handler
};

static int setup_shutdown_watcher(void)
{
	int err;

	xenbus_scanf(XBT_NIL, "control",
		     "platform-feature-multiprocessor-suspend",
		     "%d", &fast_suspend);

	err = register_xenbus_watch(&shutdown_watch);
	if (err) {
		printk(KERN_ERR "Failed to set shutdown watcher\n");
		return err;
	}
	xenbus_write(XBT_NIL, "control", "feature-reboot", "1");

	err = register_xenbus_watch(&sysrq_watch);
	if (err) {
		printk(KERN_ERR "Failed to set sysrq watcher\n");
		return err;
	}
	xenbus_write(XBT_NIL, "control", "feature-sysrq", "1");

	return 0;
}

#ifdef CONFIG_XEN

static int shutdown_event(struct notifier_block *notifier,
			  unsigned long event,
			  void *data)
{
	setup_shutdown_watcher();
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

#else /* !defined(CONFIG_XEN) */

int xen_reboot_init(void)
{
	return setup_shutdown_watcher();
}

#endif /* !defined(CONFIG_XEN) */
