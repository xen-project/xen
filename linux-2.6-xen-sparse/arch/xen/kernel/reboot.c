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
#include <asm-xen/evtchn.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/dom0_ops.h>
#include <asm-xen/linux-public/suspend.h>
#include <asm-xen/queues.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/ctrl_if.h>
#include <linux/cpu.h>
#include <linux/kthread.h>

#define SHUTDOWN_INVALID  -1
#define SHUTDOWN_POWEROFF  0
#define SHUTDOWN_REBOOT    1
#define SHUTDOWN_SUSPEND   2

void machine_restart(char * __unused)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_reboot();
}

void machine_halt(void)
{
	machine_power_off();
}

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_shutdown();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int reboot_thru_bios = 0;	/* for dmi_scan.c */
EXPORT_SYMBOL(machine_restart);
EXPORT_SYMBOL(machine_halt);
EXPORT_SYMBOL(machine_power_off);
#endif


/******************************************************************************
 * Stop/pickle callback handling.
 */

/* Ignore multiple shutdown requests. */
static int shutting_down = SHUTDOWN_INVALID;

#ifndef CONFIG_HOTPLUG_CPU
#define cpu_down(x) (-EOPNOTSUPP)
#define cpu_up(x) (-EOPNOTSUPP)
#endif

static int __do_suspend(void *ignore)
{
    int i, j;
    suspend_record_t *suspend_record;

    /* Hmmm... a cleaner interface to suspend/resume blkdevs would be nice. */
	/* XXX SMH: yes it would :-( */	
#ifdef CONFIG_XEN_BLKDEV_FRONTEND
    extern void blkdev_suspend(void);
    extern void blkdev_resume(void);
#else
#define blkdev_suspend() do{}while(0)
#define blkdev_resume()  do{}while(0)
#endif

#ifdef CONFIG_XEN_NETDEV_FRONTEND
    extern void netif_suspend(void);
    extern void netif_resume(void);  
#else
#define netif_suspend() do{}while(0)
#define netif_resume()  do{}while(0)
#endif

#ifdef CONFIG_XEN_USB_FRONTEND
    extern void usbif_resume();
#else
#define usbif_resume() do{}while(0)
#endif

#ifdef CONFIG_XEN_BLKDEV_GRANT
    extern int gnttab_suspend(void);
    extern int gnttab_resume(void);
#else
#define gnttab_suspend() do{}while(0)
#define gnttab_resume()  do{}while(0)
#endif

#ifdef CONFIG_SMP
    extern void smp_suspend(void);
    extern void smp_resume(void);
#endif
    extern void time_suspend(void);
    extern void time_resume(void);
    extern unsigned long max_pfn;
    extern unsigned int *pfn_to_mfn_frame_list;

    cpumask_t feasible_cpus;
    int err = 0;

    BUG_ON(smp_processor_id() != 0);
    BUG_ON(in_interrupt());

#if defined(CONFIG_SMP) && !defined(CONFIG_HOTPLUG_CPU)
    if (num_online_cpus() > 1) {
	printk(KERN_WARNING "Can't suspend SMP guests without CONFIG_HOTPLUG_CPU\n");
	return -EOPNOTSUPP;
    }
#endif

    suspend_record = (suspend_record_t *)__get_free_page(GFP_KERNEL);
    if ( suspend_record == NULL )
        goto out;

    /* Take all of the other cpus offline.  We need to be careful not
       to get preempted between the final test for num_online_cpus()
       == 1 and disabling interrupts, since otherwise userspace could
       bring another cpu online, and then we'd be stuffed.  At the
       same time, cpu_down can reschedule, so we need to enable
       preemption while doing that.  This kind of sucks, but should be
       correct. */
    /* (We don't need to worry about other cpus bringing stuff up,
       since by the time num_online_cpus() == 1, there aren't any
       other cpus) */
    cpus_clear(feasible_cpus);
    preempt_disable();
    while (num_online_cpus() > 1) {
	preempt_enable();
	for_each_online_cpu(i) {
	    if (i == 0)
		continue;
	    err = cpu_down(i);
	    if (err != 0) {
		printk(KERN_CRIT "Failed to take all CPUs down: %d.\n", err);
		goto out_reenable_cpus;
	    }
	    cpu_set(i, feasible_cpus);
	}
    }

    suspend_record->nr_pfns = max_pfn; /* final number of pfns */

    __cli();

#ifdef __i386__
    mm_pin_all();
    kmem_cache_shrink(pgd_cache);
#endif

    netif_suspend();

    blkdev_suspend();

    time_suspend();

#ifdef CONFIG_SMP
    smp_suspend();
#endif

    xenbus_suspend();

    ctrl_if_suspend();

    irq_suspend();

    gnttab_suspend();

    HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
    clear_fixmap(FIX_SHARED_INFO);

    memcpy(&suspend_record->resume_info, &xen_start_info,
           sizeof(xen_start_info));

    /* We'll stop somewhere inside this hypercall.  When it returns,
       we'll start resuming after the restore. */
    HYPERVISOR_suspend(virt_to_machine(suspend_record) >> PAGE_SHIFT);


    shutting_down = SHUTDOWN_INVALID; 

    memcpy(&xen_start_info, &suspend_record->resume_info,
           sizeof(xen_start_info));

    set_fixmap(FIX_SHARED_INFO, xen_start_info.shared_info);

    HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);

    memset(empty_zero_page, 0, PAGE_SIZE);

    for ( i=0, j=0; i < max_pfn; i+=(PAGE_SIZE/sizeof(unsigned long)), j++ )
    {
        pfn_to_mfn_frame_list[j] = 
            virt_to_machine(&phys_to_machine_mapping[i]) >> PAGE_SHIFT;
    }
    HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list =
        virt_to_machine(pfn_to_mfn_frame_list) >> PAGE_SHIFT;

    gnttab_resume();

    irq_resume();

    ctrl_if_resume();

    xenbus_resume();

#ifdef CONFIG_SMP
    smp_resume();
#endif

    time_resume();

    blkdev_resume();

    netif_resume();

    usbif_resume();

    preempt_enable();

    __sti();

 out_reenable_cpus:
    while (!cpus_empty(feasible_cpus)) {
	i = first_cpu(feasible_cpus);
	j = cpu_up(i);
	if (j != 0) {
	    printk(KERN_CRIT "Failed to bring cpu %d back up (%d).\n",
		   i, j);
	    err = j;
	}
	cpu_clear(i, feasible_cpus);
    }

 out:
    if ( suspend_record != NULL )
        free_page((unsigned long)suspend_record);
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

    daemonize(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        "shutdown"
#endif
        );

    switch ( shutting_down )
    {
    case SHUTDOWN_POWEROFF:
        if ( execve("/sbin/poweroff", poweroff_argv, envp) < 0 )
        {
            sys_reboot(LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_POWER_OFF,
                       NULL);
        }
        break;

    case SHUTDOWN_REBOOT:
        if ( execve("/sbin/reboot", restart_argv, envp) < 0 )
        {
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

static struct task_struct *kthread_create_on_cpu(int (*f)(void *arg),
						 void *arg,
						 const char *name,
						 int cpu)
{
    struct task_struct *p;
    p = kthread_create(f, arg, name);
    kthread_bind(p, cpu);
    wake_up_process(p);
    return p;
}

static void __shutdown_handler(void *unused)
{
    int err;

    if ( shutting_down != SHUTDOWN_SUSPEND )
    {
        err = kernel_thread(shutdown_process, NULL, CLONE_FS | CLONE_FILES);
        if ( err < 0 )
            printk(KERN_ALERT "Error creating shutdown process!\n");
    }
    else
    {
	kthread_create_on_cpu(__do_suspend, NULL, "suspender", 0);
    }
}

static void shutdown_handler(struct xenbus_watch *watch, const char *node)
{
    static DECLARE_WORK(shutdown_work, __shutdown_handler, NULL);

    char *str;

    str = (char *)xenbus_read("control", "shutdown", NULL);
    /* Ignore read errors. */
    if (IS_ERR(str))
        return;
    if (strlen(str) == 0) {
        kfree(str);
        return;
    }

    xenbus_write("control", "shutdown", "", O_CREAT);

    if (strcmp(str, "poweroff") == 0)
        shutting_down = SHUTDOWN_POWEROFF;
    else if (strcmp(str, "reboot") == 0)
        shutting_down = SHUTDOWN_REBOOT;
    else if (strcmp(str, "suspend") == 0)
        shutting_down = SHUTDOWN_SUSPEND;
    else {
        printk("Ignoring shutdown request: %s\n", str);
        shutting_down = SHUTDOWN_INVALID;
    }

    kfree(str);

    if (shutting_down != SHUTDOWN_INVALID)
        schedule_work(&shutdown_work);
}

#ifdef CONFIG_MAGIC_SYSRQ
static void sysrq_handler(struct xenbus_watch *watch, const char *node)
{
    char sysrq_key = '\0';
    
    if (!xenbus_scanf("control", "sysrq", "%c", &sysrq_key)) {
        printk(KERN_ERR "Unable to read sysrq code in control/sysrq\n");
        return;
    }

    xenbus_printf("control", "sysrq", "%c", '\0');

    if (sysrq_key != '\0') {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        handle_sysrq(sysrq_key, NULL, NULL);
#else
        handle_sysrq(sysrq_key, NULL, NULL, NULL);
#endif
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

/* Setup our watcher
   NB: Assumes xenbus_lock is held!
*/
static int setup_shutdown_watcher(struct notifier_block *notifier,
                                  unsigned long event,
                                  void *data)
{
    int err1 = 0;
#ifdef CONFIG_MAGIC_SYSRQ
    int err2 = 0;
#endif

    BUG_ON(down_trylock(&xenbus_lock) == 0);

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
