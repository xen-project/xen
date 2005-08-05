#define __KERNEL_SYSCALLS__
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/dom0_ops.h>
#include <asm-xen/linux-public/suspend.h>
#include <asm-xen/queues.h>
#include <asm-xen/xenbus.h>

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

static void __do_suspend(void)
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

    suspend_record = (suspend_record_t *)__get_free_page(GFP_KERNEL);
    if ( suspend_record == NULL )
        goto out;

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

    irq_suspend();

    gnttab_suspend();

    HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
    clear_fixmap(FIX_SHARED_INFO);

    memcpy(&suspend_record->resume_info, &xen_start_info,
           sizeof(xen_start_info));

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

    xenbus_resume();

#ifdef CONFIG_SMP
    smp_resume();
#endif

    time_resume();

    blkdev_resume();

    netif_resume();

    usbif_resume();

    __sti();

 out:
    if ( suspend_record != NULL )
        free_page((unsigned long)suspend_record);
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
        __do_suspend();
    }
}

static void shutdown_handler(struct xenbus_watch *watch, const char *node)
{
    static DECLARE_WORK(shutdown_work, __shutdown_handler, NULL);

    int type = -1;

    if (!xenbus_scanf("control", "shutdown", "%i", &type)) {
        printk("Unable to read code in control/shutdown\n");
        return;
    };

    xenbus_printf("control", "shutdown", "%i", SHUTDOWN_INVALID);

    if ((type == SHUTDOWN_POWEROFF) ||
        (type == SHUTDOWN_REBOOT)   ||
        (type == SHUTDOWN_SUSPEND)) {
        shutting_down = type;
        schedule_work(&shutdown_work);
    }

}

#ifdef CONFIG_MAGIC_SYSRQ
static void sysrq_handler(struct xenbus_watch *watch, const char *node)
{
    char sysrq_key = '\0';
    
    if (!xenbus_scanf("control", "sysrq", "%c", &sysrq_key)) {
        printk("Unable to read sysrq code in control/sysrq\n");
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

static int setup_shutdown_watcher(struct notifier_block *notifier,
                                  unsigned long event,
                                  void *data)
{
    int err1 = 0;
#ifdef CONFIG_MAGIC_SYSRQ
    int err2 = 0;
#endif

    down(&xenbus_lock);
    err1 = register_xenbus_watch(&shutdown_watch);
#ifdef CONFIG_MAGIC_SYSRQ
    err2 = register_xenbus_watch(&sysrq_watch);
#endif
    up(&xenbus_lock);

    if (err1) {
        printk("Failed to set shutdown watcher\n");
    }
    
#ifdef CONFIG_MAGIC_SYSRQ
    if (err2) {
        printk("Failed to set sysrq watcher\n");
    }
#endif

    return NOTIFY_STOP;
}

static int __init setup_shutdown_event(void)
{
    
    xenstore_notifier.notifier_call = setup_shutdown_watcher;

    if (xen_start_info.store_evtchn) {
        setup_shutdown_watcher(&xenstore_notifier, 0, NULL);
    } else {
        register_xenstore_notifier(&xenstore_notifier);
    }
    
    return 0;
}

subsys_initcall(setup_shutdown_event);
